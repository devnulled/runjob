//go:build linux

package job

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/devnulled/runjob/pkg/runjob/cgroup"
	"github.com/devnulled/runjob/pkg/runjob/tokenring"

	"golang.org/x/sys/unix"
)

// This needs to be ran at startup to create the cgroup on disk
func StartLib() error {
	//TODO: Implement with something like sync.RunOnce, mock file system for easier testing, etc.
	return cgroup.StartMgr()
}

// Creates a cgroup, execs the binExec with args to run the job command
//
// - Creates new cgroup
// - Creates an exec config that will launch the binExec in new namespaces for:
//   - PID
//   - Network
//   - Hostname
//   - mount
//
// Gets the cgroup file descriptor as part of the args to run in the new cgroup
// so that the new process will start in that cgroup
//
// Gets a new group id; all child processes created from it will be in process group together
func (j *Job) StartJob() error {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	slog.Debug("Starting Job", j.id, j.spec.command)

	if j.state != StateNotStarted {
		// j.state = StateFailed
		//TODO: Not sure what to do with this
		return fmt.Errorf("job %s has already been started", j.id)
	}

	j.state = StateCreating

	//
	// Setting up the args to use against the binary that runs processes
	//
	// The default settings need to make a call like this to run a process:
	//
	// jobmanager runjob /bin/hello --command-args="-P hello -A howareya --delete --opts="cool""
	execBinArg := ExecBinCmdArg
	preArgs := []string{
		execBinArg,
		j.spec.command,
		"--command-args=",
	}

	// Combine all of the original command args into one quoted and escaped string
	runJobArgs := flattenAndAppendArgs(j.spec.arguments, preArgs)

	jobIdEnv := fmt.Sprintf("%s=%s", EnvNameJobID, j.id)

	/*
	* Cloneflags:
	*
	* CLONE_NEWUTS: Isolates the hostname and domain name for the process, allowing it to set and use its own UTS
	* settings, independent of the host system or other processes.
	*
	* CLONE_NEWPID: Creates a new PID namespace, where the process gets a new PID tree starting from 1.
	*
	* CLONE_NEWNS: Creates a new mount namespace, isolating filesystem mounts from the parent namespace.
	*
	* CLONE_NEWNET: Creates a new network namespace, isolating network interfaces, routing tables, and
	* IP addresses from the parent namespace. This allows the process to have its own independent network stack.
	*
	* Additional options:
	*
	* UseCgroupFD: true - allows the process to join the cgroup specified by the provided file
	* descriptor, ensuring it enters the desired cgroup as soon as the process is created.
	*
	* Setpgid: sets the new child process up in its own process group.  any processes it creates will
	* be in the same process group
	 */

	cmd := exec.Command(j.spec.execBinPath, runJobArgs...)
	cmd.Stdin = nil
	cmd.Env = []string{jobIdEnv}
	cmd.Stderr = j.outputBuffer
	cmd.Stdout = j.outputBuffer

	cmd.SysProcAttr = &unix.SysProcAttr{
		Setpgid:    true,
		Cloneflags: unix.CLONE_NEWUTS | unix.CLONE_NEWPID | unix.CLONE_NEWNS}

	// Sets the parent death signal for a child process. It configures the kernel to
	// automatically send a SIGKILL signal to the child process (md) if its parent process dies.
	// This should clean-up all of the processes if the server dies, or clean-up child processes
	// if a watcher dies
	cmd.SysProcAttr.Pdeathsig = unix.SIGKILL

	// Setup a network namespace if configured to be isolated
	// TODO: Actually make this configurable in the client/server.  Currently true by default.
	if j.spec.cgroupSpec.IsolateNetwork {
		cmd.SysProcAttr.Cloneflags |= unix.CLONE_NEWNET
	}

	// Create a new cgroup for this job
	if err := j.spec.cgroupSpec.CreateCGroup(); err != nil {
		j.state = StateFailed
		return err
	}

	// Destroy the cgroup after it finishes/errors
	defer j.spec.cgroupSpec.DestroyCGroup()

	// Apply the limits
	if err := j.spec.cgroupSpec.ApplyCGroupLimits(); err != nil {
		j.state = StateFailed
		return err
	}

	// Get the path for this cgroup so we can load the file descriptor to it
	// TODO: should probably load in the cgroup package; just unsure about defer file.Close()
	// in another method in this moment and will figure it out later

	cgroupPath := j.spec.cgroupSpec.GetCGroupPath()

	// load the FD to our cgroup so it can be passed to the new process
	cgroupFD, err := os.OpenFile(cgroupPath, os.O_RDONLY, 0)
	if err != nil {
		j.state = StateFailed
		return fmt.Errorf("unable to open cgroup fd: %w", err)
	}
	defer cgroupFD.Close()

	// Configure the new process into its own process group.  Any child processes this new process
	// creates will be in the same process group
	cmd.SysProcAttr.CgroupFD = int(cgroupFD.Fd())

	if err := cmd.Start(); err != nil {
		j.state = StateFailed
		return fmt.Errorf("unable to start wrapper for job %s: %w", j.id, err)
	}

	//TODO: Maybe move this exec process back to parent namespace so that it doesn't have resource
	// limits applied to it?  Might be best to start it in the new cgroup then move it back so it can
	// have access to both.

	now := time.Now()
	j.startTimeUtc = now.UTC()
	j.state = StateRunning

	j.cmd = cmd

	// Handle process completion in a separate goroutine
	go func() {
		defer j.outputBuffer.Close()
		processState, err := j.cmd.Process.Wait()

		// Check for errors from the command or context
		if err != nil {
			j.state = StateFailed
			j.exitError = errors.Join(j.exitError, fmt.Errorf("error while running command for job %s: %w", j.id, err))
		} else if err == nil && !processState.Success() {
			j.state = StateFailed
			j.exitError = errors.Join(j.exitError, &exec.ExitError{ProcessState: processState})
		} else {
			j.state = StateFinished
		}

	}()

	return nil
}

func (j *Job) Stop() error {
	j.mutex.Lock()
	defer j.mutex.Unlock()

	if j.cmd == nil {
		return fmt.Errorf("job %s hasn't been started", j.id)
	}

	//TODO: Kill these more gracefully and give them a chance to clean-up before shutdown
	j.cmd.Process.Kill()
	j.state = StateCanceled

	// Sleeping for 5 seconds before nuking the cgroups just to be safe
	time.Sleep(5 * time.Second)

	j.spec.cgroupSpec.DestroyCGroup()

	return nil
}

func (j *Job) Status() *JobStatusReport {
	j.mutex.RLock()
	defer j.mutex.RUnlock()

	copy := JobStatusReport{
		ID:           j.id,
		ExitCode:     j.exitCode,
		Status:       j.state,
		StartTimeUTC: j.startTimeUtc,
	}

	// Copy the ExitError if it exists
	if j.exitError != nil {
		copy.ExitError = errors.New(j.exitError.Error()) // Create a new error object with the same message
	}

	return &copy
}

// Take our args to the requested process from the command line, then
// fix quoting, and then turn it into one big string argument for the execBin
// TODO: Not tested at all yet, maybe even unnecessary
func flattenAndAppendArgs(processargs []string, appendTo []string) []string {
	// Step 1: Iterate over the slice, escape internal quotes and surround each element with quotes
	flattened := make([]string, len(processargs))
	for i, s := range processargs {
		escaped := strings.ReplaceAll(s, `"`, `\"`) // Escape quotes inside the string
		flattened[i] = `"` + escaped + `"`          // Surround each element with quotes
	}

	// Step 2: Join all the elements into one string
	joined := strings.Join(flattened, " ")

	// Step 3: Surround the entire flattened string with quotes
	finalString := `"` + joined + `"`

	// Step 3: Append this one record to the second slice and return the result
	return append(appendTo, finalString)
}

func (j *Job) Stream() *tokenring.TokenRingBuffer {
	// Add a buffer to our buffer to protect against slow clients
	buff := tokenring.NewTokenRingBuffer()
	buff.ReadFrom(j.outputBuffer.NewReader())
	return buff
}

// Clean-up all of the things
func StopLib() error {
	// cleanup all cgroups
	return cgroup.StopMgr()
}

// Starts the requested process from a job
//
// Setup for io streams:
//
// - stdin:  /dev/null
// - stdout: both the stderr and stdout will go here because of the
// file descriptor getting setup to combine streams and well as not return
// error codes
func (jcs *JobCommandSpec) StartProc() error {

	// Seting up a new FD to combine stdout/stderr
	stderrFD, err := unix.Dup(int(os.Stderr.Fd()))
	if err != nil {
		return fmt.Errorf("unable to dup stderr for job process %s: %v ", jcs.JobID, err)
	}

	stderrFile := os.NewFile(uintptr(stderrFD), "err")

	// Will not return en error code
	unix.CloseOnExec(stderrFD)

	if err := unix.Dup2(unix.Stdout, unix.Stderr); err != nil {
		fmt.Fprintf(stderrFile, "unable to dup stdout: %v", err)
	}

	// Change to the root dir before mounting our cgroup /proc
	if err := unix.Chdir("/"); err != nil {
		return fmt.Errorf("unable to change to root directory for job process %s: %w", jcs.JobID, err)
	}

	//if err := unix.Mount("proc", "/proc", "proc", 0, ""); err != nil {
	//	return fmt.Errorf("could not mount /proc: %w", err)
	//}

	envv := []string{"PATH=/usr/bin:/bin", "HOME=/root"}

	err = unix.Exec(jcs.Command, jcs.Arguments, envv)
	if err != nil {
		return fmt.Errorf("unable to run requested command %s: for job process %s", jcs.Command, jcs.JobID)
	}
	// Never get here since the above command replaces this process with the requested one
	return nil
}
