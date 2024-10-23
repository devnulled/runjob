package job

import (
	"os/exec"
	"sync"
	"time"

	"github.com/devnulled/runjob/pkg/runjob/cgroup"
	"github.com/devnulled/runjob/pkg/runjob/osutils"
	"github.com/devnulled/runjob/pkg/runjob/tokenring"
	v "github.com/devnulled/runjob/pkg/runjob/validate"
)

type JobStateEnum uint64

const (
	StateNotStarted JobStateEnum = iota
	StateCreating
	StateCreated
	StateRunning
	StateFinished
	StateCanceled
	StateFailed
)

const (
	EnvNameJobID string = "RUNJOB_JOBID"

	// The string used to specify as an argument to a jobrunner to know that its the mode that will execute processes
	//
	// Example:  $ biname runjob -A arg
	ExecBinCmdArg string = "runjob"
)

var (
	// Defined somewhat generically so they could potentially be reused for validation across the stack
	// TODO: Fix all of this hacky stuff with something else
	ErrCGroupSpec = v.LazyErr("CGroupSpec")
	ErrCommand    = v.LazyErr("Command")
	ErrOwner      = v.LazyErr("Owner")
)

// The requested params for the job to run; used to build jobs and as arguments to run processes
// implements the JobBuilder interface
type JobSpec struct {

	// command is the command to run.
	command string
	// arguments are the arguments to pass to the command, if any.
	arguments []string

	// The various settings needed for the cgroup functionality
	cgroupSpec cgroup.CGroupSpec

	// The username derived from TLS who requested this job
	owner string

	// The full path to the binary which can run as a wrapper/launcher for requested processes
	execBinPath string
}

// To create a runnable job, start here by creating a JobSpec and apply all of the options
func NewJobSpec(opts ...JobSpecOption) *JobSpec {
	s := &JobSpec{}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

type JobSpecOption func(*JobSpec)

// WithCommand sets the command field in JobSpec
func WithCommand(command string) JobSpecOption {
	return func(j *JobSpec) {
		j.command = command
	}
}

// WithCommandArgs sets the arguments field in JobSpec.
func WithCommandArgs(args []string) JobSpecOption {
	return func(j *JobSpec) {
		j.arguments = args
	}
}

// WithCGroupSpec sets the cgroupSpec field in JobSpec.
func WithCGroupSpec(cgroupSpec *cgroup.CGroupSpec) JobSpecOption {
	return func(j *JobSpec) {
		j.cgroupSpec = *cgroupSpec
	}
}

// WithOwner sets the owner field in JobSpec.
func WithOwner(owner string) JobSpecOption {
	return func(j *JobSpec) {
		j.owner = owner
	}
}

// WithDefaultExecBin sets the execBinPath to the current running process
func WithDefaultExecBin() JobSpecOption {
	execBin, err := osutils.GetCurrentBinPath()
	if err != nil {
		//TODO: Do something better here
		return func(j *JobSpec) {
			j.execBinPath = "/hey/cantfind/exe"
		}
	}
	return func(j *JobSpec) {
		j.execBinPath = execBin
	}
}

// WithExecBin allows you to specify the execBinPath you want to use
// to run the jobs requested processes
func WithExecBin(binpath string) JobSpecOption {
	return func(j *JobSpec) {
		j.execBinPath = binpath
	}
}

// Validate a JobSpec before creating a Job from it
func (s *JobSpec) Validate() error {
	if err := s.cgroupSpec.Validate(); err != nil {
		return err
	}

	if 2 > len(s.command) {
		return ErrCommand
	}

	if 2 > len(s.owner) {
		return ErrOwner
	}

	//TODO: Make sure the binary exists and is executable
	return nil
}

// A Job is what represents a job that creates a cgroup and runs a requsted process
// Implements the JobExec interface
type Job struct {
	id        string
	spec      JobSpec
	exitCode  uint32
	exitError error

	state        JobStateEnum
	startTimeUtc time.Time
	owner        string

	outputBuffer *tokenring.TokenRingBuffer
	mutex        sync.RWMutex
	cmd          *exec.Cmd
}

// Creates a new runnable Job
func (s *JobSpec) NewJob() *Job {
	// UUID already generated, use it for the jobid
	jobid := s.cgroupSpec.CGroupName
	buff := tokenring.NewTokenRingBuffer()
	return &Job{
		id:           jobid,
		spec:         *s,
		state:        StateNotStarted,
		outputBuffer: buff,
		owner:        s.owner,
	}
}

// CloneToStatus safely clones a subset of the Job into JobStatusReport
func (j *Job) CloneToStatus() *JobStatusReport {
	// Lock for reading
	j.mutex.RLock()
	defer j.mutex.RUnlock()

	// Deep copy relevant fields
	return &JobStatusReport{
		ID:           j.id,
		StartTimeUTC: j.startTimeUtc,
		Status:       j.state,
		ExitCode:     j.exitCode,
		ExitError:    j.exitError,
	}
}

// Used as a return type that gets a copy of what the current status is
// rather than returning the Job itself for non blocking reasons
type JobStatusReport struct {
	ID           string
	StartTimeUTC time.Time
	Status       JobStateEnum
	ExitCode     uint32
	ExitError    error
}

func NewDefaultJobStatus() *JobStatusReport {
	return &JobStatusReport{}
}

// Represents the arguments passed to a runjob watcher (job.execBinPath) to run a process in a cgroup
type JobCommandSpec struct {
	// command is the command to run.
	Command string
	// arguments are the arguments to pass to the command, if any.
	Arguments []string

	// should be retrieved from the runtime env
	// Mostly just used for logging/errors
	JobID string
}

// / JobCommandOpt is the functional option type for JobCommandSpec
type JobCommandOpt func(*JobCommandSpec)

// WithCmd sets the Command field for JobCommandSpec
func WithCmd(Command string) JobCommandOpt {
	return func(jcs *JobCommandSpec) {
		jcs.Command = Command
	}
}

// WithArguments sets the Arguments field for JobCommandSpec
func WithArguments(Arguments []string) JobCommandOpt {
	return func(jcs *JobCommandSpec) {
		jcs.Arguments = Arguments
	}
}

// WithJobID sets the JobID field for JobCommandSpec
func WithJobID(JobID string) JobCommandOpt {
	return func(jcs *JobCommandSpec) {
		jcs.JobID = JobID
	}
}

// NewJobCommandSpec constructs a JobCommandSpec with given options
func NewJobCommandSpec(opts ...JobCommandOpt) *JobCommandSpec {
	jcs := &JobCommandSpec{}
	for _, opt := range opts {
		opt(jcs)
	}
	return jcs
}
