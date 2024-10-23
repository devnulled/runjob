package cgroup

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"runtime"

	"github.com/devnulled/runjob/pkg/runjob/osutils"
)

//
//
// TODO: General refactor of using a CGroupSpec for all arguments rather than a job.
// Used the job to short cut potentially needing another layer of mutexs in the CGroupSpec
//

// Initializes a new directory tree where the runjob cgroup will be stored.
// Should only be ran once when the library starts-up
//
// TODO: Maybe a candidate for sync.OnceFunc or sync.OnceValue
// adding things to init() comes with its own problems
/*
func StartMgr() error {
	return nil
} */

func StartMgr() error {
	//
	// Controllers aren't necessarily enabled by default.
	// Controllers can be enabled and disabled by writing to the “cgroup.subtree_control”
	//
	pathSubtree := filepath.Join(toStr(CGroupRootPath))
	if err := createSubtreeControl(pathSubtree); err != nil {
		return fmt.Errorf("unable to re-configure cgroup for runjob: %w", err)
	}

	//
	// Create the base dir for our own cgroup tree
	//
	runJobPath := toStr(RunJobRootPath)

	// Lets see if clear it out in case there is anything leftover from our last testing
	if !osutils.FileExists(runJobPath) {
		if err := os.RemoveAll(toStr(RunJobRootPath)); err != nil {
			return fmt.Errorf("unable to reset parent cgroup directory for runjob: %w", err)
		}
	}

	if err := os.MkdirAll(runJobPath, cgDirMode); err != nil {
		return fmt.Errorf("unable to create new cgroup for runjob: %w", err)
	}

	// Add our PID to this tree
	procPath := filepath.Join(toStr(CGroupRootPath), "runjob", "cgroup.procs")
	if err := os.WriteFile(procPath, []byte(strconv.Itoa(os.Getpid())), cgFileMode); err != nil {
		return fmt.Errorf("unable to write to group.procs: %w", err)
	}

	return nil
}

// Creates a cgroup for running a job in
// Each cgroup is identified by its jobid
func (spec *CGroupSpec) CreateCGroup() error {

	//
	// More info on the "Core Interface Files" of cgroup v2
	//
	// https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files
	//

	// Create a new sub dir under our root CGroup controller
	// Format: /sys/fs/cgroup/runjob/<spec.cGroupName>/tasks
	//
	// Note: the job.id is created from spec.cGroupName, so they are the same
	//

	dirCGroup := filepath.Join(toStr(CGroupRootPath), spec.CGroupName)

	if err := os.MkdirAll(dirCGroup, cgDirMode); err != nil {
		return fmt.Errorf("unable to create new base & task path for cgroup %s: %w", spec.CGroupName, err)
	}

	// Add ourselves to the proc
	if err := cGroupWriter(spec.CGroupName, "cgroup.procs", strconv.Itoa(os.Getpid())); err != nil {
		return fmt.Errorf("unable to add process pid into cgroup: %w", err)
	}

	/*
		if err := cGroupWriter(spec.CGroupName, "cgroup.subtree_control", toStr(DefaultParentSubTreeControl)); err != nil {
			return fmt.Errorf("unable to add process pid into cgroup: %w", err)
		}
	*/
	/*
		// Create a new cgroup.subtree_control for this cgroup
		if err := createSubtreeControl(pathCGroup); err != nil {
			return fmt.Errorf("unable to configure subtree control for cgroup %s: %w", spec.CGroupName, err)
		}

		// Create a new cgroup.clone_children for this group.
		// This makes any child processes created stay in the same cgroup
		if err := os.WriteFile(filepath.Join(pathCGroup, "cgroup.clone_children"), []byte(strconv.Itoa(1)), cgFileMode); err != nil {
			return fmt.Errorf("unable to configure cgroup.clone_children for cgroup %s: %w", spec.CGroupName, err)
		}
	*/
	return nil

}

// Creates a new cgroup.subtree_control with default settings
func createSubtreeControl(dirPath string) error {
	filePath := filepath.Join(dirPath, "cgroup.subtree_control")
	if err := os.WriteFile(filePath, []byte(DefaultParentSubTreeControl), cgFileMode); err != nil {
		// Let the caller write a better error message
		return err
	}

	return nil
}

// Applies all of the configured limits
func (spec *CGroupSpec) ApplyCGroupLimits() error {

	//
	// Set CPU value in millis. 1000 == 1 CPU
	//

	cpuMaxVal := getCpuMaxValue(spec.CpuLimitMillis)
	cpuMaxContent := fmt.Sprintf("%d %d", cpuMaxVal, DefaultCpuMaxPeriod)
	cpuLimitPath := filepath.Join(toStr(CGroupRootPath), spec.CGroupName, toStr(GroupLimitsCpu))

	if err := os.WriteFile(cpuLimitPath, []byte(cpuMaxContent), cgFileMode); err != nil {
		return fmt.Errorf("unable to write to cpu.max: %w", err)
	}

	//
	// Set number of processes limit (PID)
	//

	pidLimitPath := filepath.Join(toStr(CGroupRootPath), spec.CGroupName, toStr(GroupLimitsPids))
	pidContent := fmt.Sprintf("%d", spec.ProcessLimit)
	if err := os.WriteFile(pidLimitPath, []byte(pidContent), cgFileMode); err != nil {
		return fmt.Errorf("unable to write to pids.max: %w", err)
	}

	//
	// Set Memory value limit in bytes
	// If the running process exceeded this value, it could be killed by the kernel
	//

	memLimitPath := filepath.Join(toStr(CGroupRootPath), spec.CGroupName, toStr(GroupLimitsMemory))
	memContent := fmt.Sprintf("%d", spec.MemLimitBytes)
	if err := os.WriteFile(memLimitPath, []byte(memContent), cgFileMode); err != nil {
		return fmt.Errorf("unable to write to memory.max: %w", err)
	}

	//
	// Set IO Limits
	//
	// format:  8:16 rbps=2097152 wbps=max riops=max wiops=max

	//TODO: Make this more configuraable to separate read/write settings, as well as being able to apply bps settings
	// Also should be able to set by device.

	ioLimitPath := filepath.Join(toStr(CGroupRootPath), spec.CGroupName, toStr(GroupLimitsIO))
	ioLimitContent := fmt.Sprintf("%d:%d rbps=max wbps=max riops=%d wiops%d", spec.RootDeviceMajor, spec.RootDeviceMinor, spec.IopsLimit, spec.IopsLimit)
	log.Println(ioLimitContent)
	if err := os.WriteFile(ioLimitPath, []byte(ioLimitContent), cgFileMode); err != nil {
		return fmt.Errorf("unable to write to io.max: %w", err)
	}

	// Uses an internal util to get around not working on Mac
	if err := osutils.SetHostname(spec.CGroupName); err != nil {
		return fmt.Errorf("unable to set container hostname: %w", err)
	}

	return nil

}

// Used to fulfill an argument for the runjob watcher
func (spec *CGroupSpec) GetCGroupPath() string {
	return filepath.Join(toStr(CGroupRootPath), spec.CGroupName)
}

func cGroupWriter(cgname string, filename string, val string) error {
	return os.WriteFile(filepath.Join(toStr(CGroupRootPath), cgname, filename), []byte(val), cgFileMode)
}

// Calculate the fractional value based on how many CPU's are available
func getCpuMaxValue(cpulimit uint32) uint32 {
	numCPU := runtime.NumCPU()
	cpuAvailMillis := uint32(numCPU * 1000)

	cGroupCPUMax := DefaultCpuMaxPeriod

	// Perform cross-multiply-and-divide to get the newCpuRequest
	newCpuLimit := (cpulimit * cGroupCPUMax) / cpuAvailMillis
	return newCpuLimit
}

// Clean-up a cgroup after it's process has exited
func (spec *CGroupSpec) DestroyCGroup() error {
	cPath := filepath.Join(toStr(CGroupRootPath), spec.CGroupName)

	if err := os.RemoveAll(cPath); err != nil {
		return fmt.Errorf("unable to remove cgroup directory for job %s: %w", spec.CGroupName, err)
	}

	return nil
}

// Clean-up the filesystem before shutting down server
func StopMgr() error {
	if err := os.RemoveAll(toStr(RunJobRootPath)); err != nil {
		return fmt.Errorf("unable to remove parent cgroup directory for runjob: %w", err)
	}
	return nil
}
git s