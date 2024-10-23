package cgroup

import (
	"strings"

	v "github.com/devnulled/runjob/pkg/runjob/validate"

	"github.com/google/uuid"
)

// Represents the file path to a CGroup item
type CGroupPath string

// Default values to write
type CGroupDefaultValue string

// Make it easy to get strings from our custom const values
type Stringable interface {
	CGroupPath | CGroupDefaultValue
}

// To string value of custom consts
func toStr[T Stringable](input T) string {
	return string(input)
}

const (
	CGroupRootPath CGroupPath = "/sys/fs/cgroup"
	RunJobRootPath CGroupPath = "/sys/fs/cgroup/runjob"
	//
	// Paths to cgroup core interface files
	// https://docs.kernel.org/admin-guide/cgroup-v2.html#core-interface-files
	//
	ParentSubTreeControl CGroupPath = "/sys/fs/cgroup/cgroup.subtree_control"

	GroupSubTreeControl CGroupPath = "cgroup.subtree_control"
	GroupLimitsPids     CGroupPath = "pids.max"
	GroupLimitsMemory   CGroupPath = "memory.max"
	GroupLimitsIO       CGroupPath = "io.max"
	GroupLimitsCpu      CGroupPath = "cpu.max"
	GroupCloneChildren  CGroupPath = "cgroup.clone_children"

	// Content to write into cgroup.subtree
	DefaultParentSubTreeControl CGroupDefaultValue = "+cpu +io +memory +pids"

	// Used for setting/calcuating CPU Limits
	DefaultCpuMaxPeriod uint32 = 100000

	// Human readable values for big numbers that are easier to understand with a foggy brain at 3 AM when something is broken
	valFourCPUAsMillis     uint32 = 4000
	valSixteenGBAsBytes    uint64 = 16000000000
	valFiveTwelveKBAsBytes uint64 = 512000
	valOneMeeelionIops     uint64 = 1000000

	//Default dir and file modes
	//cgFileMode = 0700
	//cgFileMode = 0644
	//cgDirMode = 0755

	//cgFileMode = 320
	//cgDirMode  = 320

	cgDirMode  = 0755
	cgFileMode = 0644
)

var (
	// Defined somewhat generically so they could potentially be reused for validation across the stack
	// TODO: Fix all of this hacky stuff with something else
	ErrRootDeviceMajor = v.LazyErr("RootDeviceMajor")
	ErrRootDeviceMinor = v.LazyErr("RootDeviceMinor")
	ErrCPULimit        = v.LazyErr("CPU Limit")
	ErrMemLimit        = v.LazyErr("Memory Limit")
	ErrIOPSLimit       = v.LazyErr("IOPS Limit")
	ErrProcessLimit    = v.LazyErr("Number of Processes Limit")
	ErrCGroupName      = v.LazyErr("cgroup name")
)

// Creates and manages CGroups for running jobs
type CGroupManager interface {
	// Needs to be ran once you initialize the library so it can create the default cgroup dirs
	StartMgr() error

	// Create a new CGroup for a job
	CreateCGroup() error

	// Apply configured limits to a created CGroup
	// TODO: not designed or tested to run more than once on a cgroup
	ApplyCGroupLimits() error

	// Get the root path to the CGroup in the CGroupSpec on proc
	GetCGroupPath() string

	// Destroy a CGroup when a Job has exited
	DestroyCGroup() error

	// Should be ran when the process running the lib is shutting down to clean up resources
	StopMgr() error
}

// Provides the configuration for creating a new cgroup
//
// An instance of this struct will not have any changes once it has been created; it is only read from.
// As such, no mutex needed.
type CGroupSpec struct {
	CGroupName string //jobid

	CpuLimitMillis uint32
	MemLimitBytes  uint64
	IopsLimit      uint64
	ProcessLimit   uint32
	IsolateNetwork bool

	RootDeviceMajor uint32
	RootDeviceMinor uint32
}

type CGroupOpt func(*CGroupSpec)

func WithCpuLimit(cpuLimitMillis uint32) CGroupOpt {
	return func(c *CGroupSpec) {
		c.CpuLimitMillis = cpuLimitMillis
	}
}

func WithMemLimit(memLimitBytes uint64) CGroupOpt {
	return func(c *CGroupSpec) {
		c.MemLimitBytes = memLimitBytes
	}
}

func WithIOPSLimit(iopsLimit uint64) CGroupOpt {
	return func(c *CGroupSpec) {
		c.IopsLimit = iopsLimit
	}
}

func WithProcessLimit(processLimit uint32) CGroupOpt {
	return func(c *CGroupSpec) {
		c.ProcessLimit = processLimit
	}
}

func WithRootDeviceMajor(rootDeviceMajor uint32) CGroupOpt {
	return func(c *CGroupSpec) {
		c.RootDeviceMajor = rootDeviceMajor
	}
}

func WithRootDeviceMinor(rootDeviceMinor uint32) CGroupOpt {
	return func(c *CGroupSpec) {
		c.RootDeviceMinor = rootDeviceMinor
	}
}

func WithDefaultGroupName() CGroupOpt {
	uuid := uuid.New().String()
	return func(c *CGroupSpec) {
		c.CGroupName = uuid
	}
}

func WithGroupName(name string) CGroupOpt {
	return func(c *CGroupSpec) {
		c.CGroupName = name
	}
}

func NewCGroupSpec(opts ...CGroupOpt) *CGroupSpec {
	//TODO: Isolate Network is set by default.  Add more options in the future.
	s := &CGroupSpec{IsolateNetwork: true}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

func (c *CGroupSpec) Validate() error {
	if len(strings.TrimSpace(c.CGroupName)) == 0 {
		return ErrCGroupName
	}

	// Super high ceiling of 4 cores/CPU max
	if c.CpuLimitMillis == 0 || c.CpuLimitMillis > valFourCPUAsMillis {
		return ErrCPULimit
	}

	// Min: 512KB Max: 16GB
	if valFiveTwelveKBAsBytes > c.MemLimitBytes || c.MemLimitBytes > valSixteenGBAsBytes {
		return ErrMemLimit
	}

	// Min: 10  Max: 1000000
	if 10 > c.IopsLimit || c.IopsLimit > valOneMeeelionIops {
		return ErrIOPSLimit
	}

	// Min: 2  Max: 100
	if 2 > c.ProcessLimit || c.ProcessLimit > 100 {
		return ErrProcessLimit
	}

	return nil

}
