package main

import (
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
	"github.com/google/uuid"

	"github.com/devnulled/runjob/internal/server"
	"github.com/devnulled/runjob/pkg/runjob/cgroup"
	"github.com/devnulled/runjob/pkg/runjob/job"
	"github.com/devnulled/runjob/pkg/runjob/osutils"
)

// Used for all commands that connect to a remote host
type CmdServe struct {
	ServerArgs server.GRPCServerConfig `embed:""`
}

type CmdRunJob struct {
	Command     string   `name:"command" arg:"" help:"Full path of the command to run on the RunJob server"`
	CommandArgs []string `name:"command-args" short:"A" optional:"" help:"Arguments to the command being ran"`
	JobID       string   `hidden:""`
}

type CLI struct {
	Serve  CmdServe  `cmd:"" name:"serve" help:"Start the JobManager gRPC server and listen for requests"`
	RunJob CmdRunJob `cmd:"" name:"runjob" help:"Setup namespaces, cgroup resource limits, and then run the requested command"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Set the default logger
	slog.SetDefault(logger)

	// Parse the command-line arguments and map them to the struct
	cli := &CLI{}
	ctx := kong.Parse(cli)

	// Dispatch to the appropriate command handler
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

func (r *CmdRunJob) AfterApply(ctx *kong.Context) error {
	// If there is a JobID set in the env, lets grab it in case it's useful
	if jobid, exists := os.LookupEnv(job.EnvNameJobID); exists {
		r.JobID = jobid
	} else {
		// Not used for anything important; generate one but make it obvious
		//TODO: Do something better here  :)
		uuid := uuid.New().String()
		r.JobID = fmt.Sprintf("%s%s", "jobmanager-generated-id-", uuid)

	}
	return nil
}

func (r *CmdRunJob) Run(ctx *kong.Context) error {
	log.Printf("Here is what I saw:\n\n")
	log.Printf("Command: %v\n", r.Command)
	log.Printf("Command Args: %v\n", r.CommandArgs)

	jcs := job.NewJobCommandSpec(job.WithArguments(r.CommandArgs),
		job.WithCmd(r.Command),
		job.WithJobID(r.JobID))

	if err := jcs.StartProc(); err != nil {
		return err
	}

	return nil
}

func (r *CmdServe) Run(ctx *kong.Context) error {

	return server.StartGRPCServer(r.ServerArgs)
}

func (r *CmdServe) Validate() error {

	// Validate the root-mount args if they have both been passed; the default is 9000
	// TODO: Fix these args, this is dumb and hacky
	if (r.ServerArgs.RootMountMajorVersion != 9000) && (r.ServerArgs.RootMountMinorVersion != 9000) {
		// The values have been set manually, skip auto-detect
		r.ServerArgs.RootMountAutoDetect = false
	}

	// Validate the CGroup Args by trying to create one
	// We will attempt to deal with the RootDevice stuff later, just adding basic value to validate everything else
	//TODO: Do something else here
	cga := cgroup.NewCGroupSpec(cgroup.WithCpuLimit(r.ServerArgs.DefaultCPULimitMillis),
		cgroup.WithIOPSLimit(r.ServerArgs.DefaultIOPSLimit),
		cgroup.WithMemLimit(r.ServerArgs.DefaultMemLimitBytes),
		cgroup.WithProcessLimit(r.ServerArgs.DefaultMaxProcLimit),
		cgroup.WithRootDeviceMajor(1),
		cgroup.WithRootDeviceMinor(1),
		cgroup.WithDefaultGroupName())

	if err := cga.Validate(); err != nil {
		return err
	}

	return nil
}

func (r *CmdServe) AfterApply(ctx *kong.Context) error {
	// Lets try to auto detect the root mount if its not set

	if r.ServerArgs.RootMountAutoDetect && osutils.IsLinux() {
		ioDevice, err := osutils.GetRootDevice()
		if err != nil {
			return fmt.Errorf("unable to auto-detect root mount: %w", err)
		}

		r.ServerArgs.RootMountMajorVersion = ioDevice.DeviceMajor
		r.ServerArgs.RootMountMinorVersion = ioDevice.DeviceMinor
	}

	return nil
}
