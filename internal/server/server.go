package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	pb "github.com/devnulled/runjob/internal/proto"
	itls "github.com/devnulled/runjob/internal/tls"
	"github.com/devnulled/runjob/pkg/runjob/cgroup"
	"github.com/devnulled/runjob/pkg/runjob/job"
	"google.golang.org/grpc"

	//"google.golang.org/grpc/reflection"
	"github.com/google/uuid"
)

type GRPCServerConfig struct {
	ServerHost      string `name:"server-host" short:"H" default:"localhost" help:"Listen address to bind the JobManager server to"`
	ServerPort      uint32 `name:"server-port" short:"P" default:"8080" help:"Listen port to bind the JobManager server to"`
	ClientCAPemPath string `name:"client-pem-path" type:"existingfile" default:"certs/ca-clients-bundle.pem" help:"Path to Client CA PEM bundle file"`
	ServerCertPath  string `name:"server-cert-path" type:"existingfile" default:"certs/server-cert.pem" help:"Path to server cert file"`
	ServerKeyPath   string `name:"server-key-path" type:"existingfile" default:"certs/server-key.pem" help:"Path to server key file"`

	DefaultCPULimitMillis uint32 `name:"default-limits-cpu" default:"1000" help:"CPU limit in millis to apply to requested jobs. 1000 = 1 CPU/Processing Core (same as Kubernetes pods)"`
	DefaultMaxProcLimit   uint32 `name:"default-limits-proc" default:"10" help:"Maximum number of child processes to apply to requested jobs"`
	DefaultProcessLimit   uint32 `name:"default-limits-numproc" default:"10" help:"Maximum number of processes this command can spawn"`
	DefaultMemLimitBytes  uint64 `name:"default-limits-bytes" default:"512000000" help:"Memory limit in bytes to apply to requsted jobs"`
	DefaultIOPSLimit      uint64 `name:"default-limits-iops" default:"400000" xor:"rootver" help:"Default IOPS to apply to requsted jobs"`
	RootMountAutoDetect   bool   `name:"root-mount-autodetect" default:"true" help:"Whether or not to try to automatically detect the version of the root mount. If set to false, will need to specify the versions manually."`
	RootMountMajorVersion uint32 `name:"root-mount-major" group:"rootver" and:"root-mount-minor" default:"9000" help:"The Linux root mount device MajorVersion from the 'MajorVersion:MinorVersion' format. If specified, root mount detect will be disabled. Both major and minor version args are required if you use one of them."`
	RootMountMinorVersion uint32 `name:"root-mount-minor" group:"rootver" and:"root-mount-major" default:"9000" help:"The Linux root mount device MinorVersion from the 'MajorVersion:MinorVersion' format. If specified, root mount detect will be disabled. Both major and minor version args are required if you use one of them."`
}

func StartGRPCServer(srvCfg GRPCServerConfig) error {

	serverOptions := []grpc.ServerOption{}

	// Init the RunJob library
	if err := job.StartLib(); err != nil {
		return fmt.Errorf("unable to initialize runjob library: %w", err)
	}

	// Make sure we have the correct TLS creds before listening to a port
	tlsCredentials, err := itls.BuildServerCredentials(srvCfg.ClientCAPemPath,
		srvCfg.ServerCertPath,
		srvCfg.ServerKeyPath)
	if err != nil {
		return fmt.Errorf("unable to load TLS credentials: %w", err)
	}

	serverOptions = append(serverOptions, grpc.Creds(tlsCredentials))

	addr := fmt.Sprintf("%s:%d", srvCfg.ServerHost, srvCfg.ServerPort)

	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind and listen: %v", err)
	}

	log.Printf("Started JobManager server at: %s", addr)
	grpcServer := grpc.NewServer(serverOptions...)

	jobServer := &JobManagerServer{
		Gcfg: srvCfg}
	pb.RegisterJobManagerServer(grpcServer, jobServer)

	done := make(chan struct{})
	go func() {
		<-done
		grpcServer.GracefulStop()
	}()

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Set up channel on which to receive signal notifications.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Block until a signal is received.
	sig := <-sigCh
	fmt.Printf("\nReceived signal: %v. Shutting down...\n", sig)

	job.StopLib()

	// Gracefully stop the gRPC server
	grpcServer.GracefulStop()
	fmt.Println("JobManager server shut down successfully")

	return nil

}

type JobManagerServer struct {
	pb.UnimplementedJobManagerServer

	Gcfg  GRPCServerConfig
	mutex sync.Mutex
}

func (s *JobManagerServer) Start(ctx context.Context, request *pb.JobStartRequest) (*pb.JobStartResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	user, err := itls.GetUserFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from certificate: %w", err)
	}

	log.Printf("Found user: %+v", user)
	jobId := uuid.New().String()

	cgSpec := cgroup.NewCGroupSpec(
		cgroup.WithCpuLimit(s.Gcfg.DefaultCPULimitMillis),
		cgroup.WithDefaultGroupName(),
		cgroup.WithIOPSLimit(s.Gcfg.DefaultIOPSLimit),
		cgroup.WithMemLimit(s.Gcfg.DefaultMemLimitBytes),
		cgroup.WithProcessLimit(s.Gcfg.DefaultMaxProcLimit),
		cgroup.WithRootDeviceMajor(s.Gcfg.RootMountMajorVersion),
		cgroup.WithRootDeviceMinor(s.Gcfg.RootMountMinorVersion),
	)

	if err := cgSpec.Validate(); err != nil {
		return nil, fmt.Errorf("something isn't set right in the RunJob defaults: %w", err)
	}

	jobSpec := job.NewJobSpec(
		job.WithCGroupSpec(cgSpec),
		job.WithCommand(request.Command),
		job.WithCommandArgs(request.Args),
		job.WithDefaultExecBin(),
		job.WithOwner(user.Username))

	if err := jobSpec.Validate(); err != nil {
		return nil, fmt.Errorf("something isn't set right in the JobSpec: %w", err)
	}

	newJob := jobSpec.NewJob()

	if err := newJob.StartJob(); err != nil {
		return nil, fmt.Errorf("unable to start new job: %w", err)
	}

	//cgSpec := job.NewCGroupSpec(job.WithCpuLimit(request.))

	return &pb.JobStartResponse{JobId: string(jobId)}, nil
}

func (s *JobManagerServer) Stop(ctx context.Context, request *pb.JobStopRequest) (*pb.JobStopResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	user, err := itls.GetUserFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from certificate: %w", err)
	}

	log.Printf("Found user: %+v", user)

	return &pb.JobStopResponse{}, nil
}

func (s *JobManagerServer) Status(ctx context.Context, request *pb.JobStatusRequest) (*pb.JobStatusResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	user, err := itls.GetUserFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from certificate: %w", err)
	}

	log.Printf("Found user: %+v", user)

	return &pb.JobStatusResponse{}, nil
}

func (s *JobManagerServer) Ping(ctx context.Context, request *pb.PingRequest) (*pb.PingResponse, error) {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	user, err := itls.GetUserFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get user from certificate: %w", err)
	}

	log.Printf("Found user: %+v", user)

	return &pb.PingResponse{}, nil
}

func (s *JobManagerServer) Stream(request *pb.JobStreamRequest, stream pb.JobManager_StreamServer) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	user, err := itls.GetUserFromContext(stream.Context())
	if err != nil {
		return fmt.Errorf("failed to get user from certificate: %w", err)
	}

	log.Printf("Found user: %+v", user)

	// Stub out random bytes
	stubBytes := make([]byte, 8000)
	rand.Read(stubBytes)

	//buffer := make([]byte, 1024)

	err = stream.Send(&pb.JobStreamResponse{Output: stubBytes})

	if err != nil {
		return fmt.Errorf("unable to write job output to stream: %w", err)
	}
	/*

		for {
			bytesRead, err := jobOutput.Read(buffer)
			if err != nil {

				if !errors.Is(err, io.EOF) {
					return fmt.Errorf("Unable to read job output: %w, err")
				}

				err = stream.Send(&pb.JobStreamResponse{Response: buffer[:bytesRead]})

				if err != nil {
					return fmt.Errorf("Unable to write job output to stream: %w", err)
				}

				break
			}

			err = stream.Send(&pb.JobStreamResponse{Response: buffer[:bytesRead]})

			if err != nil {
				return fmt.Errorf("Unable to write job output to stream at end of current buffer: %w", err)
			}
		}
	*/

	return nil
}
