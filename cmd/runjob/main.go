package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"time"

	"github.com/devnulled/runjob/internal/client"
	pb "github.com/devnulled/runjob/internal/proto"
	"github.com/devnulled/runjob/internal/tls"

	"github.com/alecthomas/kong"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type JobExecSpec struct {
	Command     string   `name:"server-command" arg:"" help:"Full path of the command to run on the RunJob server"`
	CommandArgs []string `name:"command-args" short:"A" optional:"" help:"Arguments to the command being ran"`
}

type JobIdSpec struct {
	JobID string `name:"job-id" arg:"" help:"The Job ID"`
}

type CmdStart struct {
	ConnectConfig client.GRPCClientConfig `embed:""`
	JobSpec       JobExecSpec             `embed:""`
}

type CmdStop struct {
	ConnectConfig client.GRPCClientConfig `embed:""`
	JobId         JobIdSpec               `embed:""`
}

type CmdStatus struct {
	ConnectConfig client.GRPCClientConfig `embed:""`
	JobId         JobIdSpec               `embed:""`
}

type CmdStream struct {
	ConnectConfig client.GRPCClientConfig `embed:""`
	JobId         JobIdSpec               `embed:""`
}

type CmdPing struct {
	ConnectConfig client.GRPCClientConfig `embed:""`
}

var CLI struct {
	Start CmdStart `cmd:"" help:"Start a Job on a remote server"`

	Stop CmdStop `cmd:"" help:"Stop a Job on a remote server"`

	Status CmdStatus `cmd:"" help:"View the status of a Job on a remote server"`

	Stream CmdStream `cmd:"" help:"Get the running output from a Job running on a remote server"`

	Ping CmdPing `cmd:"" help:"Verify connectivity and authentication with a remote server"`
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Set the default logger
	slog.SetDefault(logger)

	// Parse the command-line arguments and map them to the struct
	ctx := kong.Parse(&CLI)

	// Dispatch to the appropriate command handler
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}

func (r *CmdStart) Run(ctx *kong.Context) error {

	clientTlsConfig, err := tls.BuildClientCredentials(r.ConnectConfig.CACertPath,
		r.ConnectConfig.ClientCertPath,
		r.ConnectConfig.ClientKeyPath)
	if err != nil {
		return fmt.Errorf("unable to load client TLS credentials: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", r.ConnectConfig.ServerHost, r.ConnectConfig.ServerPort)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(clientTlsConfig))
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	defer conn.Close()

	jmc := pb.NewJobManagerClient(conn)

	req := &pb.JobStartRequest{Command: r.JobSpec.Command, Args: r.JobSpec.CommandArgs}

	// Create a context with a timeout
	clctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Make the gRPC call with the context
	response, err := jmc.Start(clctx, req)

	if err != nil {
		if status.Code(err) == codes.Canceled {
			log.Println("Request was canceled")
		} else if status.Code(err) == codes.DeadlineExceeded {
			log.Println("Request timed out")
		} else {
			log.Fatalf("gRPC call failed: %v", err)
		}
		return err
	}

	fmt.Printf("Success! Response:  %s", response.String())
	return nil

}

func (r *CmdPing) Run(ctx *kong.Context) error {

	clientTlsConfig, err := tls.BuildClientCredentials(r.ConnectConfig.CACertPath,
		r.ConnectConfig.ClientCertPath,
		r.ConnectConfig.ClientKeyPath)
	if err != nil {
		return fmt.Errorf("unable to load client TLS credentials: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", r.ConnectConfig.ServerHost, r.ConnectConfig.ServerPort)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(clientTlsConfig))
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	defer conn.Close()

	jmc := pb.NewJobManagerClient(conn)

	// Create a context with a timeout
	clctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Make the gRPC call with the context
	response, err := jmc.Ping(clctx, &pb.PingRequest{})

	if err != nil {
		if status.Code(err) == codes.Canceled {
			log.Println("Request was canceled")
		} else if status.Code(err) == codes.DeadlineExceeded {
			log.Println("Request timed out")
		} else {
			log.Fatalf("gRPC call failed: %v", err)
		}
		return err
	}

	fmt.Printf("Success! Response:  %s", response.String())

	return nil
}

func (r *CmdStart) Start(ctx *kong.Context) error {

	return nil
}
