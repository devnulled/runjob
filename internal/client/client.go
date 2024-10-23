package client

import (
	"fmt"

	pb "github.com/devnulled/runjob/internal/proto"
	"github.com/devnulled/runjob/internal/tls"

	"google.golang.org/grpc"
)

type GRPCClientConfig struct {
	ServerHost string `name:"server-host" short:"H" default:"localhost" help:"Host address of the RunJob server"`
	ServerPort uint32 `name:"server-port" short:"P" default:"8080" help:"Host port of the RunJob server"`

	CACertPath     string `name:"ca-cert-path" type:"existingfile" default:"certs/root-ca-cert.pem" help:"Path to CA cert file for authenticating server"`
	ClientCertPath string `name:"client-cert-path" type:"existingfile" default:"certs/client-cert.pem" help:"Path to client cert file"`
	ClientKeyPath  string `name:"client-key-path" type:"existingfile" default:"certs/client-key.pem" help:"Path to client key file"`
}

type RemoteClient struct {
	client *pb.JobManagerClient
	//conn
}

func Connect(config GRPCClientConfig) (*pb.JobManagerClient, error) {

	clientTlsConfig, err := tls.BuildClientCredentials(config.CACertPath,
		config.ClientCertPath,
		config.ClientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("unable to load client TLS credentials: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", config.ServerHost, config.ServerPort)

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(clientTlsConfig))
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	defer conn.Close()

	client := pb.NewJobManagerClient(conn)

	return &client, nil
}
