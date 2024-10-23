package tls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var (
	ErrUserPeer      = errors.New("unable to retrive user peer information from context")
	ErrUserCertTls   = errors.New("certificate is missing TLS authentication info")
	ErrUserCertPeers = errors.New("certificate is missing peer certificates")

	ErrCertFile    = errors.New("unable to load certificate file")
	ErrCertParsing = errors.New("unable to parse certificate")
	ErrCertKeyPair = errors.New("unable to initialize the certificate and key provided")

	ErrUnauthorized = errors.New("user is unauthorized")
)

type TlsUser struct {
	Username string //Username extracted from the CN value of the cert. /CN=username
}

func NewTlsUser(username string) *TlsUser {
	return &TlsUser{Username: username}
}

func GetUserFromContext(ctx context.Context) (*TlsUser, error) {
	// Check peer validation
	peer, hasPeer := peer.FromContext(ctx)
	if !hasPeer {
		return nil, ErrUserPeer
	}

	tlsAuthInfo, hasTlsAuthInfo := peer.AuthInfo.(credentials.TLSInfo)
	if !hasTlsAuthInfo {
		return nil, ErrUserCertTls
	}

	if len(tlsAuthInfo.State.PeerCertificates) == 0 {
		return nil, ErrUserCertPeers
	}

	username := tlsAuthInfo.State.PeerCertificates[0].Subject.CommonName

	return NewTlsUser(username), nil
}

func BuildServerCredentials(pathClientCAPem string,
	pathServerCert string,
	pathServerKey string) (credentials.TransportCredentials, error) {

	// Load client certs + the CA who signed client's certificate
	// The pem should be concatenated of client certs + the CA cert
	// at the end of the .pem file
	clientCAPem, err := os.ReadFile(pathClientCAPem)
	if err != nil {
		return nil, fmt.Errorf("unable to load client certificate pem: %w", err)
	}

	// Create cert pool from ClientCAPem file contents
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(clientCAPem) {
		return nil, fmt.Errorf("unable to init client certificate bundle: %w", err)
	}

	// Load server certificate and private key
	serverCert, err := tls.LoadX509KeyPair(pathServerCert, pathServerKey)
	if err != nil {
		return nil, fmt.Errorf("unable to init server key + cert: %w", err)
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    certPool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(config), nil
}

func BuildClientCredentials(pathCACert string,
	pathClientCert string,
	pathClientKey string) (credentials.TransportCredentials, error) {

	// Load trusted the trusted CA cert which signed this clients certs
	// Can also be a pem with intermediates who signed the cert
	// but should have the CA cert at the end of the PEM
	caCert, err := os.ReadFile(pathCACert)
	if err != nil {
		return nil, fmt.Errorf("unable to load CA certificate(s): %w", err)
	}

	// Create cert pool from Trusted CA cert file contents
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("unable to init CA certificate(s): %w", err)
	}

	// Load client certificate and private key
	clientCert, err := tls.LoadX509KeyPair(pathClientCert, pathClientKey)
	if err != nil {
		return nil, fmt.Errorf("unable to init client key + cert: %w", err)
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      certPool,
		MinVersion:   tls.VersionTLS13,
	}

	return credentials.NewTLS(config), nil
}
