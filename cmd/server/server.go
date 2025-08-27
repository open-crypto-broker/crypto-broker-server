// Package main defines executable program that listens for data using predefind IPC method
package main

import (
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/open-crypto-broker/crypto-broker-server/internal/di"
	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"google.golang.org/grpc"
)

// defaultSocketPath defines default full OS path to socket file.
// The path is hardcoded and is also used by the clients in the different programming languages.
var (
	baseDir           = "/tmp"
	defaultSocketPath = filepath.Join(baseDir, "cryptobroker.sock")

	// defaultProfiles is predefined file name that contains profiles data
	defaultProfiles = "Profiles.yaml"
)

// main defines executable program logic
func main() {
	container := di.NewContainer(defaultProfiles)

	container.Logger.Println("Creating new gRPC Server")

	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		os.Mkdir(baseDir, 0755)
	}

	listener, err := net.Listen("unix", defaultSocketPath)
	if err != nil {
		container.Logger.Fatalf("Failed to listen on %s: %v", defaultSocketPath, err)
	}

	server := grpc.NewServer()
	pb.RegisterCryptoBrokerServer(server, container.Server)

	container.Logger.Println("Starting gRPC server")

	// Handle termination signals for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c

		container.Logger.Println("Received termination signal, shutting down gRPC server")

		server.GracefulStop()
		listener.Close()
		os.Remove(defaultSocketPath)
	}()

	// Start serving incoming gRPC requests
	container.Logger.Printf("gRPC server is listening on %s", defaultSocketPath)

	if err = server.Serve(listener); err != nil {
		panic(err)
	}
}
