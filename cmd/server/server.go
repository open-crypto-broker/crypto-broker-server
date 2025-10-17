// Package main defines executable program that listens for data using predefind IPC method
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/open-crypto-broker/crypto-broker-server/internal/clog"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/open-crypto-broker/crypto-broker-server/internal/di"
	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// defaultSocketPath defines default full OS path to socket file.
// The path is hardcoded and is also used by the clients in the different programming languages.
var (
	baseDir           = "/tmp"
	defaultSocketPath = filepath.Join(baseDir, "cryptobroker.sock")

	// defaultProfiles is predefined file name that contains profiles data
	defaultProfiles = "Profiles.yaml"
)

// interceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func interceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

// main defines executable program logic
func main() {
	rpcLogger := clog.SetupGlobalLogger()
	rpcLogger.Debug("Bootstrapping server dependencies")
	container := di.NewContainer(defaultProfiles)
	rpcLogger.Debug("Server dependencies bootstrapped")

	rpcLogger.Debug("Checking if directory for socket file exists", slog.String("path", baseDir))
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		rpcLogger.Debug("Directory for socket file does not exist, creating it", slog.String("path", baseDir))
		if err := os.Mkdir(baseDir, 0755); err != nil {
			rpcLogger.Error("Failed to create directory for socket file", slog.String("path", baseDir), slog.String("error", err.Error()))

			panic(err)
		}

		rpcLogger.Debug("Directory for socket file created", slog.String("path", baseDir))
	}

	rpcLogger.Debug("Directory for socket file exists", slog.String("path", baseDir))
	rpcLogger.Debug("Attempting to listen on socket", slog.String("address", defaultSocketPath))
	listener, err := net.Listen("unix", defaultSocketPath)
	if err != nil {
		rpcLogger.Error("Failed to listen on socket", slog.String("address", defaultSocketPath), slog.String("error", err.Error()))

		panic(err)
	}

	rpcLogger.Debug("Successfully listened on socket", slog.String("address", listener.Addr().String()))

	grpcPanicRecoveryHandler := func(p any) (err error) {
		rpcLogger.Error("recovered from panic", slog.String("panic", fmt.Sprintf("%v", p)))
		return status.Errorf(codes.Internal, "%s", p)
	}

	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			logging.UnaryServerInterceptor(interceptorLogger(rpcLogger)),
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(grpcPanicRecoveryHandler)),
		),
	)
	pb.RegisterCryptoBrokerServer(server, container.Server)

	rpcLogger.Debug("Starting to listen for system signals", slog.Group("signals", slog.String("SIGINT", "interrupt"), slog.String("SIGTERM", "termination")))
	// Handle termination signals for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c

		rpcLogger.Info("Received termination signal, shutting down gRPC server")

		server.GracefulStop()
		listener.Close()
		os.Remove(defaultSocketPath)
	}()

	rpcLogger.Info("server is serving incoming gRPC requests", slog.String("address", listener.Addr().String()))

	if err = server.Serve(listener); err != nil {
		rpcLogger.Error("Failed to serve gRPC requests",
			slog.String("address", listener.Addr().String()), slog.String("error", err.Error()))

		panic(err)
	}
}
