// Package main defines executable program that listens for data using predefind IPC method
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"crypto/fips140"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/open-crypto-broker/crypto-broker-server/internal/api"
	"github.com/open-crypto-broker/crypto-broker-server/internal/clog"
	"github.com/open-crypto-broker/crypto-broker-server/internal/di"
	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
	"github.com/open-crypto-broker/crypto-broker-server/internal/interceptors"
	"github.com/open-crypto-broker/crypto-broker-server/internal/otel"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
)

// defaultSocketPath defines default full OS path to socket file.
// The path is hardcoded and is also used by the clients in the different programming languages.
var (
	baseDir           = "/tmp/open-crypto-broker"
	defaultSocketPath = filepath.Join(baseDir, "crypto-broker-server.sock")

	// defaultProfiles is predefined file name that contains profiles data
	defaultProfiles = "Profiles.yaml"

	// gitSHA and gitTag are set at build time using ldflags
	gitSHA = "unknown"
	gitTag = "unknown"

	// ENV
	devENV = "dev"
)

// pprofHandler returns an HTTP handler with pprof endpoints registered on a dedicated mux.
func pprofHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	return mux
}

// interceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func interceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		if cid := interceptors.CorrelationIDFromContext(ctx); cid != "" {
			fields = append([]any{slog.String(string(otel.AttributeCorrelationId), cid)}, fields...)
		}
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func newGRPCServerStatsHandler(options ...otelgrpc.Option) stats.Handler {
	options = append(options, otelgrpc.WithPropagators(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	)))
	return otelgrpc.NewServerHandler(options...)
}

// main defines executable program logic
func main() {
	// Create context for initialization
	ctx := context.Background()
	rpcLogger := clog.SetupGlobalLogger(ctx)
	rpcLogger.Info("Server info", slog.String("git.sha", gitSHA), slog.String("git.tag", gitTag))
	rpcLogger.Debug("Bootstrapping server dependencies")
	container := di.NewContainer(ctx, defaultProfiles)
	rpcLogger.Debug("Server dependencies bootstrapped")

	if fips140.Enabled() {
		rpcLogger.Info("FIPS mode is enabled")
		rpcLogger.Info("FIPS mode version", slog.String("version", fips140.Version()))
		rpcLogger.Info("FIPS mode enforced", slog.Bool("enforced", fips140.Enforced()))
	} else {
		rpcLogger.Info("FIPS mode is disabled")
	}

	exporter, endpoint, sampler := os.Getenv(env.OTEL_TRACES_EXPORTER), os.Getenv(env.OTEL_EXPORTER_OTLP_ENDPOINT), os.Getenv(env.OTEL_TRACES_SAMPLER)
	switch otel.TracingBootstrapProbeDecision() {
	case otel.BootstrapProbeAttempted:
		if err := container.TracerProvider.ProbeExport(ctx, 5*time.Second); err != nil {
			rpcLogger.Warn("Tracing bootstrap probe failed",
				slog.String("exporters", exporter),
				slog.String("endpoint", endpoint),
				slog.String("error", err.Error()))
		} else {
			rpcLogger.Info("Tracing bootstrap probe succeeded",
				slog.String("exporters", exporter),
				slog.String("endpoint", endpoint))
		}
	case otel.BootstrapProbeSkippedDueToSampler:
		rpcLogger.Info("Tracing bootstrap probe skipped due to sampler",
			slog.String("sampler", sampler),
			slog.String("exporters", exporter))
	default:
	}

	rpcLogger.Debug("Checking if directory for socket file exists", slog.String("path", baseDir))
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		rpcLogger.Debug("Directory for socket file does not exist, creating it", slog.String("path", baseDir))
		if err := os.MkdirAll(baseDir, 0700); err != nil {
			rpcLogger.Error("Failed to create directory for socket file", slog.String("path", baseDir), slog.String("error", err.Error()))

			panic(err)
		}

		rpcLogger.Debug("Directory for socket file created", slog.String("path", baseDir))
	}

	rpcLogger.Debug("Directory for socket file exists", slog.String("path", baseDir))

	if removeErr := os.Remove(defaultSocketPath); removeErr != nil && !os.IsNotExist(removeErr) {
		rpcLogger.Warn("Failed to remove stale socket file", slog.String("path", defaultSocketPath), slog.String("error", removeErr.Error()))
	}

	rpcLogger.Debug("Attempting to listen on socket", slog.String("address", defaultSocketPath))

	// Restrict unix socket permissions to owner during creation.
	mask := syscall.Umask(0177)
	listener, err := net.Listen("unix", defaultSocketPath)
	if err != nil {
		rpcLogger.Error("Failed to listen on socket", slog.String("address", defaultSocketPath), slog.String("error", err.Error()))
		panic(err)
	}
	syscall.Umask(mask)

	if err = os.Chmod(defaultSocketPath, 0600); err != nil {
		rpcLogger.Error("Failed to set socket file permissions", slog.String("path", defaultSocketPath), slog.String("error", err.Error()))
		listener.Close()
		panic(err)
	}

	rpcLogger.Debug("Successfully listened on socket", slog.String("address", listener.Addr().String()))

	grpcPanicRecoveryHandler := func(p any) (err error) {
		rpcLogger.Error("recovered from panic", slog.String("panic", fmt.Sprintf("%v", p)))
		return status.Errorf(codes.Internal, "%s", p)
	}

	server := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			interceptors.UnaryRemoteTraceInterceptor(),
			interceptors.UnaryCorrelationInterceptor(),
			interceptors.UnaryRequestLifecycleObservabilityInterceptor(container.MeterProvider != nil),
			logging.UnaryServerInterceptor(interceptorLogger(rpcLogger)),
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(grpcPanicRecoveryHandler)),
		),
		grpc.MaxRecvMsgSize(int(api.MaxGrpcRecvMsgSize)),
		grpc.MaxSendMsgSize(int(api.MaxGrpcSendMsgSize)),
		grpc.MaxConcurrentStreams(getMaxConcurrentStreams()),
		grpc.StatsHandler(newGRPCServerStatsHandler()),
	)

	// Register crypto broker service
	pb.RegisterCryptoGrpcServer(server, container.Server)

	var pprofSrv *http.Server
	if os.Getenv(env.APP_ENV) == devENV {
		dev := api.NewCryptoBrokerDevServer(procedure.NewBenchmark(), procedure.NewFakeEndpoint())
		pb.RegisterCryptoGrpcDevServer(server, dev)

		if pprofAddr := os.Getenv(env.PPROF_ADDR); pprofAddr != "" {
			pprofSrv = &http.Server{
				Addr:              pprofAddr,
				Handler:           pprofHandler(),
				ReadHeaderTimeout: 10 * time.Second,
			}
			go func() {
				rpcLogger.Info("pprof HTTP server listening", slog.String("address", pprofAddr))

				if serveErr := pprofSrv.ListenAndServe(); serveErr != nil && serveErr != http.ErrServerClosed {
					rpcLogger.Error("pprof HTTP server exited", slog.String("error", serveErr.Error()))
				}
			}()
		}
	}

	// Register health check service
	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(server, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	rpcLogger.Debug("Starting to listen for system signals", slog.Group("signals", slog.String("SIGINT", "interrupt"), slog.String("SIGTERM", "termination")))
	// Handle termination signals for graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c

		rpcLogger.Info("Received termination signal, shutting down gRPC server")
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)

		if pprofSrv != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)

			if shutdownErr := pprofSrv.Shutdown(shutdownCtx); shutdownErr != nil {
				rpcLogger.Warn("pprof HTTP server shutdown failed", slog.String("error", shutdownErr.Error()))
			}
			cancel()
		}

		server.GracefulStop()

		// Shutdown tracer provider if initialized
		if container.TracerProvider != nil {
			if err = container.TracerProvider.Shutdown(ctx); err != nil {
				rpcLogger.Error("Failed to shutdown tracer provider", slog.String("error", err.Error()))
			}
		}

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

func getMaxConcurrentStreams() uint32 {
	maxConcurrentStreams := uint32(1024)
	val := os.Getenv(env.GRPC_MAX_CONCURRENT_STREAMS)

	if val != "" {
		custom, err := strconv.ParseUint(val, 10, 32)
		if err == nil {
			maxConcurrentStreams = uint32(custom)
		}
	}

	return maxConcurrentStreams
}
