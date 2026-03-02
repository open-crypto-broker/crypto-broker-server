package api

import (
	"context"
	"fmt"
	"runtime"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/otel"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// CryptoBrokerServer defines crypto broker's server
type CryptoBrokerServer struct {
	protobuf.CryptoGrpcServer
	procedureHash         *procedure.Hash
	procedureSign         *procedure.Sign
	procedureBenchmark    *procedure.Benchmark
	procedureFakeEndpoint *procedure.FakeEndpoint
	meter                 metric.Meter
	metricsEnabled        bool
}

func NewCryptoBrokerServer(c10yNative *c10y.LibraryNative, procedureHash *procedure.Hash, procedureSign *procedure.Sign, procedureBenchmark *procedure.Benchmark, procedureFakeEndpoint *procedure.FakeEndpoint, metricsEnabled bool) *CryptoBrokerServer {
	server := &CryptoBrokerServer{
		procedureHash:         procedureHash,
		procedureSign:         procedureSign,
		procedureBenchmark:    procedureBenchmark,
		procedureFakeEndpoint: procedureFakeEndpoint,
		metricsEnabled:        metricsEnabled,
	}

	if metricsEnabled {
		server.meter = otel.GetGlobalMeter(otel.ServiceName)
		if err := otel.InitializeInstruments(server.meter); err != nil {
			panic(fmt.Sprintf("failed to initialize metric instruments: %v", err))
		}
		go server.collectSystemMetrics()
	}

	return server
}

// Hash contains data hashing logic
func (server *CryptoBrokerServer) Hash(ctx context.Context, req *protobuf.HashRequest) (*protobuf.HashResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	tracer := otel.GetGlobalTracer(otel.ServiceName)
	if req.Metadata != nil && req.Metadata.TraceContext != nil {
		traceID, err := trace.TraceIDFromHex(req.Metadata.TraceContext.TraceId)
		if err == nil {
			spanID, err := trace.SpanIDFromHex(req.Metadata.TraceContext.SpanId)
			if err == nil {
				remoteSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
					Remote:     true,
				})

				ctx = trace.ContextWithRemoteSpanContext(ctx, remoteSpanContext)
			}
		}
	}

	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.Hash",
		trace.WithAttributes(
			otel.AttributeRpcMethod.String(otel.RPCMethodHash),
			otel.AttributeCryptoProfile.String(req.Profile),
			otel.AttributeCryptoInputSize.Int(len(req.Input)),
		))
	defer span.End()

	response, err := server.procedureHash.Execute(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		if server.metricsEnabled {
			duration := time.Since(start).Seconds()
			// Record error metrics
			otel.OperationsErrorsTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodHash),
				attribute.String("error_type", "hash_error"),
			))

			otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodHash),
				attribute.String("profile", req.Profile),
				attribute.String("status", otel.StatusError),
			))
		}

		return nil, fmt.Errorf("something went wrong while hashing data: %s", err.Error())
	}

	span.SetAttributes(
		otel.AttributeCryptoHashAlgorithm.String(response.HashAlgorithm),
		otel.AttributeCryptoHashOutputSize.Int(len(response.HashValue)),
	)
	span.SetStatus(codes.Ok, "Hash operation completed successfully")

	if server.metricsEnabled {
		duration := time.Since(start).Seconds()
		otel.RequestsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodHash),
			attribute.String("profile", req.Profile),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodHash),
			attribute.String("profile", req.Profile),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.HashOperationsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("algorithm", response.HashAlgorithm),
		))

		otel.OperationBytesProcessed.Add(ctx, int64(len(req.Input)), metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodHash),
		))
	}

	return response, nil
}

// Sign contains certificate signing logic
func (server *CryptoBrokerServer) Sign(ctx context.Context, req *protobuf.SignRequest) (*protobuf.SignResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	tracer := otel.GetGlobalTracer(otel.ServiceName)

	if req.Metadata != nil && req.Metadata.TraceContext != nil {
		traceID, err := trace.TraceIDFromHex(req.Metadata.TraceContext.TraceId)
		if err == nil {
			spanID, err := trace.SpanIDFromHex(req.Metadata.TraceContext.SpanId)
			if err == nil {
				remoteSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
					Remote:     true,
				})

				ctx = trace.ContextWithRemoteSpanContext(ctx, remoteSpanContext)
			}
		}
	}

	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.Sign",
		trace.WithAttributes(
			otel.AttributeRpcMethod.String(otel.RPCMethodSign),
			otel.AttributeCryptoProfile.String(req.Profile),
			otel.AttributeCryptoCsrSize.Int(len(req.Csr)),
			otel.AttributeCryptoCaCertSize.Int(len(req.CaCert)),
			otel.AttributeCryptoCaKeySize.Int(len(req.CaPrivateKey)),
		))
	defer span.End()

	response, err := server.procedureSign.Execute(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		if server.metricsEnabled {
			duration := time.Since(start).Seconds()
			// Record error metrics
			otel.OperationsErrorsTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodSign),
				attribute.String("error_type", "sign_error"),
			))

			otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodSign),
				attribute.String("profile", req.Profile),
				attribute.String("status", otel.StatusError),
			))
		}

		return nil, fmt.Errorf("something went wrong while signing certificate: %s", err.Error())
	}

	span.SetAttributes(otel.AttributeCryptoSignedCertSize.Int(len(response.SignedCertificate)))
	span.SetStatus(codes.Ok, "Certificate signing completed successfully")

	if server.metricsEnabled {
		duration := time.Since(start).Seconds()
		// Record success metrics
		otel.RequestsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSign),
			attribute.String("profile", req.Profile),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSign),
			attribute.String("profile", req.Profile),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.SignOperationsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("profile", req.Profile),
		))

		otel.OperationBytesProcessed.Add(ctx, int64(len(req.Csr)+len(req.CaCert)+len(req.CaPrivateKey)), metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodSign),
		))
	}

	return response, nil
}

// Benchmark runs performance benchmarks on cryptographic operations
func (server *CryptoBrokerServer) Benchmark(ctx context.Context, req *protobuf.BenchmarkRequest) (*protobuf.BenchmarkResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	tracer := otel.GetGlobalTracer(otel.ServiceName)

	if req.Metadata != nil && req.Metadata.TraceContext != nil {
		traceID, err := trace.TraceIDFromHex(req.Metadata.TraceContext.TraceId)
		if err == nil {
			spanID, err := trace.SpanIDFromHex(req.Metadata.TraceContext.SpanId)
			if err == nil {
				remoteSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
					Remote:     true,
				})

				ctx = trace.ContextWithRemoteSpanContext(ctx, remoteSpanContext)
			}
		}
	}

	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.Benchmark",
		trace.WithAttributes(otel.AttributeRpcMethod.String(otel.RPCMethodBenchmark)))
	defer span.End()

	response, err := server.procedureBenchmark.Execute(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		if server.metricsEnabled {
			duration := time.Since(start).Seconds()
			// Record error metrics
			otel.OperationsErrorsTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodBenchmark),
				attribute.String("error_type", "benchmark_error"),
			))

			otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodBenchmark),
				attribute.String("status", otel.StatusError),
			))
		}

		return nil, fmt.Errorf("something went wrong while running benchmarks: %s", err.Error())
	}

	span.SetAttributes(otel.AttributeCryptoBenchmarkResultsSize.Int(len(response.BenchmarkResults)))
	span.SetStatus(codes.Ok, "Benchmark operation completed successfully")

	if server.metricsEnabled {
		duration := time.Since(start).Seconds()
		// Record success metrics
		otel.RequestsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodBenchmark),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodBenchmark),
			attribute.String("status", otel.StatusSuccess),
		))
	}

	return response, nil
}

// FakeEndpoint runs the fake endpoint procedure
func (server *CryptoBrokerServer) FakeEndpoint(ctx context.Context, req *protobuf.FakeEndpointRequest) (*protobuf.FakeEndpointResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	tracer := otel.GetGlobalTracer(otel.ServiceName)

	if req.Metadata != nil && req.Metadata.TraceContext != nil {
		traceID, err := trace.TraceIDFromHex(req.Metadata.TraceContext.TraceId)
		if err == nil {
			spanID, err := trace.SpanIDFromHex(req.Metadata.TraceContext.SpanId)
			if err == nil {
				remoteSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
					Remote:     true,
				})

				ctx = trace.ContextWithRemoteSpanContext(ctx, remoteSpanContext)
			}
		}
	}

	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.FakeEndpoint",
		trace.WithAttributes(otel.AttributeRpcMethod.String(otel.RPCMethodFakeEndpoint)))
	defer span.End()

	response, err := server.procedureFakeEndpoint.Execute(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		if server.metricsEnabled {
			duration := time.Since(start).Seconds()
			// Record error metrics
			otel.OperationsErrorsTotal.Add(ctx, 1, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodFakeEndpoint),
				attribute.String("error_type", "fake_endpoint_error"),
			))

			otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
				attribute.String("rpc_method", otel.RPCMethodFakeEndpoint),
				attribute.String("status", otel.StatusError),
			))
		}

		return nil, err
	}

	span.SetStatus(codes.Ok, "Fake endpoint operation completed successfully")

	if server.metricsEnabled {
		duration := time.Since(start).Seconds()
		// Record success metrics
		otel.RequestsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodFakeEndpoint),
			attribute.String("status", otel.StatusSuccess),
		))

		otel.RequestDuration.Record(ctx, duration, metric.WithAttributes(
			attribute.String("rpc_method", otel.RPCMethodFakeEndpoint),
			attribute.String("status", otel.StatusSuccess),
		))
	}

	return response, nil
}

// collectSystemMetrics sets up asynchronous metric callbacks for system metrics
func (server *CryptoBrokerServer) collectSystemMetrics() {
	if !server.metricsEnabled {
		return
	}

	// Set up asynchronous gauge for memory usage
	_, err := server.meter.RegisterCallback(func(ctx context.Context, o metric.Observer) error {
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		o.ObserveInt64(otel.MemoryUsage, int64(m.Alloc))
		return nil
	}, otel.MemoryUsage)
	if err != nil {
		panic(fmt.Sprintf("failed to register memory usage callback: %v", err))
	}
}
