package api

import (
	"context"
	"fmt"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/interceptors"
	"github.com/open-crypto-broker/crypto-broker-server/internal/otel"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// CryptoBrokerDevServer defines crypto broker's development server
type CryptoBrokerDevServer struct {
	protobuf.CryptoGrpcDevServer
	procedureBenchmark    *procedure.Benchmark
	procedureFakeEndpoint *procedure.FakeEndpoint
	metricsEnabled        bool
}

func NewCryptoBrokerDevServer(procedureBenchmark *procedure.Benchmark, procedureFakeEndpoint *procedure.FakeEndpoint, metricsEnabled bool) *CryptoBrokerDevServer {
	return &CryptoBrokerDevServer{
		procedureBenchmark:    procedureBenchmark,
		procedureFakeEndpoint: procedureFakeEndpoint,
	}
}

// Benchmark runs performance benchmarks on cryptographic operations
func (server *CryptoBrokerDevServer) Benchmark(ctx context.Context, req *protobuf.BenchmarkRequest) (*protobuf.BenchmarkResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	tracer := otel.GetGlobalTracer()
	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.Benchmark",
		trace.WithAttributes(otel.AttributeRpcMethod.String(otel.RPCMethodBenchmark),
			otel.AttributeCorrelationId.String(req.GetMetadata().GetTraceContext().GetCorrelationId()),
		))
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

		return nil, fmt.Errorf("something went wrong while running benchmarks: %w", err)
	}

	span.SetAttributes(otel.AttributeCryptoBenchmarkResultsSize.Int(len(response.GetBenchmarkResults())))
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
func (server *CryptoBrokerDevServer) FakeEndpoint(ctx context.Context, req *protobuf.FakeEndpointRequest) (*protobuf.FakeEndpointResponse, error) {
	var start time.Time
	if server.metricsEnabled {
		start = time.Now()
	}

	tracer := otel.GetGlobalTracer()
	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.FakeEndpoint",
		trace.WithAttributes(otel.AttributeRpcMethod.String(otel.RPCMethodFakeEndpoint),
			otel.AttributeCorrelationId.String(interceptors.CorrelationIDFromProtoRequest(req)),
		))
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
