package api

import (
	"context"
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/otel"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// CryptoBrokerServer defines crypto broker's server
type CryptoBrokerServer struct {
	protobuf.CryptoGrpcServer
	procedureHash      *procedure.Hash
	procedureSign      *procedure.Sign
	procedureBenchmark *procedure.Benchmark
}

func NewCryptoBrokerServer(c10yNative *c10y.LibraryNative, procedureHash *procedure.Hash, procedureSign *procedure.Sign, procedureBenchmark *procedure.Benchmark) *CryptoBrokerServer {
	return &CryptoBrokerServer{
		procedureHash:      procedureHash,
		procedureSign:      procedureSign,
		procedureBenchmark: procedureBenchmark,
	}
}

// Hash contains data hashing logic
func (server *CryptoBrokerServer) Hash(ctx context.Context, req *protobuf.HashRequest) (*protobuf.HashResponse, error) {
	tracer := otel.GetGlobalTracer(otel.ServiceName)

	// If trace context is provided in metadata, inject it into the context
	// This allows otelgrpc's automatic instrumentation to use it as the parent span
	if req.Metadata != nil && req.Metadata.TraceContext != nil {
		traceID, err := trace.TraceIDFromHex(req.Metadata.TraceContext.TraceId)
		if err == nil {
			spanID, err := trace.SpanIDFromHex(req.Metadata.TraceContext.SpanId)
			if err == nil {
				// Create a remote span context from the client's trace context
				remoteSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
					Remote:     true,
				})

				// Set this as the parent context
				ctx = trace.ContextWithRemoteSpanContext(ctx, remoteSpanContext)
			}
		}
	}

	// Create a child span from the context (which now has the client's span as parent)
	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.Hash",
		trace.WithAttributes(
			otel.AttributeRpcMethod.String("Hash"),
			otel.AttributeCryptoProfile.String(req.Profile),
			otel.AttributeCryptoInputSize.Int(len(req.Input)),
		))
	defer span.End()

	response, err := server.procedureHash.Execute(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		return nil, fmt.Errorf("something went wrong while hashing data: %s", err.Error())
	}

	span.SetAttributes(
		otel.AttributeCryptoHashAlgorithm.String(response.HashAlgorithm),
		otel.AttributeCryptoHashOutputSize.Int(len(response.HashValue)),
	)
	span.SetStatus(codes.Ok, "Hash operation completed successfully")

	return response, nil
}

// Sign contains certificate signing logic
func (server *CryptoBrokerServer) Sign(ctx context.Context, req *protobuf.SignRequest) (*protobuf.SignResponse, error) {
	tracer := otel.GetGlobalTracer(otel.ServiceName)

	// If trace context is provided in metadata, inject it into the context
	// This allows otelgrpc's automatic instrumentation to use it as the parent span
	if req.Metadata != nil && req.Metadata.TraceContext != nil {
		traceID, err := trace.TraceIDFromHex(req.Metadata.TraceContext.TraceId)
		if err == nil {
			spanID, err := trace.SpanIDFromHex(req.Metadata.TraceContext.SpanId)
			if err == nil {
				// Create a remote span context from the client's trace context
				remoteSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
					Remote:     true,
				})

				// Set this as the parent context
				ctx = trace.ContextWithRemoteSpanContext(ctx, remoteSpanContext)
			}
		}
	}

	// Create a child span from the context (which now has the client's span as parent)
	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.Sign",
		trace.WithAttributes(
			otel.AttributeRpcMethod.String("Sign"),
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

		return nil, fmt.Errorf("something went wrong while signing certificate: %s", err.Error())
	}

	span.SetAttributes(otel.AttributeCryptoSignedCertSize.Int(len(response.SignedCertificate)))
	span.SetStatus(codes.Ok, "Certificate signing completed successfully")

	return response, nil
}

// Benchmark runs performance benchmarks on cryptographic operations
func (server *CryptoBrokerServer) Benchmark(ctx context.Context, req *protobuf.BenchmarkRequest) (*protobuf.BenchmarkResponse, error) {
	tracer := otel.GetGlobalTracer(otel.ServiceName)

	// If trace context is provided in metadata, inject it into the context
	// This allows otelgrpc's automatic instrumentation to use it as the parent span
	if req.Metadata != nil && req.Metadata.TraceContext != nil {
		traceID, err := trace.TraceIDFromHex(req.Metadata.TraceContext.TraceId)
		if err == nil {
			spanID, err := trace.SpanIDFromHex(req.Metadata.TraceContext.SpanId)
			if err == nil {
				// Create a remote span context from the client's trace context
				remoteSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
					TraceID:    traceID,
					SpanID:     spanID,
					TraceFlags: trace.FlagsSampled,
					Remote:     true,
				})

				// Set this as the parent context
				ctx = trace.ContextWithRemoteSpanContext(ctx, remoteSpanContext)
			}
		}
	}

	// Create a child span from the context (which now has the client's span as parent)
	ctx, span := tracer.Start(ctx, "CryptoBrokerServer.Benchmark",
		trace.WithAttributes(otel.AttributeRpcMethod.String("Benchmark")))
	defer span.End()

	response, err := server.procedureBenchmark.Execute(req)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())

		return nil, fmt.Errorf("something went wrong while running benchmarks: %s", err.Error())
	}

	span.SetAttributes(otel.AttributeCryptoBenchmarkResultsSize.Int(len(response.BenchmarkResults)))
	span.SetStatus(codes.Ok, "Benchmark operation completed successfully")

	return response, nil
}
