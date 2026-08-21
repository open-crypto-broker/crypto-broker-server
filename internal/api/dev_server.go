package api

import (
	"context"
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-server/internal/otel"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/trace"
)

// CryptoBrokerDevServer defines crypto broker's development server
type CryptoBrokerDevServer struct {
	protobuf.CryptoGrpcDevServer
	procedureBenchmark    *procedure.Benchmark
	procedureFakeEndpoint *procedure.FakeEndpoint
}

func NewCryptoBrokerDevServer(procedureBenchmark *procedure.Benchmark, procedureFakeEndpoint *procedure.FakeEndpoint) *CryptoBrokerDevServer {
	return &CryptoBrokerDevServer{
		procedureBenchmark:    procedureBenchmark,
		procedureFakeEndpoint: procedureFakeEndpoint,
	}
}

// Benchmark runs performance benchmarks on cryptographic operations
func (server *CryptoBrokerDevServer) Benchmark(ctx context.Context, req *protobuf.BenchmarkRequest) (*protobuf.BenchmarkResponse, error) {
	span := trace.SpanFromContext(ctx)
	response, err := server.procedureBenchmark.Execute(req)

	if err != nil {
		return nil, fmt.Errorf("something went wrong while running benchmarks: %w", err)
	}

	span.SetAttributes(otel.AttributeCryptoBenchmarkResultsSize.Int(len(response.GetBenchmarkResults())))

	return response, nil
}

// FakeEndpoint runs the fake endpoint procedure
func (server *CryptoBrokerDevServer) FakeEndpoint(ctx context.Context, req *protobuf.FakeEndpointRequest) (*protobuf.FakeEndpointResponse, error) {
	response, err := server.procedureFakeEndpoint.Execute(req)

	if err != nil {
		return nil, err
	}

	return response, nil
}
