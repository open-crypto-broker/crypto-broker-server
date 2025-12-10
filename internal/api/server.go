package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
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
	timestampEndpointStart := time.Now()

	response, err := server.procedureHash.Execute(req)
	if err != nil {
		slog.Debug(err.Error())

		return nil, fmt.Errorf("something went wrong while hashing data: %s", err.Error())
	}

	timestampEndpointEnd := time.Now()
	durationElapsedEndpoint := timestampEndpointEnd.Sub(timestampEndpointStart)

	server.logDuration(ctx, "Hash", durationElapsedEndpoint)

	return response, nil
}

// Sign contains certificate signing logic
func (server *CryptoBrokerServer) Sign(ctx context.Context, req *protobuf.SignRequest) (*protobuf.SignResponse, error) {
	timestampEndpointStart := time.Now()

	response, err := server.procedureSign.Execute(req)
	if err != nil {
		slog.Debug(err.Error())

		return nil, fmt.Errorf("something went wrong while signing certificate: %s", err.Error())
	}

	timestampEndpointEnd := time.Now()
	durationElapsedEndpoint := timestampEndpointEnd.Sub(timestampEndpointStart)

	server.logDuration(ctx, "Sign", durationElapsedEndpoint)

	return response, nil
}

// Benchmark runs performance benchmarks on cryptographic operations
func (server *CryptoBrokerServer) Benchmark(ctx context.Context, req *protobuf.BenchmarkRequest) (*protobuf.BenchmarkResponse, error) {
	timestampEndpointStart := time.Now()

	response, err := server.procedureBenchmark.Execute(req)
	if err != nil {
		slog.Debug(err.Error())

		return nil, fmt.Errorf("something went wrong while running benchmarks: %s", err.Error())
	}

	timestampEndpointEnd := time.Now()
	durationElapsedEndpoint := timestampEndpointEnd.Sub(timestampEndpointStart)

	server.logDuration(ctx, "Benchmark", durationElapsedEndpoint)

	return response, nil
}

func (srv *CryptoBrokerServer) logDuration(ctx context.Context, methodName string, duration time.Duration) {
	slog.LogAttrs(ctx, slog.LevelDebug, "time measurement", slog.String("method", methodName), slog.Float64("duration", float64(duration.Nanoseconds())/1000.0))
}
