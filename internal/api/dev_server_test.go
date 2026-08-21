package api

import (
	"context"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

func TestCryptoBrokerDevServer_Benchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark endpoint test in -short mode")
	}

	server := NewCryptoBrokerDevServer(
		procedure.NewBenchmark(),
		procedure.NewFakeEndpoint(),
	)

	resp, err := server.Benchmark(context.Background(), &protobuf.BenchmarkRequest{
		Metadata: &protobuf.Metadata{
			TraceContext: &protobuf.TraceContext{
				CorrelationId: "corr-benchmark-1",
			},
		},
	})
	if err != nil {
		t.Fatalf("Benchmark failed: %v", err)
	}
	if len(resp.GetBenchmarkResults()) == 0 {
		t.Fatalf("expected non-empty benchmark results")
	}
}

func TestCryptoBrokerDevServer_FakeEndpoint(t *testing.T) {
	server := NewCryptoBrokerDevServer(
		procedure.NewBenchmark(),
		procedure.NewFakeEndpoint(),
	)

	for i := 1; i <= 4; i++ {
		_, err := server.FakeEndpoint(context.Background(), &protobuf.FakeEndpointRequest{})
		if err == nil {
			t.Fatalf("expected error on call %d", i)
		}
	}

	resp, err := server.FakeEndpoint(context.Background(), &protobuf.FakeEndpointRequest{})
	if err != nil {
		t.Fatalf("expected success on 5th call, got: %v", err)
	}
	if resp.GetMessage() == "" {
		t.Fatalf("expected non-empty response message")
	}
}
