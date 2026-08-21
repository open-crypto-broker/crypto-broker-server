package api

import (
	"context"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
)

func TestCryptoBrokerDevServer_Benchmark_MetricsEnabled_Success_RecordsMetricsBranch(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark endpoint test in -short mode")
	}

	otel.SetMeterProvider(metricnoop.NewMeterProvider())

	server := NewCryptoBrokerDevServer(
		procedure.NewBenchmark(),
		procedure.NewFakeEndpoint(),
	)

	resp, err := server.Benchmark(context.Background(), &protobuf.BenchmarkRequest{
		Metadata: &protobuf.Metadata{
			TraceContext: &protobuf.TraceContext{
				CorrelationId: "corr-benchmark-metrics-1",
			},
		},
	})
	if err != nil {
		t.Fatalf("expected success, got err: %v", err)
	}
	if resp == nil || len(resp.GetBenchmarkResults()) == 0 {
		t.Fatalf("expected non-empty benchmark results")
	}
}

func TestCryptoBrokerDevServer_FakeEndpoint_MetricsEnabled_CoversErrorAndSuccess(t *testing.T) {
	otel.SetMeterProvider(metricnoop.NewMeterProvider())

	server := NewCryptoBrokerDevServer(
		procedure.NewBenchmark(),
		procedure.NewFakeEndpoint(),
	)

	// First 4 calls should return error.
	for i := 1; i <= 4; i++ {
		_, err := server.FakeEndpoint(context.Background(), &protobuf.FakeEndpointRequest{})
		if err == nil {
			t.Fatalf("expected error on call %d", i)
		}
	}

	// 5th call succeeds.
	resp, err := server.FakeEndpoint(context.Background(), &protobuf.FakeEndpointRequest{})
	if err != nil {
		t.Fatalf("expected success on 5th call, got: %v", err)
	}
	if resp.GetMessage() == "" {
		t.Fatalf("expected non-empty response message")
	}
}
