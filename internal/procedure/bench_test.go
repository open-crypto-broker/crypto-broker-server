package procedure

import (
	"strings"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

func TestNewBenchmark(t *testing.T) {
	p := NewBenchmark()
	if p == nil {
		t.Fatalf("expected non-nil")
	}
}

func TestBenchmark_Execute(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark procedure in -short mode")
	}

	p := NewBenchmark()
	resp, err := p.Execute(&protobuf.BenchmarkRequest{})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if resp.BenchmarkResults == "" {
		t.Fatalf("expected non-empty BenchmarkResults")
	}
	if !strings.Contains(resp.BenchmarkResults, `"results"`) {
		t.Fatalf("expected JSON results to contain \"results\" key, got: %s", resp.BenchmarkResults)
	}
}
