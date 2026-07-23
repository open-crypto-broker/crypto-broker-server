package procedure

import (
	"encoding/json"
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
	if resp.GetBenchmarkResults() == "" {
		t.Fatalf("expected non-empty BenchmarkResults")
	}
	if !strings.Contains(resp.GetBenchmarkResults(), `"results"`) {
		t.Fatalf("expected JSON results to contain \"results\" key, got: %s", resp.GetBenchmarkResults())
	}

	var results benchmarkResults
	if err := json.Unmarshal([]byte(resp.GetBenchmarkResults()), &results); err != nil {
		t.Fatalf("could not decode benchmark results: %v", err)
	}

	benchmarkNames := make(map[string]struct{}, len(results.Results))
	for _, result := range results.Results {
		benchmarkNames[result.Name] = struct{}{}
	}
	for _, name := range []string{"BenchmarkLibraryNative_EncryptData", "BenchmarkLibraryNative_DecryptData"} {
		if _, found := benchmarkNames[name]; !found {
			t.Fatalf("expected benchmark result %q, got %#v", name, results.Results)
		}
	}
}
