package procedure

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/bench"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

type Benchmark struct {}

// benchmarkResult represents the result of a single benchmark
type benchmarkResult struct {
	Name    string `json:"name"`
	AvgTime int64  `json:"avgTime"` // nanoseconds
}

// benchmarkResults represents the collection of all benchmark results
type benchmarkResults struct {
	Results []benchmarkResult `json:"results"`
}

func NewBenchmark() *Benchmark {
	return &Benchmark{}
}

func (procedure *Benchmark) Execute(req *protobuf.BenchmarkRequest) (*protobuf.BenchmarkResponse, error) {
	results, err := procedure.runAllBenchmarks()
	if err != nil {
		return nil, fmt.Errorf("failed to run benchmarks: %w", err)
	}

	jsonResults, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("failed to encode benchmark results: %w", err)
	}

	return &protobuf.BenchmarkResponse{BenchmarkResults: string(jsonResults), Metadata: req.Metadata}, nil
}

// runAllBenchmarks executes all cryptographic benchmarks and returns the results
func (procedure *Benchmark) runAllBenchmarks() (benchmarkResults, error) {
	results := make([]benchmarkResult, 0, 11)

	results = append(results, procedure.runHashBenchmark("BenchmarkLibraryNative_HashSHA3_256", bench.RunHashSHA3_256Benchmark))
	results = append(results, procedure.runHashBenchmark("BenchmarkLibraryNative_HashSHA3_384", bench.RunHashSHA3_384Benchmark))
	results = append(results, procedure.runHashBenchmark("BenchmarkLibraryNative_HashSHA3_512", bench.RunHashSHA3_512Benchmark))
	results = append(results, procedure.runHashBenchmark("BenchmarkLibraryNative_HashSHA_256", bench.RunHashSHA_256Benchmark))
	results = append(results, procedure.runHashBenchmark("BenchmarkLibraryNative_HashSHA_384", bench.RunHashSHA_384Benchmark))
	results = append(results, procedure.runHashBenchmark("BenchmarkLibraryNative_HashSHA_512", bench.RunHashSHA_512Benchmark))
	results = append(results, procedure.runHashBenchmark("BenchmarkLibraryNative_HashSHA_512_256", bench.RunHashSHA_512_256Benchmark))

	signCertificateNISTSECP521R1RSA4096Result, err := procedure.runSignBenchmark(
		"BenchmarkLibraryNative_SignCertificate_NIST_SECP521R1_RSA4096", bench.RunSignCertificateNISTSECP521R1RSA4096Benchmark)
	if err != nil {
		return benchmarkResults{Results: results}, err
	}
	results = append(results, signCertificateNISTSECP521R1RSA4096Result)

	signCertificateNISTSECP521R1NISTSECP521R1Result, err := procedure.runSignBenchmark(
		"BenchmarkLibraryNative_SignCertificate_NIST_SECP521R1_NIST_SECP521R1", bench.RunSignCertificateNISTSECP521R1NISTSECP521R1Benchmark)
	if err != nil {
		return benchmarkResults{Results: results}, err
	}
	results = append(results, signCertificateNISTSECP521R1NISTSECP521R1Result)

	return benchmarkResults{Results: results}, nil
}

// runHashBenchmark executes a hash benchmark and returns the result
func (procedure *Benchmark) runHashBenchmark(name string, benchmarkFunc func(*testing.B)) benchmarkResult {
	b := &testing.B{N: 1000}
	start := time.Now()
	benchmarkFunc(b)
	duration := time.Since(start)
	avgTime := duration.Nanoseconds() / int64(b.N)
	return benchmarkResult{Name: name, AvgTime: avgTime}
}

// runSignBenchmark executes a certificate signing benchmark and returns the result
func (procedure *Benchmark) runSignBenchmark(name string, benchmarkFunc func(*testing.B) error) (benchmarkResult, error) {
	b := &testing.B{N: 10}

	start := time.Now()
	err := benchmarkFunc(b)
	duration := time.Since(start)

	if err != nil {
		return benchmarkResult{Name: name, AvgTime: 0}, err
	}

	avgTime := duration.Nanoseconds() / int64(b.N)

	return benchmarkResult{Name: name, AvgTime: avgTime}, nil
}