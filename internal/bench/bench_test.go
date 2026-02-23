package bench

import (
	"testing"
)

// BenchmarkLibraryNative_HashSHA3_256 to run benchmark:
// go test -benchmem -run=^$ -bench ^BenchmarkLibraryNative_HashSHA3_256$ github.com/open-crypto-broker/crypto-broker-server/internal/bench
func BenchmarkLibraryNative_HashSHA3_256(b *testing.B) {
	RunHashSHA3_256Benchmark(b)
}

func BenchmarkLibraryNative_HashSHA3_384(b *testing.B) {
	RunHashSHA3_384Benchmark(b)
}

func BenchmarkLibraryNative_HashSHA3_512(b *testing.B) {
	RunHashSHA3_512Benchmark(b)
}

func BenchmarkLibraryNative_HashSHA_256(b *testing.B) {
	RunHashSHA_256Benchmark(b)
}

func BenchmarkLibraryNative_HashSHA_384(b *testing.B) {
	RunHashSHA_384Benchmark(b)
}

func BenchmarkLibraryNative_HashSHA_512(b *testing.B) {
	RunHashSHA_512Benchmark(b)
}

func BenchmarkLibraryNative_HashSHA_512_256(b *testing.B) {
	RunHashSHA_512_256Benchmark(b)
}

func BenchmarkLibraryNative_HashShake_128(b *testing.B) {
	RunHashShake_128Benchmark(b)
}

func BenchmarkLibraryNative_HashShake_256(b *testing.B) {
	RunHashShake_256Benchmark(b)
}

func BenchmarkLibraryNative_SignCertificate_CSR_SECP256R1_CA_RSA4096(b *testing.B) {
	err := RunSignCertificate_CSR_SECP521R1_CA_RSA4096Benchmark(b)
	if err != nil {
		b.Fatalf("benchmark failed: %s", err.Error())
	}
}

func BenchmarkLibraryNative_SignCertificate_CSR_SECP521R1_CA_SECP521R1(b *testing.B) {
	err := RunSignCertificate_CSR_SECP521R1_CA_SECP521R1Benchmark(b)
	if err != nil {
		b.Fatalf("benchmark failed: %s", err.Error())
	}
}

func BenchmarkLibraryNative_SignCertificate_CSR_SECP256R1_CA_SECP384R1(b *testing.B) {
	err := RunSignCertificate_CSR_SECP256R1_CA_SECP384R1Benchmark(b)
	if err != nil {
		b.Fatalf("benchmark failed: %s", err.Error())
	}
}

func BenchmarkLibraryNative_SignCertificate(b *testing.B) {
	err := RunSignCertificateBenchmark(b)
	if err != nil {
		b.Fatalf("benchmark failed: %s", err.Error())
	}
}
