package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/bench"
	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

// CryptoBrokerServer defines crypto broker's server
type CryptoBrokerServer struct {
	protobuf.CryptoGrpcServer
	cryptographicEngineNative *c10y.LibraryNative
}

func NewCryptoBrokerServer(c10yNative *c10y.LibraryNative) *CryptoBrokerServer {
	return &CryptoBrokerServer{cryptographicEngineNative: c10yNative}
}

// Hash contains data hashing logic
func (server *CryptoBrokerServer) Hash(ctx context.Context, req *protobuf.HashRequest) (*protobuf.HashResponse, error) {
	timestampEndpointStart := time.Now()

	reqProfile, err := profile.Retrieve(req.Profile)
	if err != nil {
		slog.Debug(err.Error())

		return nil, fmt.Errorf("could not retrieve profile, err: %w", err)
	}

	hashedBytes, err := server.hash(req.Input, reqProfile)
	if err != nil {
		slog.Debug(err.Error())

		return nil, fmt.Errorf("error while hashing data: %s", err.Error())
	}

	timestampEndpointEnd := time.Now()
	durationElapsedEndpoint := timestampEndpointEnd.Sub(timestampEndpointStart)

	server.logDuration(ctx, "Hash", durationElapsedEndpoint)

	return &protobuf.HashResponse{
		HashValue:     string(hashedBytes),
		HashAlgorithm: reqProfile.API.HashData.HashAlg.String(),
		Metadata:      req.Metadata,
	}, nil
}

// Sign contains certificate signing logic
func (server *CryptoBrokerServer) Sign(ctx context.Context, req *protobuf.SignRequest) (*protobuf.SignResponse, error) {
	timestampEndpointStart := time.Now()

	reqProfile, err := profile.Retrieve(req.Profile)
	if err != nil {
		slog.Debug(err.Error())

		return nil, fmt.Errorf("could not retrieve profile, err: %w", err)
	}

	input, err := newSignClientInput(req)
	if err != nil {
		slog.Debug(err.Error())

		return nil, fmt.Errorf("error parsing request data: %w", err)
	}

	clientCRTRaw, err := server.sign(input, reqProfile)
	if err != nil {
		slog.Debug(err.Error())

		return nil, fmt.Errorf("error while signing data: %w", err)
	}

	timestampEndpointEnd := time.Now()
	durationElapsedEndpoint := timestampEndpointEnd.Sub(timestampEndpointStart)

	server.logDuration(ctx, "Sign", durationElapsedEndpoint)

	return &protobuf.SignResponse{
		SignedCertificate: base64.StdEncoding.EncodeToString(clientCRTRaw),
		Metadata:          req.Metadata,
	}, nil
}

// BenchmarkResult represents the result of a single benchmark
type BenchmarkResult struct {
	Name    string `json:"name"`
	AvgTime int64  `json:"avgTime"` // nanoseconds
}

// BenchmarkResults represents the collection of all benchmark results
type BenchmarkResults struct {
	Results []BenchmarkResult `json:"results"`
}

// Benchmark runs performance benchmarks on cryptographic operations
func (server *CryptoBrokerServer) Benchmark(ctx context.Context, req *protobuf.BenchmarkRequest) (*protobuf.BenchmarkResponse, error) {
	timestampEndpointStart := time.Now()

	results, err := server.runAllBenchmarks()
	if err != nil {
		slog.Debug("failed to run benchmarks", slog.String("error", err.Error()))

		return nil, fmt.Errorf("failed to run benchmarks: %w", err)
	}

	jsonResults, err := json.Marshal(results)
	if err != nil {
		slog.Debug("failed to encode benchmark results", slog.String("error", err.Error()))

		return nil, fmt.Errorf("failed to encode benchmark results: %w", err)
	}

	timestampEndpointEnd := time.Now()
	durationElapsedEndpoint := timestampEndpointEnd.Sub(timestampEndpointStart)

	server.logDuration(ctx, "Benchmark", durationElapsedEndpoint)

	return &protobuf.BenchmarkResponse{BenchmarkResults: string(jsonResults), Metadata: req.Metadata}, nil
}

// runAllBenchmarks executes all cryptographic benchmarks and returns the results
func (server *CryptoBrokerServer) runAllBenchmarks() (BenchmarkResults, error) {
	results := make([]BenchmarkResult, 0, 11)

	results = append(results, runHashBenchmark("BenchmarkLibraryNative_HashSHA3_256", bench.RunHashSHA3_256Benchmark))
	results = append(results, runHashBenchmark("BenchmarkLibraryNative_HashSHA3_384", bench.RunHashSHA3_384Benchmark))
	results = append(results, runHashBenchmark("BenchmarkLibraryNative_HashSHA3_512", bench.RunHashSHA3_512Benchmark))
	results = append(results, runHashBenchmark("BenchmarkLibraryNative_HashSHA_256", bench.RunHashSHA_256Benchmark))
	results = append(results, runHashBenchmark("BenchmarkLibraryNative_HashSHA_384", bench.RunHashSHA_384Benchmark))
	results = append(results, runHashBenchmark("BenchmarkLibraryNative_HashSHA_512", bench.RunHashSHA_512Benchmark))
	results = append(results, runHashBenchmark("BenchmarkLibraryNative_HashSHA_512_256", bench.RunHashSHA_512_256Benchmark))

	signCertificateNISTSECP521R1RSA4096Result, err := runSignBenchmark(
		"BenchmarkLibraryNative_SignCertificate_NIST_SECP521R1_RSA4096", bench.RunSignCertificateNISTSECP521R1RSA4096Benchmark)
	if err != nil {
		return BenchmarkResults{Results: results}, err
	}
	results = append(results, signCertificateNISTSECP521R1RSA4096Result)

	signCertificateNISTSECP521R1NISTSECP521R1Result, err := runSignBenchmark(
		"BenchmarkLibraryNative_SignCertificate_NIST_SECP521R1_NIST_SECP521R1", bench.RunSignCertificateNISTSECP521R1NISTSECP521R1Benchmark)
	if err != nil {
		return BenchmarkResults{Results: results}, err
	}
	results = append(results, signCertificateNISTSECP521R1NISTSECP521R1Result)

	return BenchmarkResults{Results: results}, nil
}

// runHashBenchmark executes a hash benchmark and returns the result
func runHashBenchmark(name string, benchmarkFunc func(*testing.B)) BenchmarkResult {
	b := &testing.B{N: 1000}
	start := time.Now()
	benchmarkFunc(b)
	duration := time.Since(start)
	avgTime := duration.Nanoseconds() / int64(b.N)
	return BenchmarkResult{Name: name, AvgTime: avgTime}
}

// runSignBenchmark executes a certificate signing benchmark and returns the result
func runSignBenchmark(name string, benchmarkFunc func(*testing.B) error) (BenchmarkResult, error) {
	b := &testing.B{N: 10}

	start := time.Now()
	err := benchmarkFunc(b)
	duration := time.Since(start)

	if err != nil {
		return BenchmarkResult{Name: name, AvgTime: 0}, err
	}

	avgTime := duration.Nanoseconds() / int64(b.N)

	return BenchmarkResult{Name: name, AvgTime: avgTime}, nil
}

type signClientInput struct {
	csr                   *x509.CertificateRequest
	caPrivateKey          any
	caCert                *x509.Certificate
	validNotBefore        *time.Time
	validNotAfter         *time.Time
	subject               *string
	CrlDistributionPoints []string
}

func newSignClientInput(req *protobuf.SignRequest) (signClientInput, error) {
	block, _ := pem.Decode([]byte(req.Csr))
	if block == nil {
		return signClientInput{}, fmt.Errorf("could not decode CSR as PEM file")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return signClientInput{}, fmt.Errorf("could not parse certificate request, err: %s", err)
	}

	caPrivateKey, err := c10y.ParsePrivateKeyFromPEM([]byte(req.CaPrivateKey))
	if err != nil {
		return signClientInput{}, fmt.Errorf("could not parse private key, err: %s", err)
	}

	cert, err := c10y.ParseX509Cert([]byte(req.CaCert))
	if err != nil {
		return signClientInput{}, fmt.Errorf("could not parse x.509 CA cert from request, err: %w", err)
	}

	input := signClientInput{
		csr:                   csr,
		caPrivateKey:          caPrivateKey,
		caCert:                cert,
		subject:               req.Subject,
		CrlDistributionPoints: req.CrlDistributionPoints,
	}

	if req.ValidNotBefore != nil {
		startValidity := time.Unix(int64(*req.ValidNotBefore), 0)
		input.validNotBefore = &startValidity
	}

	if req.ValidNotAfter != nil {
		endValidity := time.Unix(int64(*req.ValidNotAfter), 0)
		input.validNotAfter = &endValidity
	}

	return input, nil
}

// sign contains logic that signs CSR and returns signed certificate or non-nil error if any.
func (server *CryptoBrokerServer) sign(clientInput signClientInput, p profile.Profile) (certDER []byte, err error) {
	type signer interface {
		SignCertificate(c10y.SignProfileOpts, c10y.SignAPIOpts) ([]byte, error)
	}

	var s signer
	switch p.Settings.CryptoLibrary {
	case c10y.LibNative:
		s = server.cryptographicEngineNative
	default:
		return nil, fmt.Errorf("unknown '%s' library value, available values: %v",
			p.Settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
	}

	var subject string
	if clientInput.subject != nil {
		subject = *clientInput.subject
	}

	optsProfile := c10y.SignProfileOpts{
		SignatureAlgorithm: p.API.SignCertificate.SignatureAlgorithm,
		Validity: c10y.SignProfileValidity{ // default values
			NotBeforeOffset: p.API.SignCertificate.Validity.NotBeforeOffset,
			NotAfterOffset:  p.API.SignCertificate.Validity.NotAfterOffset,
		},
		KeyUsage:         p.API.SignCertificate.KeyUsage,
		ExtendedKeyUsage: p.API.SignCertificate.ExtendedKeyUsage,
		BasicConstraints: c10y.SignProfileBasicConstraints{
			IsCA:              p.API.SignCertificate.BasicConstraints.CA,
			PathLenConstraint: p.API.SignCertificate.BasicConstraints.PathLenConstraint,
		},
		SubjectKeyConstraints: p.API.SignCertificate.KeyConstraints.Subject,
	}

	optsAPI := c10y.SignAPIOpts{
		CACert:                clientInput.caCert,
		PrivateKey:            clientInput.caPrivateKey,
		CSR:                   clientInput.csr,
		Subject:               subject,
		CrlDistributionPoints: clientInput.CrlDistributionPoints,
		ValidNotBefore:        clientInput.validNotBefore,
		ValidNotAfter:         clientInput.validNotAfter,
	}
	clientCRTRaw, err := s.SignCertificate(optsProfile, optsAPI)
	if err != nil {
		return nil, fmt.Errorf("could not create certificate, err: %s", err)
	}

	return clientCRTRaw, nil
}

// hash hashes provided data according to profile rules
func (server *CryptoBrokerServer) hash(data []byte, p profile.Profile) (c10y.Hash, error) {

	// hasher defines abstraction over hashing library/engine.
	type hasher interface {
		HashSHA3_256(dataToHash []byte) (c10y.Hash, error)
		HashSHA3_384(dataToHash []byte) (c10y.Hash, error)
		HashSHA3_512(dataToHash []byte) (c10y.Hash, error)
		HashSHA_256(dataToHash []byte) (c10y.Hash, error)
		HashSHA_384(dataToHash []byte) (c10y.Hash, error)
		HashSHA_512(dataToHash []byte) (c10y.Hash, error)
		HashSHA_512_256(dataToHash []byte) (c10y.Hash, error)
		HashShake_128(size int, dataToHash []byte) (c10y.Hash, error)
		HashShake_256(size int, dataToHash []byte) (c10y.Hash, error)
	}

	var h hasher
	switch p.Settings.CryptoLibrary {
	case c10y.LibNative:
		h = server.cryptographicEngineNative
	default:
		return "", fmt.Errorf("unknown '%s' library value, available values: %v",
			p.Settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
	}

	var (
		hash c10y.Hash
		err  error
	)
	switch p.API.HashData.HashAlg {
	case c10y.SHA3_256:
		hash, err = h.HashSHA3_256(data)
	case c10y.SHA3_384:
		hash, err = h.HashSHA3_384(data)
	case c10y.SHA3_512:
		hash, err = h.HashSHA3_512(data)
	case c10y.SHA_256:
		hash, err = h.HashSHA_256(data)
	case c10y.SHA_384:
		hash, err = h.HashSHA_384(data)
	case c10y.SHA_512:
		hash, err = h.HashSHA_512(data)
	case c10y.SHA_512_256:
		hash, err = h.HashSHA_512_256(data)
	case c10y.SHAKE_128:
		hash, err = h.HashShake_128(16, data)
	case c10y.SHAKE_256:
		hash, err = h.HashShake_256(32, data)
	default:
		return "", fmt.Errorf("unknown '%s' algorithm value, available values: %v", p.API.HashData.HashAlg, c10y.HashDataAlgorithmsSupported)
	}

	if err != nil {
		return "", fmt.Errorf("could not hash provided bytes, err: %s", err)
	}

	return hash, nil
}

func (srv *CryptoBrokerServer) logDuration(ctx context.Context, methodName string, duration time.Duration) {
	slog.LogAttrs(ctx, slog.LevelDebug, "time measurement", slog.String("method", methodName), slog.Float64("duration", float64(duration.Nanoseconds())/1000.0))
}
