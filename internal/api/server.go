package api

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
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

	input := signClientInput{
		csr:                   req.Csr,
		caPrivateKey:          req.CaPrivateKey,
		caCert:                req.CaCert,
		validNotBeforeOffset:  req.ValidNotBeforeOffset,
		validNotAfterOffset:   req.ValidNotAfterOffset,
		subject:               req.Subject,
		CrlDistributionPoints: req.CrlDistributionPoints,
	}
	clientCRTRaw, err := server.sign(input, reqProfile)
	if err != nil {
		slog.Debug(err.Error())

		return nil, fmt.Errorf("error while signing data: %s", err.Error())
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
	csr                   string
	caPrivateKey          string
	caCert                string
	validNotBeforeOffset  *string
	validNotAfterOffset   *string
	subject               *string
	CrlDistributionPoints []string
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

	block, _ := pem.Decode([]byte(clientInput.csr))
	if block == nil {
		return nil, fmt.Errorf("could not decode CSR as PEM file")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("could not parse certificate request, err: %s", err)
	}

	if err = csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid certificate request signature, err: %s", err)
	}

	// Check whether the public key in CSR is secure enough according to profile
	if err = c10y.ValidatePublicKey(csr.PublicKey, p.API.SignCertificate.KeyConstraints.Subject); err != nil {
		if errors.Is(err, c10y.ErrMissingKeyConstraints) {
			return nil, fmt.Errorf("profile does not contain key constraints for algorithm used in the CSR's public key, err: %w", err)
		}

		return nil, fmt.Errorf("invalid public key, err: %w", err)
	}

	caPrivateKey, err := c10y.ParsePrivateKeyFromPEM([]byte(clientInput.caPrivateKey))
	if err != nil {
		return nil, fmt.Errorf("could not parse private key, err: %s", err)
	}

	// Check whether the private key from the CA is secure enough according to profile
	if err = c10y.ValidatePrivateKey(caPrivateKey, p.API.SignCertificate.KeyConstraints.Issuer); err != nil {
		if errors.Is(err, c10y.ErrMissingKeyConstraints) {
			return nil, fmt.Errorf("profile does not contain key constraints for algorithm used in the CA's private key, err: %w", err)
		}

		return nil, err
	}

	cert, err := c10y.ParseX509Cert([]byte(clientInput.caCert))
	if err != nil {
		return nil, fmt.Errorf("could not parse x.509 CA cert from request, err: %w", err)
	}

	// Parse the custom durations
	var notBeforeOffset, notAfterOffset time.Duration
	if clientInput.validNotBeforeOffset != nil {
		notBeforeOffset, err = time.ParseDuration(*clientInput.validNotBeforeOffset)
		if err != nil {
			return nil, fmt.Errorf("error while parsing the User's defined notBeforeOffset %w", err)
		}
		if notBeforeOffset-p.API.SignCertificate.Validity.NotBeforeOffset < 0 {
			return nil, fmt.Errorf("error: user's beforeOffset %s is earlier than the allowed by the profile %s", notBeforeOffset.String(), p.API.SignCertificate.Validity.NotBeforeOffset.String())
		}
	} else {
		notBeforeOffset = p.API.SignCertificate.Validity.NotBeforeOffset
	}
	if clientInput.validNotAfterOffset != nil {
		notAfterOffset, err = time.ParseDuration(*clientInput.validNotAfterOffset)
		if err != nil {
			return nil, fmt.Errorf("error while parsing the User's defined notAfterOffset %w", err)
		}
		if notAfterOffset-p.API.SignCertificate.Validity.NotAfterOffset > 0 {
			return nil, fmt.Errorf("error: user's afterOffset %s is later than the allowed by the profile %s", notAfterOffset.String(), p.API.SignCertificate.Validity.NotAfterOffset.String())
		}
	} else {
		notAfterOffset = p.API.SignCertificate.Validity.NotAfterOffset
	}

	var subject string
	if clientInput.subject != nil {
		subject = *clientInput.subject
	}

	optsProfile := c10y.SignProfileOpts{
		SignatureAlgorithm: p.API.SignCertificate.SignatureAlgorithm,
		Validity: c10y.SignProfileValidity{
			NotBefore: notBeforeOffset,
			NotAfter:  notAfterOffset,
		},
		KeyUsage:         p.API.SignCertificate.KeyUsage,
		ExtendedKeyUsage: p.API.SignCertificate.ExtendedKeyUsage,
		BasicConstraints: c10y.SignProfileBasicConstraints{
			IsCA:              p.API.SignCertificate.BasicConstraints.CA,
			PathLenConstraint: p.API.SignCertificate.BasicConstraints.PathLenConstraint,
		},
	}
	optsAPI := c10y.SignAPIOpts{
		CACert:                cert,
		PrivateKey:            caPrivateKey,
		CSR:                   csr,
		Subject:               subject,
		CrlDistributionPoints: clientInput.CrlDistributionPoints,
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
