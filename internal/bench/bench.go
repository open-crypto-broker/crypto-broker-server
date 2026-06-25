package bench

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/cache"
)

var bb = []byte(`ɥsɐɥ oʇ sɹǝʇɔɐɹɐɥɔ ʎɹɐɹʇᴉqɹɐ ǝɯoS
╔════╦══════╦══╗
╠═══╗║╠═══╦╗║╚╗║
║╔═╗╬╠═╦═╣║║╚╚║║
║╚╗╠╚╦║║╔═╣╚═╦╝║
║║║╝╔═╩╝║╠╝╣╔╝╔╣
║║╚═╣╔══╣╔═╝║╩╣║
║╚═╗╚╝╣║╝║╝═╩╔╩║
╚══╩══╩══╩═════╝`)

// RunHashSHA3_256Benchmark runs SHA3-256 hash benchmark
func RunHashSHA3_256Benchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.HashSHA3_256(bb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// RunHashSHA3_384Benchmark runs SHA3-384 hash benchmark
func RunHashSHA3_384Benchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.HashSHA3_384(bb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// RunHashSHA3_512Benchmark runs SHA3-512 hash benchmark
func RunHashSHA3_512Benchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.HashSHA3_512(bb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// RunHashSHA_256Benchmark runs SHA-256 hash benchmark
func RunHashSHA_256Benchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.HashSHA_256(bb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// RunHashSHA_384Benchmark runs SHA-384 hash benchmark
func RunHashSHA_384Benchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.HashSHA_384(bb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// RunHashSHA_512Benchmark runs SHA-512 hash benchmark
func RunHashSHA_512Benchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.HashSHA_512(bb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// RunHashSHA_512_256Benchmark runs SHA-512-256 hash benchmark
func RunHashSHA_512_256Benchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.HashSHA_512_256(bb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func RunHashShake_128Benchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.HashShake_128(32, bb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func RunHashShake_256Benchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.HashShake_256(32, bb)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// RunSignCertificate_CSR_SECP256R1_CA_RSA4096Benchmark runs certificate signing benchmark with NIST SECP521R1 + RSA 4096
func RunSignCertificate_CSR_SECP256R1_CA_RSA4096Benchmark(b *testing.B) error {
	notAfter, err := time.ParseDuration("8760h")
	if err != nil {
		return fmt.Errorf("could not parse duration: %w", err)
	}
	notBefore, err := time.ParseDuration("-1h")
	if err != nil {
		return fmt.Errorf("could not parse duration: %w", err)
	}

	caCert := []byte(`-----BEGIN CERTIFICATE-----
MIIC7DCCAk2gAwIBAgIUcy7fW7YwJWYg5YC1VIK+27ly8yYwCgYIKoZIzj0EAwQw
fjELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExGjAYBgNVBAoMEVRlc3Qt
T3JnYW5pemF0aW9uMR0wGwYDVQQLDBRUZXN0LU9yZ2FuaXphdGlvbi1DQTEiMCAG
A1UEAwwZVGVzdC1Pcmdhbml6YXRpb24tUm9vdC1DQTAeFw0yMzAxMDEwMTAxMDFa
Fw0zMzAxMDEwMTAxMDFaMH4xCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlh
MRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdh
bml6YXRpb24tQ0ExIjAgBgNVBAMMGVRlc3QtT3JnYW5pemF0aW9uLVJvb3QtQ0Ew
gZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAERlddbQZRNFQU21lb8jJUpjaS2UG2T
H3CFdFxmCwFo66LI7NF6KgAbculBz4++FbD7fcb0DtjzHrdJ+nj4OUaRYwD4jjv8
Z7gEiQ9GYM8hPsyvAXJbbMsiUo+lcsXNWa4a7ZmGYPEvJDRcZOaQELgCfS90jAPT
45yefLkIsgEWq45bKKNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8E
BAMCAYYwHQYDVR0OBBYEFCYxHAX0Wr6I9FIybAP6+p2xnPRyMB8GA1UdIwQYMBaA
FCYxHAX0Wr6I9FIybAP6+p2xnPRyMAoGCCqGSM49BAMEA4GMADCBiAJCAUgiYrF4
H6K3+1vqastXKjfhnv12eNOZuv+Awo0Q1RPqYHhZxF5x5gykw0clhgy6wfmqB+Km
dAHEn4LToNX0cl1oAkIB8Cv/F/7TJ0tJn0FpwtCBbNWzlUpz6TJj2wz5e4t80dzi
DKXl/HVVm/pvigXURZC+DzE90ztDcthH55yHm+sMhuE=
-----END CERTIFICATE-----`)
	caCertParsed, err := c10y.ParseX509Cert(caCert)
	if err != nil {
		return fmt.Errorf("could not parse CA cert: %w", err)
	}

	caPrivateKey := []byte(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAsaSvwGS0nfPXCBX7MY0nt2VYYkOrf1dygvH8oIxyDE9LyWJ7eDBx
T77tKXW71fO1Kq0WOcocNp89wg6PMsUFZxWgBwYFK4EEACOhgYkDgYYABAERlddb
QZRNFQU21lb8jJUpjaS2UG2TH3CFdFxmCwFo66LI7NF6KgAbculBz4++FbD7fcb0
DtjzHrdJ+nj4OUaRYwD4jjv8Z7gEiQ9GYM8hPsyvAXJbbMsiUo+lcsXNWa4a7ZmG
YPEvJDRcZOaQELgCfS90jAPT45yefLkIsgEWq45bKA==
-----END EC PRIVATE KEY-----`)
	caPrivateKeyParsed, err := c10y.ParsePrivateKeyFromPEM(caPrivateKey)
	if err != nil {
		return fmt.Errorf("could not parse CA private key: %w", err)
	}

	csrBytes := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBXzCCAQUCAQAwgaIxCzAJBgNVBAYTAkRFMREwDwYDVQQKDAhUZXN0IE9yZzEl
MCMGA1UECwwcVGVzdCBPcmcgQ2VydGlmaWNhdGUgU2VydmljZTEMMAoGA1UECwwD
RGV2MSEwHwYDVQQLDBhzdGFnaW5nLWNlcnRpZmljYXRlcy0xMDExDTALBgNVBAcM
BHRlc3QxGTAXBgNVBAMMEHRlc3QtY29tbW9uLW5hbWUwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATznFqF7j2Gbsvmv96hkY6WLYC4V0A/AHmxxaHYNyJlu5mJLHC0
b9jEuGIuifnfJjMUqPXbXVNkGp8lSIgyfJIJoAAwCgYIKoZIzj0EAwIDSAAwRQIh
ALeIB2/wKr3HtLRsmlYYoUAJPkw2vAXj9kiBUwhGw2hFAiBP9PTPCcOIZN50n9C0
NrPbJOOC/7QNdsuxmDFGEapyZg==
-----END CERTIFICATE REQUEST-----`)

	block, _ := pem.Decode(csrBytes)
	if block == nil {
		return fmt.Errorf("could not decode CSR as PEM file")
	}

	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("could not parse CSR: %w", err)
	}

	if err = csrParsed.CheckSignature(); err != nil {
		return fmt.Errorf("invalid certificate request signature: %w", err)
	}

	now := time.Now().UTC()
	kus := []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment}
	var finalKU x509.KeyUsage
	for _, ku := range kus {
		finalKU |= ku
	}

	input := c10y.SignCertificateInput{
		CSR:                csrParsed,
		CACert:             caCertParsed,
		PrivateKey:         caPrivateKeyParsed,
		Subject:            "C=DE, O=SAP SE, OU=SAP Cloud Platform Certificate Service Test Clients, OU=Dev, OU=cf-us10-staging-certificate-service, L=test, CN=test",
		NotBefore:          now.Add(notBefore),
		NotAfter:           now.Add(notAfter),
		KeyUsage:           finalKU,
		ExtendedKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:               false,
		PathLenConstraint:  -1,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}

	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	for b.Loop() {
		_, err := service.SignCertificate(input)
		if err != nil {
			return fmt.Errorf("could not sign certificate: %w", err)
		}
	}

	return nil
}

// RunSignCertificate_CSR_SECP521R1_CA_SECP521R1Benchmark runs certificate signing benchmark with NIST SECP521R1 + NIST SECP521R1
func RunSignCertificate_CSR_SECP521R1_CA_SECP521R1Benchmark(b *testing.B) error {
	notAfter, err := time.ParseDuration("8760h")
	if err != nil {
		return fmt.Errorf("could not parse duration: %w", err)
	}
	notBefore, err := time.ParseDuration("-1h")
	if err != nil {
		return fmt.Errorf("could not parse duration: %w", err)
	}

	caCert := []byte(`-----BEGIN CERTIFICATE-----
MIIC7DCCAk2gAwIBAgIUcy7fW7YwJWYg5YC1VIK+27ly8yYwCgYIKoZIzj0EAwQw
fjELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExGjAYBgNVBAoMEVRlc3Qt
T3JnYW5pemF0aW9uMR0wGwYDVQQLDBRUZXN0LU9yZ2FuaXphdGlvbi1DQTEiMCAG
A1UEAwwZVGVzdC1Pcmdhbml6YXRpb24tUm9vdC1DQTAeFw0yMzAxMDEwMTAxMDFa
Fw0zMzAxMDEwMTAxMDFaMH4xCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlh
MRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdh
bml6YXRpb24tQ0ExIjAgBgNVBAMMGVRlc3QtT3JnYW5pemF0aW9uLVJvb3QtQ0Ew
gZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAERlddbQZRNFQU21lb8jJUpjaS2UG2T
H3CFdFxmCwFo66LI7NF6KgAbculBz4++FbD7fcb0DtjzHrdJ+nj4OUaRYwD4jjv8
Z7gEiQ9GYM8hPsyvAXJbbMsiUo+lcsXNWa4a7ZmGYPEvJDRcZOaQELgCfS90jAPT
45yefLkIsgEWq45bKKNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8E
BAMCAYYwHQYDVR0OBBYEFCYxHAX0Wr6I9FIybAP6+p2xnPRyMB8GA1UdIwQYMBaA
FCYxHAX0Wr6I9FIybAP6+p2xnPRyMAoGCCqGSM49BAMEA4GMADCBiAJCAUgiYrF4
H6K3+1vqastXKjfhnv12eNOZuv+Awo0Q1RPqYHhZxF5x5gykw0clhgy6wfmqB+Km
dAHEn4LToNX0cl1oAkIB8Cv/F/7TJ0tJn0FpwtCBbNWzlUpz6TJj2wz5e4t80dzi
DKXl/HVVm/pvigXURZC+DzE90ztDcthH55yHm+sMhuE=
-----END CERTIFICATE-----`)
	caCertParsed, err := c10y.ParseX509Cert(caCert)
	if err != nil {
		return fmt.Errorf("could not parse CA cert: %w", err)
	}

	caPrivateKey := []byte(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAsaSvwGS0nfPXCBX7MY0nt2VYYkOrf1dygvH8oIxyDE9LyWJ7eDBx
T77tKXW71fO1Kq0WOcocNp89wg6PMsUFZxWgBwYFK4EEACOhgYkDgYYABAERlddb
QZRNFQU21lb8jJUpjaS2UG2TH3CFdFxmCwFo66LI7NF6KgAbculBz4++FbD7fcb0
DtjzHrdJ+nj4OUaRYwD4jjv8Z7gEiQ9GYM8hPsyvAXJbbMsiUo+lcsXNWa4a7ZmG
YPEvJDRcZOaQELgCfS90jAPT45yefLkIsgEWq45bKA==
-----END EC PRIVATE KEY-----`)
	caPrivateKeyParsed, err := c10y.ParsePrivateKeyFromPEM(caPrivateKey)
	if err != nil {
		return fmt.Errorf("could not parse CA private key: %w", err)
	}

	csrBytes := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIB5zCCAUgCAQAwgaIxCzAJBgNVBAYTAkRFMREwDwYDVQQKDAhUZXN0IE9yZzEl
MCMGA1UECwwcVGVzdCBPcmcgQ2VydGlmaWNhdGUgU2VydmljZTEMMAoGA1UECwwD
RGV2MSEwHwYDVQQLDBhzdGFnaW5nLWNlcnRpZmljYXRlcy0xMDExDTALBgNVBAcM
BHRlc3QxGTAXBgNVBAMMEHRlc3QtY29tbW9uLW5hbWUwgZswEAYHKoZIzj0CAQYF
K4EEACMDgYYABAG4J9e+RaevFWbipbgZTrdvVWgjc11uGM/XTODgHZf3W08OnL3i
c91AC6m+ul7iRUKV7Feyf7jGuvR9xiqghfMR+wCaI9S0SoOff/M7JCDIDAcB6TVl
wY9xlUF9z25XXnGHq6v18AQ+kKGPZQJ8eZYQWqMo48hzbmAV8M7dzEmIaGcltqAA
MAoGCCqGSM49BAMEA4GMADCBiAJCAbck1OvqQkWqeRcBRQRwXDs2EEtLWMZJCGsO
gab0fPVu7Kh8nMW9pdk5/P1z5UpgpcZkSNQDduCxSDr1pnsTXtI3AkIBBRaUW2og
xz4as/yt+3tVfrJa9Yaf3TjDqlTlncA8kJ3hhsRX5U/dwEJv2/ZMO7MWh12XUrQL
8rifvki0agFlvWQ=
-----END CERTIFICATE REQUEST-----`)

	block, _ := pem.Decode(csrBytes)
	if block == nil {
		return fmt.Errorf("could not decode CSR as PEM file")
	}

	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("could not parse CSR: %w", err)
	}

	if err = csrParsed.CheckSignature(); err != nil {
		return fmt.Errorf("invalid certificate request signature: %w", err)
	}

	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	now := time.Now().UTC()
	kus := []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment}
	var finalKU x509.KeyUsage
	for _, ku := range kus {
		finalKU |= ku
	}
	input := c10y.SignCertificateInput{
		CSR:                csrParsed,
		CACert:             caCertParsed,
		PrivateKey:         caPrivateKeyParsed,
		Subject:            "C=DE, O=SAP SE, OU=SAP Cloud Platform Certificate Service Test Clients, OU=Dev, OU=cf-us10-staging-certificate-service, L=test, CN=test",
		NotBefore:          now.Add(notBefore),
		NotAfter:           now.Add(notAfter),
		KeyUsage:           finalKU,
		ExtendedKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:               false,
		PathLenConstraint:  -1,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	for b.Loop() {
		_, err := service.SignCertificate(input)
		if err != nil {
			return fmt.Errorf("could not sign certificate: %w", err)
		}
	}

	return nil
}

func RunSignCertificateBenchmark(b *testing.B) error {
	notAfter, err := time.ParseDuration("8760h")
	if err != nil {
		b.Fatalf("could not parse duration, err: %s", err.Error())
	}
	notBefore, err := time.ParseDuration("-1h")
	if err != nil {
		b.Fatalf("could not parse duration, err: %s", err.Error())
	}

	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))

	// #nosec G703 -- trusted benchmark input
	caCert, err := os.ReadFile(os.Getenv(env.BENCHMARK_SIGN_CERTIFICATE_CA_CERT))
	if err != nil {
		b.Fatalf("could not read CA cert, err: %s", err.Error())
	}
	caCertParsed, err := c10y.ParseX509Cert(caCert)
	if err != nil {
		b.Fatalf("could not parse CA cert, err: %s", err.Error())
	}

	// #nosec G703 -- trusted benchmark input
	caPrivateKey, err := os.ReadFile(os.Getenv(env.BENCHMARK_SIGN_CERTIFICATE_PRIVATE_KEY))
	if err != nil {
		b.Fatalf("could not read CA private key, err: %s", err.Error())
	}
	caPrivateKeyParsed, err := c10y.ParsePrivateKeyFromPEM(caPrivateKey)
	if err != nil {
		b.Fatalf("could not parse CA private key, err: %s", err.Error())
	}

	// #nosec G703 -- trusted benchmark input
	csrBytes, err := os.ReadFile(os.Getenv(env.BENCHMARK_SIGN_CERTIFICATE_CSR))
	if err != nil {
		b.Fatalf("could not read CSR, err: %s", err.Error())
	}

	block, _ := pem.Decode([]byte(csrBytes))
	if block == nil {
		errString := "could not decode CSR as PEM file"
		b.Fatal(errString)

		return errors.New(errString)
	}

	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		b.Fatalf("could not parse CSR, err: %s", err.Error())
	}

	if err = csrParsed.CheckSignature(); err != nil {
		b.Fatalf("invalid certificate request signature, err: %s", err.Error())
	}

	now := time.Now().UTC()
	kus := []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment}
	var finalKU x509.KeyUsage
	for _, ku := range kus {
		finalKU |= ku
	}
	input := c10y.SignCertificateInput{
		CSR:                csrParsed,
		CACert:             caCertParsed,
		PrivateKey:         caPrivateKeyParsed,
		Subject:            "C=DE, O=SAP SE, OU=SAP Cloud Platform Certificate Service Test Clients, OU=Dev, OU=cf-us10-staging-certificate-service, L=test, CN=test",
		NotBefore:          now.Add(notBefore),
		NotAfter:           now.Add(notAfter),
		KeyUsage:           finalKU,
		ExtendedKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:               false,
		PathLenConstraint:  -1,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	for b.Loop() {
		_, err := service.SignCertificate(input)
		if err != nil {
			return fmt.Errorf("could not sign certificate: %w", err)
		}
	}

	return nil
}

// RunSignCertificate_CSR_SECP256R1_CA_SECP384R1Benchmark runs certificate signing benchmark with NIST SECP256R1 + NIST SECP384R1
func RunSignCertificate_CSR_SECP256R1_CA_SECP384R1Benchmark(b *testing.B) error {
	notAfter, err := time.ParseDuration("8760h")
	if err != nil {
		return fmt.Errorf("could not parse duration: %w", err)
	}
	notBefore, err := time.ParseDuration("-1h")
	if err != nil {
		return fmt.Errorf("could not parse duration: %w", err)
	}

	caCert := []byte(`-----BEGIN CERTIFICATE-----
MIICoTCCAiegAwIBAgIUWu/H/WSqYIKoo23VGupKI7txz+4wCgYIKoZIzj0EAwMw
fjELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExGjAYBgNVBAoMEVRlc3Qt
T3JnYW5pemF0aW9uMR0wGwYDVQQLDBRUZXN0LU9yZ2FuaXphdGlvbi1DQTEiMCAG
A1UEAwwZVGVzdC1Pcmdhbml6YXRpb24tUm9vdC1DQTAeFw0yMzAxMDEwMTAxMDFa
Fw0zMzAxMDEwMTAxMDFaMH4xCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlh
MRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdh
bml6YXRpb24tQ0ExIjAgBgNVBAMMGVRlc3QtT3JnYW5pemF0aW9uLVJvb3QtQ0Ew
djAQBgcqhkjOPQIBBgUrgQQAIgNiAATS59LZWhfYdy/WpKGVk/xNfyzHh8GYTx1r
tXtrzLrNz8vpvYxfayUUDyhVV+J/aoY4tSUAVj+x3yAM2RXZLtJJihW6UiTyXEXF
+azQXNRDVkit8IQi53+KZDR0ECdsRBKjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQEw
DgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBRv8eTneQUlEYFwISn4NaIzjm3wYTAf
BgNVHSMEGDAWgBRv8eTneQUlEYFwISn4NaIzjm3wYTAKBggqhkjOPQQDAwNoADBl
AjBdUV/yHjHq90/swrXl5DvfK2vQssqAAgfD6VvhpzKWlOwULmCIdjzd0DJ9BtF6
VqUCMQClUxcW/Pvl4+nj1WwGa9YdQY1qXAhRSUJBcRw6y7Ejr2NQ2zTN2KMM4FV2
f/KE4vY=
-----END CERTIFICATE-----`)
	caCertParsed, err := c10y.ParseX509Cert(caCert)
	if err != nil {
		return fmt.Errorf("could not parse CA cert: %w", err)
	}

	caPrivateKey := []byte(`-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDD+E65pqiUQUcKZCjrLOlpg+EMDUU+RIQmDIIilUzTim94OrhKKB/z4
OM25YzcvwQ6gBwYFK4EEACKhZANiAATS59LZWhfYdy/WpKGVk/xNfyzHh8GYTx1r
tXtrzLrNz8vpvYxfayUUDyhVV+J/aoY4tSUAVj+x3yAM2RXZLtJJihW6UiTyXEXF
+azQXNRDVkit8IQi53+KZDR0ECdsRBI=
-----END EC PRIVATE KEY-----`)
	caPrivateKeyParsed, err := c10y.ParsePrivateKeyFromPEM(caPrivateKey)
	if err != nil {
		return fmt.Errorf("could not parse CA private key: %w", err)
	}

	csrBytes := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIBXzCCAQUCAQAwgaIxCzAJBgNVBAYTAkRFMREwDwYDVQQKDAhUZXN0IE9yZzEl
MCMGA1UECwwcVGVzdCBPcmcgQ2VydGlmaWNhdGUgU2VydmljZTEMMAoGA1UECwwD
RGV2MSEwHwYDVQQLDBhzdGFnaW5nLWNlcnRpZmljYXRlcy0xMDExDTALBgNVBAcM
BHRlc3QxGTAXBgNVBAMMEHRlc3QtY29tbW9uLW5hbWUwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATznFqF7j2Gbsvmv96hkY6WLYC4V0A/AHmxxaHYNyJlu5mJLHC0
b9jEuGIuifnfJjMUqPXbXVNkGp8lSIgyfJIJoAAwCgYIKoZIzj0EAwIDSAAwRQIh
ALeIB2/wKr3HtLRsmlYYoUAJPkw2vAXj9kiBUwhGw2hFAiBP9PTPCcOIZN50n9C0
NrPbJOOC/7QNdsuxmDFGEapyZg==
-----END CERTIFICATE REQUEST-----`)

	block, _ := pem.Decode(csrBytes)
	if block == nil {
		return fmt.Errorf("could not decode CSR as PEM file")
	}

	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return fmt.Errorf("could not parse CSR: %w", err)
	}

	if err = csrParsed.CheckSignature(); err != nil {
		return fmt.Errorf("invalid certificate request signature: %w", err)
	}

	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	now := time.Now().UTC()
	kus := []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment}
	var finalKU x509.KeyUsage
	for _, ku := range kus {
		finalKU |= ku
	}
	input := c10y.SignCertificateInput{
		CSR:                csrParsed,
		CACert:             caCertParsed,
		PrivateKey:         caPrivateKeyParsed,
		Subject:            "C=DE, O=SAP SE, OU=SAP Cloud Platform Certificate Service Test Clients, OU=Dev, OU=cf-us10-staging-certificate-service, L=test, CN=test",
		NotBefore:          now.Add(notBefore),
		NotAfter:           now.Add(notAfter),
		KeyUsage:           finalKU,
		ExtendedKeyUsage:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		IsCA:               false,
		PathLenConstraint:  -1,
		SignatureAlgorithm: x509.ECDSAWithSHA512,
	}
	for b.Loop() {
		_, err := service.SignCertificate(input)
		if err != nil {
			return fmt.Errorf("could not sign certificate: %w", err)
		}
	}

	return nil
}
