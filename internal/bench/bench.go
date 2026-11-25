package bench

import (
	"crypto/mldsa"
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

var (
	benchmarkEncryptionKey = []byte("0123456789abcdef0123456789abcdef")
	benchmarkEncryptionAAD = []byte("benchmark-aad")
)

var benchmarkCAPrivateKeyA = []byte(
	"\x30\x81\xee\x02\x01\x00\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02" +
		"\x01\x06\x05\x2b\x81\x04\x00\x23\x04\x81\xd6\x30\x81\xd3\x02\x01" +
		"\x01\x04\x42\x00\xb1\xa4\xaf\xc0\x64\xb4\x9d\xf3\xd7\x08\x15\xfb" +
		"\x31\x8d\x27\xb7\x65\x58\x62\x43\xab\x7f\x57\x72\x82\xf1\xfc\xa0" +
		"\x8c\x72\x0c\x4f\x4b\xc9\x62\x7b\x78\x30\x71\x4f\xbe\xed\x29\x75" +
		"\xbb\xd5\xf3\xb5\x2a\xad\x16\x39\xca\x1c\x36\x9f\x3d\xc2\x0e\x8f" +
		"\x32\xc5\x05\x67\x15\xa1\x81\x89\x03\x81\x86\x00\x04\x01\x11\x95" +
		"\xd7\x5b\x41\x94\x4d\x15\x05\x36\xd6\x56\xfc\x8c\x95\x29\x8d\xa4" +
		"\xb6\x50\x6d\x93\x1f\x70\x85\x74\x5c\x66\x0b\x01\x68\xeb\xa2\xc8" +
		"\xec\xd1\x7a\x2a\x00\x1b\x72\xe9\x41\xcf\x8f\xbe\x15\xb0\xfb\x7d" +
		"\xc6\xf4\x0e\xd8\xf3\x1e\xb7\x49\xfa\x78\xf8\x39\x46\x91\x63\x00" +
		"\xf8\x8e\x3b\xfc\x67\xb8\x04\x89\x0f\x46\x60\xcf\x21\x3e\xcc\xaf" +
		"\x01\x72\x5b\x6c\xcb\x22\x52\x8f\xa5\x72\xc5\xcd\x59\xae\x1a\xed" +
		"\x99\x86\x60\xf1\x2f\x24\x34\x5c\x64\xe6\x90\x10\xb8\x02\x7d\x2f" +
		"\x74\x8c\x03\xd3\xe3\x9c\x9e\x7c\xb9\x08\xb2\x01\x16\xab\x8e\x5b" +
		"\x28",
)

var benchmarkCAPrivateKeyB = []byte(
	"\x30\x81\xb6\x02\x01\x00\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02" +
		"\x01\x06\x05\x2b\x81\x04\x00\x22\x04\x81\x9e\x30\x81\x9b\x02\x01" +
		"\x01\x04\x30\xfe\x13\xae\x69\xaa\x25\x10\x51\xc2\x99\x0a\x3a\xcb" +
		"\x3a\x5a\x60\xf8\x43\x03\x51\x4f\x91\x21\x09\x83\x20\x88\xa5\x53" +
		"\x34\xe2\x9b\xde\x0e\xae\x12\x8a\x07\xfc\xf8\x38\xcd\xb9\x63\x37" +
		"\x2f\xc1\x0e\xa1\x64\x03\x62\x00\x04\xd2\xe7\xd2\xd9\x5a\x17\xd8" +
		"\x77\x2f\xd6\xa4\xa1\x95\x93\xfc\x4d\x7f\x2c\xc7\x87\xc1\x98\x4f" +
		"\x1d\x6b\xb5\x7b\x6b\xcc\xba\xcd\xcf\xcb\xe9\xbd\x8c\x5f\x6b\x25" +
		"\x14\x0f\x28\x55\x57\xe2\x7f\x6a\x86\x38\xb5\x25\x00\x56\x3f\xb1" +
		"\xdf\x20\x0c\xd9\x15\xd9\x2e\xd2\x49\x8a\x15\xba\x52\x24\xf2\x5c" +
		"\x45\xc5\xf9\xac\xd0\x5c\xd4\x43\x56\x48\xad\xf0\x84\x22\xe7\x7f" +
		"\x8a\x64\x34\x74\x10\x27\x6c\x44\x12",
)

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

// RunEncryptDataBenchmark runs an AES-256-GCM encryption benchmark.
func RunEncryptDataBenchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	nonce := make([]byte, c10y.AESGCMNonceSize)

	for b.Loop() {
		nonce[len(nonce)-1]++
		_, err := service.EncryptData(c10y.EncryptDataInput{
			Key:       benchmarkEncryptionKey,
			Nonce:     nonce,
			Plaintext: bb,
			AAD:       benchmarkEncryptionAAD,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// RunDecryptDataBenchmark runs an AES-256-GCM decryption benchmark.
func RunDecryptDataBenchmark(b *testing.B) {
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	nonce := make([]byte, c10y.AESGCMNonceSize)
	encrypted, err := service.EncryptData(c10y.EncryptDataInput{
		Key:       benchmarkEncryptionKey,
		Nonce:     nonce,
		Plaintext: bb,
		AAD:       benchmarkEncryptionAAD,
	})
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		_, err := service.DecryptData(c10y.DecryptDataInput{
			Key:        benchmarkEncryptionKey,
			Nonce:      nonce,
			Ciphertext: encrypted.Ciphertext,
			AAD:        benchmarkEncryptionAAD,
			Tag:        encrypted.Tag,
		})
		if err != nil {
			b.Fatal(err)
		}
	}
}

// RunSignMLDSA65DataBenchmark measures FIPS 204 ML-DSA-65 signing without key generation overhead.
func RunSignMLDSA65DataBenchmark(b *testing.B) {
	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		b.Fatal(err)
	}
	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	input := c10y.MLDSASignDataInput{PrivateKey: privateKey, Data: bb}

	b.ResetTimer()
	for b.Loop() {
		if _, err := service.SignMLDSAData(input); err != nil {
			b.Fatal(err)
		}
	}
}

// RunVerifyMLDSA65DataBenchmark measures FIPS 204 ML-DSA-65 verification without key generation or signing overhead.
func RunVerifyMLDSA65DataBenchmark(b *testing.B) {
	privateKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		b.Fatal(err)
	}

	service := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	signature, err := service.SignMLDSAData(c10y.MLDSASignDataInput{PrivateKey: privateKey, Data: bb})
	if err != nil {
		b.Fatal(err)
	}

	input := c10y.MLDSAVerifyDataInput{PublicKey: privateKey.PublicKey(), Data: bb, Signature: signature}
	b.ResetTimer()
	for b.Loop() {
		valid, err := service.VerifyMLDSAData(input)
		if err != nil {
			b.Fatal(err)
		}

		if !valid {
			b.Fatal("ML-DSA-65 signature verification failed")
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

	caPrivateKey := benchmarkCAPrivateKeyA
	caPrivateKeyParsed, err := c10y.ParsePrivateKeyFromPKCS8DER(caPrivateKey)
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

	caPrivateKey := benchmarkCAPrivateKeyA
	caPrivateKeyParsed, err := c10y.ParsePrivateKeyFromPKCS8DER(caPrivateKey)
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
	caPrivateKeyParsed, err := c10y.ParsePrivateKeyFromPKCS8DER(caPrivateKey)
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

	caPrivateKey := benchmarkCAPrivateKeyB
	caPrivateKeyParsed, err := c10y.ParsePrivateKeyFromPKCS8DER(caPrivateKey)
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
