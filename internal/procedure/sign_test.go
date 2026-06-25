package procedure

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

func TestNewSign(t *testing.T) {
	p := newTestSign()
	if p == nil {
		t.Fatalf("expected non-nil")
	}
}

func TestSign_Execute(t *testing.T) {
	loadDefaultProfiles(t)

	caCertPEM := `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

	// #nosec G101 -- trusted test input
	caPrivateKeyPEM := `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAsaSvwGS0nfPXCBX7MY0nt2VYYkOrf1dygvH8oIxyDE9LyWJ7eDBx
T77tKXW71fO1Kq0WOcocNp89wg6PMsUFZxWgBwYFK4EEACOhgYkDgYYABAERlddb
QZRNFQU21lb8jJUpjaS2UG2TH3CFdFxmCwFo66LI7NF6KgAbculBz4++FbD7fcb0
DtjzHrdJ+nj4OUaRYwD4jjv8Z7gEiQ9GYM8hPsyvAXJbbMsiUo+lcsXNWa4a7ZmG
YPEvJDRcZOaQELgCfS90jAPT45yefLkIsgEWq45bKA==
-----END EC PRIVATE KEY-----`

	csrPEM := `-----BEGIN CERTIFICATE REQUEST-----
MIIBXzCCAQUCAQAwgaIxCzAJBgNVBAYTAkRFMREwDwYDVQQKDAhUZXN0IE9yZzEl
MCMGA1UECwwcVGVzdCBPcmcgQ2VydGlmaWNhdGUgU2VydmljZTEMMAoGA1UECwwD
RGV2MSEwHwYDVQQLDBhzdGFnaW5nLWNlcnRpZmljYXRlcy0xMDExDTALBgNVBAcM
BHRlc3QxGTAXBgNVBAMMEHRlc3QtY29tbW9uLW5hbWUwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATznFqF7j2Gbsvmv96hkY6WLYC4V0A/AHmxxaHYNyJlu5mJLHC0
b9jEuGIuifnfJjMUqPXbXVNkGp8lSIgyfJIJoAAwCgYIKoZIzj0EAwIDSAAwRQIh
ALeIB2/wKr3HtLRsmlYYoUAJPkw2vAXj9kiBUwhGw2hFAiBP9PTPCcOIZN50n9C0
NrPbJOOC/7QNdsuxmDFGEapyZg==
-----END CERTIFICATE REQUEST-----`

	p := newTestSign()

	t.Run("DER output", func(t *testing.T) {
		resp, err := p.Execute(&protobuf.SignRequest{
			Profile:      "Default",
			Csr:          csrPEM,
			CaPrivateKey: caPrivateKeyPEM,
			CaCert:       caCertPEM,
			OutputFormat: protobuf.SignOutputFormat_DER,
		})
		if err != nil {
			t.Fatalf("Execute() error: %v", err)
		}
		derBytes := resp.GetDer()
		if len(derBytes) == 0 {
			t.Fatalf("expected non-empty SignedCertificateDer")
		}
		cert, err := x509.ParseCertificate(derBytes)
		if err != nil {
			t.Fatalf("failed to parse returned certificate DER: %v", err)
		}
		if len(cert.Raw) == 0 {
			t.Fatalf("expected parsed certificate with raw bytes")
		}
	})

	t.Run("PEM output", func(t *testing.T) {
		resp, err := p.Execute(&protobuf.SignRequest{
			Profile:      "Default",
			Csr:          csrPEM,
			CaPrivateKey: caPrivateKeyPEM,
			CaCert:       caCertPEM,
			OutputFormat: protobuf.SignOutputFormat_PEM,
		})
		if err != nil {
			t.Fatalf("Execute() error: %v", err)
		}
		pemStr := resp.GetPem()
		if !strings.HasPrefix(pemStr, "-----BEGIN CERTIFICATE-----") {
			t.Fatalf("expected PEM certificate, got: %s", pemStr)
		}
		block, _ := pem.Decode([]byte(pemStr))
		if block == nil {
			t.Fatalf("failed to PEM-decode SignedCertificatePem")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("failed to parse certificate from PEM: %v", err)
		}
		if len(cert.Raw) == 0 {
			t.Fatalf("expected parsed certificate with raw bytes")
		}
	})
}

func TestSign_parseRawSignRequest(t *testing.T) {
	csrPEM := `-----BEGIN CERTIFICATE REQUEST-----
MIIBXzCCAQUCAQAwgaIxCzAJBgNVBAYTAkRFMREwDwYDVQQKDAhUZXN0IE9yZzEl
MCMGA1UECwwcVGVzdCBPcmcgQ2VydGlmaWNhdGUgU2VydmljZTEMMAoGA1UECwwD
RGV2MSEwHwYDVQQLDBhzdGFnaW5nLWNlcnRpZmljYXRlcy0xMDExDTALBgNVBAcM
BHRlc3QxGTAXBgNVBAMMEHRlc3QtY29tbW9uLW5hbWUwWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATznFqF7j2Gbsvmv96hkY6WLYC4V0A/AHmxxaHYNyJlu5mJLHC0
b9jEuGIuifnfJjMUqPXbXVNkGp8lSIgyfJIJoAAwCgYIKoZIzj0EAwIDSAAwRQIh
ALeIB2/wKr3HtLRsmlYYoUAJPkw2vAXj9kiBUwhGw2hFAiBP9PTPCcOIZN50n9C0
NrPbJOOC/7QNdsuxmDFGEapyZg==
-----END CERTIFICATE REQUEST-----`
	caCertPEM := `-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----`

	// #nosec G101 -- trusted test input
	caPrivateKeyPEM := `-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAsaSvwGS0nfPXCBX7MY0nt2VYYkOrf1dygvH8oIxyDE9LyWJ7eDBx
T77tKXW71fO1Kq0WOcocNp89wg6PMsUFZxWgBwYFK4EEACOhgYkDgYYABAERlddb
QZRNFQU21lb8jJUpjaS2UG2TH3CFdFxmCwFo66LI7NF6KgAbculBz4++FbD7fcb0
DtjzHrdJ+nj4OUaRYwD4jjv8Z7gEiQ9GYM8hPsyvAXJbbMsiUo+lcsXNWa4a7ZmG
YPEvJDRcZOaQELgCfS90jAPT45yefLkIsgEWq45bKA==
-----END EC PRIVATE KEY-----`

	proc := newTestSign()
	input, err := proc.parseRawSignRequest(&protobuf.SignRequest{
		Csr:          csrPEM,
		CaCert:       caCertPEM,
		CaPrivateKey: caPrivateKeyPEM,
	})
	if err != nil {
		t.Fatalf("parseRawSignRequest() error: %v", err)
	}
	if input.csr == nil {
		t.Fatalf("expected parsed CSR")
	}
	if input.caCert == nil {
		t.Fatalf("expected parsed CA cert")
	}
	if input.caPrivateKey == nil {
		t.Fatalf("expected parsed CA private key")
	}

	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		t.Fatalf("expected CSR PEM to decode")
	}
}
