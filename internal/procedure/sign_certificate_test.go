package procedure

import (
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	protobuf "github.com/open-crypto-broker/crypto-broker-server/internal/gen/cryptobroker/v1"
)

var caPrivateKeyPKCS8DER = []byte(
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

	caCertPtr := &caCertPEM

	t.Run("DER output", func(t *testing.T) {
		resp, err := p.Execute(&protobuf.SignCertificateRequest{
			Profile:      "Default",
			Csr:          csrPEM,
			KeySource:    certificateSignKeySource(caPrivateKeyPKCS8DER),
			CaCert:       caCertPtr,
			OutputFormat: protobuf.SignOutputFormat_SIGN_OUTPUT_FORMAT_DER,
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
		resp, err := p.Execute(&protobuf.SignCertificateRequest{
			Profile:      "Default",
			Csr:          csrPEM,
			KeySource:    certificateSignKeySource(caPrivateKeyPKCS8DER),
			CaCert:       caCertPtr,
			OutputFormat: protobuf.SignOutputFormat_SIGN_OUTPUT_FORMAT_PEM,
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

	t.Run("reject PEM signing key", func(t *testing.T) {
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caPrivateKeyPKCS8DER})
		_, err := p.Execute(&protobuf.SignCertificateRequest{
			Profile: "Default", Csr: csrPEM, KeySource: certificateSignKeySource(keyPEM),
			CaCert: caCertPtr, OutputFormat: protobuf.SignOutputFormat_SIGN_OUTPUT_FORMAT_DER,
		})
		if err == nil {
			t.Fatal("expected PEM signing key to be rejected")
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

	proc := newTestSign()

	caCertPtr := &caCertPEM

	input, err := proc.parseRawSignRequest(&protobuf.SignCertificateRequest{
		Csr:       csrPEM,
		CaCert:    caCertPtr,
		KeySource: certificateSignKeySource(caPrivateKeyPKCS8DER),
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

func certificateSignKeySource(key []byte) *protobuf.SignKeySource {
	return &protobuf.SignKeySource{Source: &protobuf.SignKeySource_Single{
		Single: &protobuf.KeySource{Source: &protobuf.KeySource_RawKey{RawKey: key}},
	}}
}
