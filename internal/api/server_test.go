package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

const bufSize = 1024 * 1024

var lis *bufconn.Listener

func bufDialer(context.Context, string) (net.Conn, error) {
	return lis.Dial()
}

// TestCryptoBrokerServer_Hash_E2E tests the Hash method of the gRPC API.
func TestCryptoBrokerServer_Hash_E2E(t *testing.T) {
	// Mock dependencies
	libraryNative := c10y.NewLibraryNative()
	grpcConnector := NewCryptoBrokerServer(libraryNative)

	// Start a mock gRPC server
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	protobuf.RegisterCryptoBrokerServer(s, grpcConnector)
	go func() {
		if err := s.Serve(lis); err != nil {
			slog.Error("Server exited with error", slog.String("error", err.Error()))
		}
	}()
	defer s.Stop()

	// Create a gRPC client
	ctx := context.Background()
	conn, err := grpc.NewClient(fmt.Sprintf("passthrough://%s", lis.Addr().String()), grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := protobuf.NewCryptoBrokerClient(conn)
	if err = profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles, err: %s", err)
	}

	t.Run("Hash - Valid Request", func(t *testing.T) {
		req := &protobuf.HashRequest{
			Profile: "Default",
			Input:   []byte("test data"),
		}

		resp, err := client.Hash(ctx, req)
		if err != nil {
			t.Fatalf("Hash failed: %v", err)
		}

		expectedHash := "YmI5ZTJhMDIyMzdlNmY4YWRjYWVmOWZjMTRiODk4YjdjODBjZWRjMTE0MTEwNDcyY2RmOTI1MjMzNjIxYjcwNTk2M2M3NmU3YjExM2JlZDNjMjc4ZmYxMTY3MWE2ZDFjZGNiYTU0NWUwMDlmZjRjMGMwMjUzOTg5OTI0MTk5M2I="
		if base64.StdEncoding.EncodeToString([]byte(resp.HashValue)) != expectedHash {
			t.Errorf("Expected hash %s, got %s", expectedHash, base64.StdEncoding.EncodeToString([]byte(resp.HashValue)))
		}
	})
}

// TestCryptoBrokerServer_Sign_E2E tests the Sign method of the gRPC API.
func TestCryptoBrokerServer_Sign_E2E(t *testing.T) {
	// Mock dependencies
	libraryNative := c10y.NewLibraryNative()
	grpcConnector := NewCryptoBrokerServer(libraryNative)

	// Start a mock gRPC server
	lis = bufconn.Listen(bufSize)
	s := grpc.NewServer()
	protobuf.RegisterCryptoBrokerServer(s, grpcConnector)
	go func() {
		if err := s.Serve(lis); err != nil {
			slog.Error("Server exited with error", slog.String("error", err.Error()))
		}
	}()
	defer s.Stop()

	// Create a gRPC client
	ctx := context.Background()
	conn, err := grpc.NewClient(fmt.Sprintf("passthrough://%s", lis.Addr().String()), grpc.WithContextDialer(bufDialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("Failed to dial bufnet: %v", err)
	}
	defer conn.Close()
	client := protobuf.NewCryptoBrokerClient(conn)
	if err = profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles, err: %s", err)
	}

	t.Run("Sign - Valid Request", func(t *testing.T) {
		req := &protobuf.SignRequest{
			Profile: "Default",
			Csr: `-----BEGIN CERTIFICATE REQUEST-----
MIIBezCCAQACAQAwgYAxCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlhMRow
GAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdhbml6
YXRpb24tQ0ExJDAiBgNVBAMMG1Rlc3QtT3JnYW5pemF0aW9uLUVuZEVudGl0eTB2
MBAGByqGSM49AgEGBSuBBAAiA2IABIC1qmCZoLFy1CS7WuqCDspLsxjc++lTGY/s
HH2/fjGQOQP1knz1ZPfyYoEDnxePSXDiNVm/oCH6tUzQJCv8TjE436cV3mIJaxVv
3tu/EN022L4RByN5DoCFCQ24Ur0Z/6AAMAoGCCqGSM49BAMEA2kAMGYCMQDOWcqY
Uc5gaIJpQbckT4VCP4I23ZsJciONJt1F6qQCXKqu5P4dOz1Eq4iprNDWqnoCMQDT
xRlYLN6hgen+Bu3SnqCZqTuNXM/LDckE/i3LOAxFTXv9QkvGhGLEvEMIu0/RmXg=
-----END CERTIFICATE REQUEST-----
`,
			CaCert: `Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            39:24:7d:29:f0:ac:87:d4:31:bf:1c:a6:a9:0f:05:8f:5e:76:39:e0
        Signature Algorithm: ecdsa-with-SHA512
        Issuer: C=DE, ST=Bavaria, O=Test-Organization, OU=Test-Organization-CA, CN=Test-Organization-Root-CA
        Validity
            Not Before: Jan  1 01:01:01 2023 GMT
            Not After : Jan  1 01:01:01 2033 GMT
        Subject: C=DE, ST=Bavaria, O=Test-Organization, OU=Test-Organization-CA, CN=Test-Organization-Intermediate-CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (384 bit)
                pub:
                    04:61:5f:85:2f:91:42:93:79:84:5e:d1:4f:eb:fc:
                    1e:f4:00:b1:94:f0:bf:f0:47:6a:83:c7:87:b9:49:
                    b5:b2:25:f6:59:a5:3d:90:93:f4:14:14:dd:8c:ae:
                    de:b2:a1:d3:ab:3e:a5:b6:91:85:a4:4c:b3:21:1a:
                    b1:15:0f:0b:b2:c1:1f:a8:97:84:a0:d9:ca:20:3f:
                    ce:ae:a6:26:73:5a:fe:1a:d4:9f:b4:c9:21:54:c8:
                    10:ce:12:38:9c:99:fa
                ASN1 OID: secp384r1
                NIST CURVE: P-384
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:0
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                F7:2A:E2:41:32:04:04:71:8A:E6:23:54:F2:18:E6:F4:3F:6F:CF:DF
            X509v3 Authority Key Identifier: 
                BC:85:12:39:DD:25:DA:83:42:6D:26:30:11:E6:CE:0A:3F:CD:11:FE
    Signature Algorithm: ecdsa-with-SHA512
    Signature Value:
        30:65:02:30:59:48:e8:9d:03:95:74:f5:3a:7f:43:f8:c3:eb:
        cf:fe:5c:82:9c:c3:18:2e:ae:1f:92:ec:eb:85:8c:81:9d:0c:
        6c:1e:bb:07:11:f2:89:61:31:91:26:c3:c5:d6:28:34:02:31:
        00:b4:17:ea:3a:d7:f1:31:b1:3a:d8:dd:2e:d7:68:9f:ae:d8:
        f0:a9:80:10:7e:f8:39:b7:74:5c:b0:39:69:1e:dc:93:0c:fc:
        dd:a0:26:65:fb:5d:80:56:b0:f7:40:20:92
-----BEGIN CERTIFICATE-----
MIICqjCCAjCgAwIBAgIUOSR9KfCsh9QxvxymqQ8Fj152OeAwCgYIKoZIzj0EAwQw
fjELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExGjAYBgNVBAoMEVRlc3Qt
T3JnYW5pemF0aW9uMR0wGwYDVQQLDBRUZXN0LU9yZ2FuaXphdGlvbi1DQTEiMCAG
A1UEAwwZVGVzdC1Pcmdhbml6YXRpb24tUm9vdC1DQTAeFw0yMzAxMDEwMTAxMDFa
Fw0zMzAxMDEwMTAxMDFaMIGGMQswCQYDVQQGEwJERTEQMA4GA1UECAwHQmF2YXJp
YTEaMBgGA1UECgwRVGVzdC1Pcmdhbml6YXRpb24xHTAbBgNVBAsMFFRlc3QtT3Jn
YW5pemF0aW9uLUNBMSowKAYDVQQDDCFUZXN0LU9yZ2FuaXphdGlvbi1JbnRlcm1l
ZGlhdGUtQ0EwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAARhX4UvkUKTeYRe0U/r/B70
ALGU8L/wR2qDx4e5SbWyJfZZpT2Qk/QUFN2Mrt6yodOrPqW2kYWkTLMhGrEVDwuy
wR+ol4Sg2cogP86upiZzWv4a1J+0ySFUyBDOEjicmfqjZjBkMBIGA1UdEwEB/wQI
MAYBAf8CAQAwDgYDVR0PAQH/BAQDAgGGMB0GA1UdDgQWBBT3KuJBMgQEcYrmI1Ty
GOb0P2/P3zAfBgNVHSMEGDAWgBS8hRI53SXag0JtJjAR5s4KP80R/jAKBggqhkjO
PQQDBANoADBlAjBZSOidA5V09Tp/Q/jD68/+XIKcwxgurh+S7OuFjIGdDGweuwcR
8olhMZEmw8XWKDQCMQC0F+o61/ExsTrY3S7XaJ+u2PCpgBB++Dm3dFywOWke3JMM
/N2gJmX7XYBWsPdAIJI=
-----END CERTIFICATE-----
`,
			CaPrivateKey: `-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDAV/ttOZfVpsZfERB0K
ukqCAMHD0M3kJVIiqyqTCuRf52V4gO88h62YDQYeiOzNkvihZANiAARhX4UvkUKT
eYRe0U/r/B70ALGU8L/wR2qDx4e5SbWyJfZZpT2Qk/QUFN2Mrt6yodOrPqW2kYWk
TLMhGrEVDwuywR+ol4Sg2cogP86upiZzWv4a1J+0ySFUyBDOEjicmfo=
-----END PRIVATE KEY-----
`}

		subject := pkix.Name{
			Country:      []string{"DE"},
			Province:     []string{"BA"},
			Organization: []string{"SAP"},
			CommonName:   "MyCert",
		}.String()
		beforeOffset := "-1h"
		afterOffset := "24h"

		req.CrlDistributionPoints = []string{"http://www.example.com/crl/test.crl"}
		req.Subject = &subject
		req.ValidNotBeforeOffset = &beforeOffset
		req.ValidNotAfterOffset = &afterOffset
		req.Metadata = &protobuf.Metadata{
			Id:        "00001-2345689-abcdefg-1",
			CreatedAt: time.Now().String(),
		}

		resp, err := client.Sign(ctx, req)
		if err != nil {
			t.Fatalf("Sign failed: %s", err.Error())
		}

		if len(resp.SignedCertificate) == 0 {
			t.Errorf("Expected signed certificate, got empty response")
		}
	})

	t.Run("Sign - Invalid CSR", func(t *testing.T) {
		req := &protobuf.SignRequest{
			Profile: "Default",
			Csr:     "invalid CSR",
		}

		_, err := client.Sign(ctx, req)
		if err == nil {
			t.Fatalf("Expected error for invalid CSR, got nil")
		}
	})

	t.Run("Sign - Invalid CaCERT", func(t *testing.T) {

		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "Test CSR"},
		}
		csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

		req := &protobuf.SignRequest{
			Profile: "Default",
			Csr:     string(csrPEM),
			CaCert:  "not valid CaCERT",
		}

		_, err := client.Sign(ctx, req)
		if err == nil {
			t.Fatalf("Expected error for invalid CaCERT, got nil")
		}
	})

	t.Run("Sign - Insecure public Key", func(t *testing.T) {

		// Sign the CSR with a too short key length
		privKey, _ := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		csrTemplate := &x509.CertificateRequest{
			Subject: pkix.Name{CommonName: "Test CSR"},
		}
		csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})

		req := &protobuf.SignRequest{
			Profile: "Default",
			Csr:     string(csrPEM),
		}

		_, err := client.Sign(ctx, req)
		if err == nil || !strings.Contains(err.Error(), "expected public key to be at least") {
			t.Fatalf("Expected error for insecure public key, got nil or unexpected error: %s", err)
		}
	})
}
