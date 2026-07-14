package api

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/cache"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel"
	metricnoop "go.opentelemetry.io/otel/metric/noop"
)

func TestCryptoBrokerServer_MetricsEnabled_CollectSystemMetrics_NoPanic(t *testing.T) {
	otel.SetMeterProvider(metricnoop.NewMeterProvider())

	libraryNative := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	server := NewCryptoBrokerServer(
		libraryNative,
		procedure.NewHashData(libraryNative),
		procedure.NewSignCertificate(libraryNative, cache.MustNewRistretto[*x509.Certificate](cache.DefaultRistrettoConfig)),
		procedure.NewEncryptData(),
		procedure.NewDecryptData(),
		true,
	)

	server.collectSystemMetrics()
}

func TestCryptoBrokerServer_HashData_MetricsEnabled_ErrorOnInvalidProfile(t *testing.T) {
	otel.SetMeterProvider(metricnoop.NewMeterProvider())

	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles: %v", err)
	}

	libraryNative := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	server := NewCryptoBrokerServer(
		libraryNative,
		procedure.NewHashData(libraryNative),
		procedure.NewSignCertificate(libraryNative, cache.MustNewRistretto[*x509.Certificate](cache.DefaultRistrettoConfig)),
		procedure.NewEncryptData(),
		procedure.NewDecryptData(),
		true,
	)

	_, err := server.HashData(context.Background(), &protobuf.HashDataRequest{
		Profile: "ThisProfileDoesNotExist",
		Input:   []byte("test data"),
	})
	if err == nil {
		t.Fatalf("expected error for invalid profile, got nil")
	}
	if !strings.Contains(err.Error(), "something went wrong while hashing data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCryptoBrokerServer_HashData_MetricsEnabled_Success_RecordsMetricsBranch(t *testing.T) {
	otel.SetMeterProvider(metricnoop.NewMeterProvider())

	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles: %v", err)
	}

	libraryNative := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	server := NewCryptoBrokerServer(
		libraryNative,
		procedure.NewHashData(libraryNative),
		procedure.NewSignCertificate(libraryNative, cache.MustNewRistretto[*x509.Certificate](cache.DefaultRistrettoConfig)),
		procedure.NewEncryptData(),
		procedure.NewDecryptData(),
		true,
	)

	resp, err := server.HashData(context.Background(), &protobuf.HashDataRequest{
		Profile: "Default",
		Input:   []byte("test data"),
	})
	if err != nil {
		t.Fatalf("expected success, got err: %v", err)
	}
	if resp == nil || resp.GetHashAlgorithm() == "" || resp.GetHashValue() == nil {
		t.Fatalf("expected non-empty hash data response")
	}
}

func TestCryptoBrokerServer_SignCertificate_MetricsEnabled_ErrorOnInvalidCSR(t *testing.T) {
	otel.SetMeterProvider(metricnoop.NewMeterProvider())

	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles: %v", err)
	}

	libraryNative := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	server := NewCryptoBrokerServer(
		libraryNative,
		procedure.NewHashData(libraryNative),
		procedure.NewSignCertificate(libraryNative, cache.MustNewRistretto[*x509.Certificate](cache.DefaultRistrettoConfig)),
		procedure.NewEncryptData(),
		procedure.NewDecryptData(),
		true,
	)

	_, err := server.SignCertificate(context.Background(), &protobuf.SignCertificateRequest{
		Profile: "Default",
		Csr:     "invalid CSR",
	})
	if err == nil {
		t.Fatalf("expected error for invalid CSR, got nil")
	}
}

func TestCryptoBrokerServer_SignCertificate_MetricsEnabled_Success_RecordsMetricsBranch(t *testing.T) {
	otel.SetMeterProvider(metricnoop.NewMeterProvider())

	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles: %v", err)
	}

	caCertPEM, caKeyPEM, csrPEM := mustMakeTestCAAndCSR(t)

	libraryNative := c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
	server := NewCryptoBrokerServer(
		libraryNative,
		procedure.NewHashData(libraryNative),
		procedure.NewSignCertificate(libraryNative, cache.MustNewRistretto[*x509.Certificate](cache.DefaultRistrettoConfig)),
		procedure.NewEncryptData(),
		procedure.NewDecryptData(),
		true,
	)

	resp, err := server.SignCertificate(context.Background(), &protobuf.SignCertificateRequest{
		Profile:      "Default",
		Csr:          csrPEM,
		CaCert:       caCertPEM,
		CaPrivateKey: caKeyPEM,
	})
	if err != nil {
		t.Fatalf("expected success, got err: %v", err)
	}
	if resp == nil || resp.GetSignedCertificate() == nil {
		t.Fatalf("expected non-empty signed certificate")
	}
}

func mustMakeTestCAAndCSR(t *testing.T) (caCertPEM string, caKeyPEM string, csrPEM string) {
	t.Helper()

	caPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}

	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "Test CA",
			Organization: []string{"open-crypto-broker"},
		},
		NotBefore:             time.Now().UTC().Add(-1 * time.Hour),
		NotAfter:              time.Now().UTC().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("create ca cert: %v", err)
	}

	leafPriv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "leaf"},
	}, leafPriv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}

	caCertPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyDER, err := x509.MarshalPKCS8PrivateKey(caPriv)
	if err != nil {
		t.Fatalf("marshal ca pkcs8: %v", err)
	}
	caKeyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER})
	csrPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	return string(caCertPEMBytes), string(caKeyPEMBytes), string(csrPEMBytes)
}
