package procedure

import (
	"crypto/x509"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/cache"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

func loadDefaultProfiles(t *testing.T) {
	t.Helper()
	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("failed to load profiles: %v", err)
	}
}

// newTestLibraryNative builds a LibraryNative backed by a default in-memory cache.
func newTestLibraryNative() *c10y.LibraryNative {
	return c10y.NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
}

// newTestSign builds a Sign procedure backed by default in-memory caches.
func newTestSign() *Sign {
	return NewSign(newTestLibraryNative(), cache.MustNewRistretto[*x509.Certificate](cache.DefaultRistrettoConfig))
}

func TestNewHash(t *testing.T) {
	p := NewHash(newTestLibraryNative())
	if p == nil {
		t.Fatalf("expected non-nil")
	}
}

func TestHash_Execute(t *testing.T) {
	loadDefaultProfiles(t)

	p := NewHash(newTestLibraryNative())
	resp, err := p.Execute(&protobuf.HashRequest{
		Profile: "Default",
		Input:   []byte("hello"),
	})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if resp.GetHashAlgorithm() != "sha3-512" {
		t.Fatalf("HashAlgorithm = %q, want %q", resp.GetHashAlgorithm(), "sha3-512")
	}
	if len(resp.GetHashValueHex()) != 128 { // sha3-512 is 64 bytes which is 128 hex chars
		t.Fatalf("HashValueHex length = %d, want 128", len(resp.GetHashValueHex()))
	}
}
