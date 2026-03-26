package procedure

import (
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

func loadDefaultProfiles(t *testing.T) {
	t.Helper()
	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("failed to load profiles: %v", err)
	}
}

func TestNewHash(t *testing.T) {
	p := NewHash(c10y.NewLibraryNative())
	if p == nil {
		t.Fatalf("expected non-nil")
	}
}

func TestHash_Execute(t *testing.T) {
	loadDefaultProfiles(t)

	p := NewHash(c10y.NewLibraryNative())
	resp, err := p.Execute(&protobuf.HashRequest{
		Profile: "Default",
		Input:   []byte("hello"),
	})
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if resp.HashAlgorithm != "sha3-512" {
		t.Fatalf("HashAlgorithm = %q, want %q", resp.HashAlgorithm, "sha3-512")
	}
	if len(resp.HashValue) != 128 { // sha3-512 is 64 bytes which is 128 hex chars
		t.Fatalf("HashValue length = %d, want 128", len(resp.HashValue))
	}
}
