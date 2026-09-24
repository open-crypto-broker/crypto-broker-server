package kms

import (
	"bytes"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
)

func TestGetKey(t *testing.T) {
	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("LoadProfiles() error: %v", err)
	}

	kmsClient := &testClient{key: []byte("test-key")}

	mux.Lock()
	client = kmsClient
	mux.Unlock()

	first, err := GetKey("test-key-id")
	if err != nil {
		t.Fatalf("first GetKey() error: %v", err)
	}

	second, err := GetKey("test-key-id")
	if err != nil {
		t.Fatalf("second GetKey() error: %v", err)
	}

	if !bytes.Equal(first, kmsClient.key) || !bytes.Equal(second, kmsClient.key) {
		t.Fatalf("GetKey() = %q, %q, want %q", first, second, kmsClient.key)
	}

	if kmsClient.calls != 2 {
		t.Errorf("KMS client calls = %d, want 2", kmsClient.calls)
	}
}

type testClient struct {
	key   []byte
	calls int
}

func (c *testClient) GetKey(string) ([]byte, error) {
	c.calls++
	return c.key, nil
}
