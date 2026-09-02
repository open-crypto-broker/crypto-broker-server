package kms

import (
	"bytes"
	"testing"
)

func TestGetKeyUsesCachedKey(t *testing.T) {
	kmsClient := &testClient{key: []byte("test-key")}

	mux.Lock()
	clients = make(map[string]Client)
	clients["test-profile"] = kmsClient
	mux.Unlock()

	first, err := GetKey("test-profile", "test-key-id")
	if err != nil {
		t.Fatalf("first GetKey() error: %v", err)
	}

	second, err := GetKey("test-profile", "test-key-id")
	if err != nil {
		t.Fatalf("second GetKey() error: %v", err)
	}

	if !bytes.Equal(first, kmsClient.key) || !bytes.Equal(second, kmsClient.key) {
		t.Fatalf("GetKey() = %q, %q, want %q", first, second, kmsClient.key)
	}
	
	if kmsClient.calls != 1 {
		t.Errorf("KMS client calls = %d, want 1", kmsClient.calls)
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
