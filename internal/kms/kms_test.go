package kms

import (
	"bytes"
	"strings"
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

	certificate      []byte
	certificateCalls int
}

func (c *testClient) GetKey(string) ([]byte, error) {
	c.calls++
	return c.key, nil
}

func (c *testClient) GetCertificate(string) ([]byte, error) {
	c.certificateCalls++
	return c.certificate, nil
}

func TestGetCertificate(t *testing.T) {
	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatal(err)
	}
	kmsClient := &testClient{certificate: []byte(strings.Repeat("certificate", 200))}
	client = kmsClient
	defer func() { client = nil }()
	const id = "certificate-id"
	certificates.Del(id)
	defer certificates.Del(id)
	keys.SetWithTTL(id, []byte("key"), 3, cacheTTL)
	keys.Wait()
	defer keys.Del(id)

	for range 2 {
		got, err := GetCertificate(id)
		if err != nil || !bytes.Equal(got, kmsClient.certificate) {
			t.Fatalf("GetCertificate() = %q, %v", got, err)
		}
	}
	if kmsClient.certificateCalls != 2 {
		t.Fatalf("client calls = %d, want 2 with caching disabled", kmsClient.certificateCalls)
	}
}
