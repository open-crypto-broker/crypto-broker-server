package procedure

import (
	"bytes"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

func TestEncryptDecryptData_Execute(t *testing.T) {
	loadDefaultProfiles(t)

	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x24}, c10y.AESGCMNonceSize)
	aad := []byte("context")
	plaintext := []byte("confidential payload")
	metadata := &protobuf.Metadata{Id: "request-1"}
	keySource := &protobuf.KeySource{Source: &protobuf.KeySource_RawKey{RawKey: key}}

	encrypt := NewEncryptData(newTestLibraryNative())
	encrypted, err := encrypt.Execute(&protobuf.EncryptDataRequest{
		Profile:   "Default",
		KeySource: keySource,
		Plaintext: plaintext,
		EncryptMetadata: &protobuf.EncryptMetadata{
			Nonce: nonce,
			Aad:   aad,
		},
		Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("EncryptData.Execute() error: %v", err)
	}
	if bytes.Equal(encrypted.GetCiphertext(), plaintext) {
		t.Fatal("ciphertext must differ from plaintext")
	}
	if !bytes.Equal(encrypted.GetCipherMetadata().GetNonce(), nonce) ||
		!bytes.Equal(encrypted.GetCipherMetadata().GetAad(), aad) ||
		len(encrypted.GetCipherMetadata().GetTag()) != c10y.AESGCMTagSize {
		t.Fatalf("unexpected cipher metadata: %#v", encrypted.GetCipherMetadata())
	}
	if encrypted.GetMetadata() != metadata {
		t.Fatal("response metadata was not propagated")
	}

	decrypt := NewDecryptData(newTestLibraryNative())
	decrypted, err := decrypt.Execute(&protobuf.DecryptDataRequest{
		Profile:    "Default",
		KeySource:  keySource,
		Ciphertext: encrypted.GetCiphertext(),
		DecryptMetadata: &protobuf.DecryptMetadata{
			Nonce: encrypted.GetCipherMetadata().GetNonce(),
			Aad:   encrypted.GetCipherMetadata().GetAad(),
			Tag:   encrypted.GetCipherMetadata().GetTag(),
		},
		Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("DecryptData.Execute() error: %v", err)
	}
	if !bytes.Equal(decrypted.GetPlaintext(), plaintext) {
		t.Fatalf("Plaintext = %q, want %q", decrypted.GetPlaintext(), plaintext)
	}
	if decrypted.GetMetadata() != metadata {
		t.Fatal("response metadata was not propagated")
	}
}

func TestEncryptData_ExecuteRejectsUnsupportedKeySource(t *testing.T) {
	loadDefaultProfiles(t)

	_, err := NewEncryptData(newTestLibraryNative()).Execute(&protobuf.EncryptDataRequest{
		Profile: "Default",
		KeySource: &protobuf.KeySource{Source: &protobuf.KeySource_KeyId{
			KeyId: "managed-key",
		}},
		EncryptMetadata: &protobuf.EncryptMetadata{Nonce: make([]byte, c10y.AESGCMNonceSize)},
	})
	if err == nil {
		t.Fatal("EncryptData.Execute() error = nil, want keyId rejection")
	}
}

func TestDecryptData_ExecuteRejectsTamperedTag(t *testing.T) {
	loadDefaultProfiles(t)

	key := bytes.Repeat([]byte{0x42}, 32)
	nonce := bytes.Repeat([]byte{0x24}, c10y.AESGCMNonceSize)
	encrypted, err := NewEncryptData(newTestLibraryNative()).Execute(&protobuf.EncryptDataRequest{
		Profile:         "Default",
		KeySource:       &protobuf.KeySource{Source: &protobuf.KeySource_RawKey{RawKey: key}},
		Plaintext:       []byte("confidential payload"),
		EncryptMetadata: &protobuf.EncryptMetadata{Nonce: nonce},
	})
	if err != nil {
		t.Fatalf("EncryptData.Execute() error: %v", err)
	}
	tag := append([]byte(nil), encrypted.GetCipherMetadata().GetTag()...)
	tag[0] ^= 1

	_, err = NewDecryptData(newTestLibraryNative()).Execute(&protobuf.DecryptDataRequest{
		Profile:    "Default",
		KeySource:  &protobuf.KeySource{Source: &protobuf.KeySource_RawKey{RawKey: key}},
		Ciphertext: encrypted.GetCiphertext(),
		DecryptMetadata: &protobuf.DecryptMetadata{
			Nonce: nonce,
			Tag:   tag,
		},
	})
	if err == nil {
		t.Fatal("DecryptData.Execute() error = nil, want authentication failure")
	}
}
