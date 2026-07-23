package c10y

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const (
	AESGCMNonceSize = 12
	AESGCMTagSize   = 16
)

type EncryptDataInput struct {
	Key       []byte
	Nonce     []byte
	Plaintext []byte
	AAD       []byte
}

type EncryptDataOutput struct {
	Ciphertext []byte
	Tag        []byte
}

type DecryptDataInput struct {
	Key        []byte
	Nonce      []byte
	Ciphertext []byte
	AAD        []byte
	Tag        []byte
}

// EncryptData encrypts plaintext using AES-GCM and returns a detached authentication tag.
func (service *LibraryNative) EncryptData(input EncryptDataInput) (EncryptDataOutput, error) {
	gcm, err := newAESGCM(input.Key)
	if err != nil {
		return EncryptDataOutput{}, err
	}

	if len(input.Nonce) != gcm.NonceSize() {
		return EncryptDataOutput{}, fmt.Errorf("invalid AES-GCM nonce length: got %d, want %d", len(input.Nonce), gcm.NonceSize())
	}

	sealed := gcm.Seal(nil, input.Nonce, input.Plaintext, input.AAD)
	ciphertextLength := len(sealed) - gcm.Overhead()
	return EncryptDataOutput{
		Ciphertext: sealed[:ciphertextLength],
		Tag:        sealed[ciphertextLength:],
	}, nil
}

// DecryptData verifies and decrypts AES-GCM ciphertext with a detached authentication tag.
func (service *LibraryNative) DecryptData(input DecryptDataInput) ([]byte, error) {
	gcm, err := newAESGCM(input.Key)
	if err != nil {
		return nil, err
	}

	if len(input.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("invalid AES-GCM nonce length: got %d, want %d", len(input.Nonce), gcm.NonceSize())
	}
	if len(input.Tag) != gcm.Overhead() {
		return nil, fmt.Errorf("invalid AES-GCM tag length: got %d, want %d", len(input.Tag), gcm.Overhead())
	}

	sealed := make([]byte, 0, len(input.Ciphertext)+len(input.Tag))
	sealed = append(sealed, input.Ciphertext...)
	sealed = append(sealed, input.Tag...)
	plaintext, err := gcm.Open(nil, input.Nonce, sealed, input.AAD)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt AES-GCM ciphertext: %w", err)
	}

	return plaintext, nil
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create AES-GCM cipher: %w", err)
	}

	return gcm, nil
}
