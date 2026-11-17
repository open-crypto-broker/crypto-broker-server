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
	gcm, err := newAESGCM(input.Key, cipher.NewGCM)
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
	gcm, err := newAESGCM(input.Key, cipher.NewGCMWithRandomNonce)
	if err != nil {
		return nil, err
	}

	if len(input.Nonce) != AESGCMNonceSize {
		return nil, fmt.Errorf("invalid AES-GCM nonce length: got %d, want %d", len(input.Nonce), AESGCMNonceSize)
	}
	if len(input.Tag) != AESGCMTagSize {
		return nil, fmt.Errorf("invalid AES-GCM tag length: got %d, want %d", len(input.Tag), AESGCMTagSize)
	}

	sealed := make([]byte, 0, len(input.Nonce)+len(input.Ciphertext)+len(input.Tag))
	sealed = append(sealed, input.Nonce...)
	sealed = append(sealed, input.Ciphertext...)
	sealed = append(sealed, input.Tag...)
	plaintext, err := gcm.Open(nil, nil, sealed, input.AAD)
	if err != nil {
		return nil, fmt.Errorf("could not decrypt AES-GCM ciphertext: %w", err)
	}

	return plaintext, nil
}

func newAESGCM(key []byte, newGCM func(cipher.Block) (cipher.AEAD, error)) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("could not create AES cipher: %w", err)
	}

	gcm, err := newGCM(block)
	if err != nil {
		return nil, fmt.Errorf("could not create AES-GCM cipher: %w", err)
	}

	return gcm, nil
}
