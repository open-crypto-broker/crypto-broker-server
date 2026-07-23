package c10y

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestLibraryNative_EncryptData_KnownAnswerTests(t *testing.T) {
	tests := []struct {
		name       string
		key        string
		nonce      string
		aad        string
		ciphertext string
		tag        string
	}{
		{
			name:       "AES-128-GCM",
			key:        "1619159426d9ac45243d3da9eed51899",
			nonce:      "08edd4dd6bfd0d69275ef2d0",
			aad:        "1af8fbdc64693a719f26baa04f0ce8be",
			ciphertext: "b613ddebb18ad870a69185f1b1015662e3a9a08a",
			tag:        "0e8a5ed855c3f96c2c35db398b714ffa",
		},
		{
			name:       "AES-192-GCM",
			key:        "83a4dc40d7b3f75dcd0f9a7640ac4959ebe54d2b23ac036e",
			nonce:      "a0167ac07433cb6b0cb8e93a",
			aad:        "3ce44a50188bb27a6369b4f23fae8ba7",
			ciphertext: "a99cd0f1483805de0bf4ddd060a4e80709e992dc",
			tag:        "c3869e8390dd2e9690be966406b5e94f",
		},
		{
			name:       "AES-256-GCM",
			key:        "67e1befda6538f162a308bb37b922441bed6e27039a26a48ad8e11c568c4cda0",
			nonce:      "a83f89b37c90f937b8df5011",
			aad:        "36e02c2a81c60eca849739d52dea95f7",
			ciphertext: "71416b876fb0d65c484ec20106af15a36454743b",
			tag:        "a77b42e960d89683140cae283a87466e",
		},
	}

	service := newTestLibraryNative()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := decodeHex(t, tt.key)
			nonce := decodeHex(t, tt.nonce)
			aad := decodeHex(t, tt.aad)
			wantCiphertext := decodeHex(t, tt.ciphertext)
			wantTag := decodeHex(t, tt.tag)

			result, err := service.EncryptData(EncryptDataInput{
				Key:       key,
				Nonce:     nonce,
				Plaintext: []byte("Welcome CryptoBroker"),
				AAD:       aad,
			})
			if err != nil {
				t.Fatalf("EncryptData() error: %v", err)
			}
			if !bytes.Equal(result.Ciphertext, wantCiphertext) {
				t.Fatalf("Ciphertext = %x, want %x", result.Ciphertext, wantCiphertext)
			}
			if !bytes.Equal(result.Tag, wantTag) {
				t.Fatalf("Tag = %x, want %x", result.Tag, wantTag)
			}

			plaintext, err := service.DecryptData(DecryptDataInput{
				Key:        key,
				Nonce:      nonce,
				Ciphertext: wantCiphertext,
				AAD:        aad,
				Tag:        wantTag,
			})
			if err != nil {
				t.Fatalf("DecryptData() error: %v", err)
			}
			if !bytes.Equal(plaintext, []byte("Welcome CryptoBroker")) {
				t.Fatalf("Plaintext = %q, want %q", plaintext, "Welcome CryptoBroker")
			}
		})
	}
}

func TestLibraryNative_EncryptData_RejectsInvalidNonceLength(t *testing.T) {
	_, err := newTestLibraryNative().EncryptData(EncryptDataInput{
		Key:   make([]byte, 16),
		Nonce: make([]byte, AESGCMNonceSize-1),
	})
	if err == nil {
		t.Fatal("EncryptData() error = nil, want non-nil")
	}
}

func TestLibraryNative_DecryptData_RejectsInvalidTagAndAuthenticationFailure(t *testing.T) {
	service := newTestLibraryNative()
	key := make([]byte, 16)
	nonce := make([]byte, AESGCMNonceSize)

	_, err := service.DecryptData(DecryptDataInput{
		Key:   key,
		Nonce: nonce,
		Tag:   make([]byte, AESGCMTagSize-1),
	})
	if err == nil {
		t.Fatal("DecryptData() error = nil for invalid tag length, want non-nil")
	}

	result, err := service.EncryptData(EncryptDataInput{
		Key:       key,
		Nonce:     nonce,
		Plaintext: []byte("plaintext"),
	})
	if err != nil {
		t.Fatalf("EncryptData() error: %v", err)
	}
	result.Tag[0] ^= 1

	_, err = service.DecryptData(DecryptDataInput{
		Key:        key,
		Nonce:      nonce,
		Ciphertext: result.Ciphertext,
		Tag:        result.Tag,
	})
	if err == nil {
		t.Fatal("DecryptData() error = nil for invalid authentication tag, want non-nil")
	}
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", value, err)
	}
	return decoded
}
