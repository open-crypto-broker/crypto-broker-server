package procedure

import (
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/kms"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

type EncryptData struct {
	cryptographicEngineNative *c10y.LibraryNative
}

func NewEncryptData(cryptographicEngineNative *c10y.LibraryNative) *EncryptData {
	return &EncryptData{cryptographicEngineNative: cryptographicEngineNative}
}

// Execute encrypts caller-supplied plaintext according to the selected profile.
func (procedure *EncryptData) Execute(req *protobuf.EncryptDataRequest) (*protobuf.EncryptDataResponse, error) {
	reqProfile, err := profile.Retrieve(req.GetProfile())
	if err != nil {
		return nil, ArgumentError("could not retrieve profile, err: %w", err)
	}

	key, err := validateEncryptionKeySource(req.GetKeySource(), reqProfile)
	if err != nil {
		return nil, err
	}

	encryptMetadata := req.GetEncryptMetadata()
	if encryptMetadata == nil {
		return nil, ArgumentError("encryptMetadata is required for caller-managed encryption")
	}
	if len(encryptMetadata.GetNonce()) != c10y.AESGCMNonceSize {
		return nil, ArgumentError("invalid AES-GCM nonce length: got %d, want %d", len(encryptMetadata.GetNonce()), c10y.AESGCMNonceSize)
	}

	engine, err := encryptionEngine(procedure.cryptographicEngineNative)
	if err != nil {
		return nil, err
	}

	result, err := engine.EncryptData(c10y.EncryptDataInput{
		Key:       key,
		Nonce:     encryptMetadata.GetNonce(),
		Plaintext: req.GetPlaintext(),
		AAD:       encryptMetadata.GetAad(),
	})
	if err != nil {
		return nil, fmt.Errorf("could not encrypt data: %w", err)
	}

	return &protobuf.EncryptDataResponse{
		Ciphertext: result.Ciphertext,
		CipherMetadata: &protobuf.CipherMetadata{
			Nonce: encryptMetadata.GetNonce(),
			Aad:   encryptMetadata.GetAad(),
			Tag:   result.Tag,
		},
		Metadata: req.GetMetadata(),
		Descriptor_: &protobuf.CryptoDescriptor{
			Profile:   reqProfile.Name,
			Operation: "EncryptData",
			Algorithm: reqProfile.API.EncryptData.EncryptAlg.String(),
		},
	}, nil
}

func encryptionEngine(cryptographicEngineNative *c10y.LibraryNative) (*c10y.LibraryNative, error) {
	settings := profile.Settings()
	if settings.CryptoLibrary != c10y.LibNative {
		return nil, ArgumentError("unknown '%s' cryptographic engine, available values: %v",
			settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
	}

	return cryptographicEngineNative, nil
}

func validateEncryptionKeySource(keySource *protobuf.KeySource, p profile.Profile) ([]byte, error) {
	if p.API.EncryptData.EncryptAlg != c10y.AES_GCM {
		return nil, ArgumentError("profile does not contain a supported EncryptData configuration")
	}

	if keySource == nil {
		return nil, ArgumentError("keySource is required")
	}

	key, err := GetKey(keySource)
	if err != nil {
		return nil, err
	}

	expectedKeyLength := p.API.EncryptData.KeySize / 8
	if len(key) != expectedKeyLength {
		return nil, ArgumentError("invalid AES-GCM key length: got %d, want %d", len(key), expectedKeyLength)
	}

	return key, nil
}

func GetKey(keySource *protobuf.KeySource) ([]byte, error) {
	keyID := keySource.GetKeyId()

	if keyID != "" {
		return kms.GetKey(keyID)
	}

	return keySource.GetRawKey(), nil
}
