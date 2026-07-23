package procedure

import (
	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

type DecryptData struct {
	cryptographicEngineNative *c10y.LibraryNative
}

func NewDecryptData(cryptographicEngineNative *c10y.LibraryNative) *DecryptData {
	return &DecryptData{cryptographicEngineNative: cryptographicEngineNative}
}

// Execute decrypts caller-supplied ciphertext according to the selected profile.
func (procedure *DecryptData) Execute(req *protobuf.DecryptDataRequest) (*protobuf.DecryptDataResponse, error) {
	reqProfile, err := profile.Retrieve(req.GetProfile())
	if err != nil {
		return nil, ArgumentError("could not retrieve profile, err: %w", err)
	}

	key, err := validateEncryptionKeySource(req.GetKeySource(), reqProfile)
	if err != nil {
		return nil, err
	}

	decryptMetadata := req.GetDecryptMetadata()
	if decryptMetadata == nil {
		return nil, ArgumentError("decryptMetadata is required for caller-managed decryption")
	}
	if len(decryptMetadata.GetNonce()) != c10y.AESGCMNonceSize {
		return nil, ArgumentError("invalid AES-GCM nonce length: got %d, want %d", len(decryptMetadata.GetNonce()), c10y.AESGCMNonceSize)
	}
	if len(decryptMetadata.GetTag()) != c10y.AESGCMTagSize {
		return nil, ArgumentError("invalid AES-GCM tag length: got %d, want %d", len(decryptMetadata.GetTag()), c10y.AESGCMTagSize)
	}

	engine, err := encryptionEngine(procedure.cryptographicEngineNative, reqProfile)
	if err != nil {
		return nil, err
	}

	plaintext, err := engine.DecryptData(c10y.DecryptDataInput{
		Key:        key,
		Nonce:      decryptMetadata.GetNonce(),
		Ciphertext: req.GetCiphertext(),
		AAD:        decryptMetadata.GetAad(),
		Tag:        decryptMetadata.GetTag(),
	})
	if err != nil {
		return nil, ArgumentError("could not decrypt data: %w", err)
	}

	return &protobuf.DecryptDataResponse{
		Plaintext: plaintext,
		Metadata:  req.GetMetadata(),
	}, nil
}
