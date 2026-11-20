package c10y

import (
	"crypto/mldsa"
	"encoding/pem"
	"fmt"
)

const (
	mlDSAPrivateKeyPEMType = "ML-DSA PRIVATE KEY"
	mlDSAPublicKeyPEMType  = "ML-DSA PUBLIC KEY"
)

// ParseMLDSAPrivateKey parses raw ML-DSA private-key seed bytes.
func ParseMLDSAPrivateKey(encoded []byte, algorithm Algorithm) (*mldsa.PrivateKey, error) {
	return mldsa.NewPrivateKey(MLDSAParameters(algorithm), encoded)
}

// ParseMLDSAPublicKey parses raw ML-DSA public-key bytes.
func ParseMLDSAPublicKey(encoded []byte, algorithm Algorithm) (*mldsa.PublicKey, error) {
	return mldsa.NewPublicKey(MLDSAParameters(algorithm), encoded)
}

// MLDSAParameters returns the FIPS 204 parameter set configured by a profile.
func MLDSAParameters(algorithm Algorithm) mldsa.Parameters {
	switch algorithm {
	case MLDSA44:
		return mldsa.MLDSA44()
	case MLDSA65:
		return mldsa.MLDSA65()
	case MLDSA87:
		return mldsa.MLDSA87()
	default:
		panic(fmt.Sprintf("unsupported ML-DSA algorithm %q", algorithm))
	}
}

// EncodeMLDSAPrivateKey encodes an ML-DSA private-key seed as PEM.
func EncodeMLDSAPrivateKey(key *mldsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: mlDSAPrivateKeyPEMType, Bytes: key.Bytes()})
}

// EncodeMLDSAPublicKey encodes an ML-DSA public key as PEM.
func EncodeMLDSAPublicKey(key *mldsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: mlDSAPublicKeyPEMType, Bytes: key.Bytes()})
}
