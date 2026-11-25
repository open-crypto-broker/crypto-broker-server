package c10y

import (
	"crypto/mldsa"
	"fmt"
)

// ParseMLDSAPrivateKey parses a PKCS#8 DER-encoded ML-DSA private key.
func ParseMLDSAPrivateKey(derBytes []byte, algorithm Algorithm) (*mldsa.PrivateKey, error) {
	key, err := ParsePrivateKeyFromPKCS8DER(derBytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := key.(*mldsa.PrivateKey)
	if !ok || privateKey.PublicKey().Parameters() != MLDSAParameters(algorithm) {
		return nil, fmt.Errorf("PKCS#8 DER private key must use %s", algorithm)
	}
	return privateKey, nil
}

// ParseMLDSAPublicKey parses a SubjectPublicKeyInfo DER-encoded ML-DSA public key.
func ParseMLDSAPublicKey(derBytes []byte, algorithm Algorithm) (*mldsa.PublicKey, error) {
	key, err := ParsePublicKeyFromDER(derBytes)
	if err != nil {
		return nil, err
	}
	publicKey, ok := key.(*mldsa.PublicKey)
	if !ok || publicKey.Parameters() != MLDSAParameters(algorithm) {
		return nil, fmt.Errorf("SubjectPublicKeyInfo DER public key must use %s", algorithm)
	}
	return publicKey, nil
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
