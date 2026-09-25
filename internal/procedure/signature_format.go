package procedure

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

const signaturePEMBlockType = "SIGNATURE"

type ecdsaSignature struct {
	R, S *big.Int
}

func effectiveSignatureFormat(requestFormat *protobuf.SignatureFormat, profileFormat profile.SignatureFormat) (protobuf.SignatureFormat, error) {
	if requestFormat != nil {
		return validateSignatureFormat(*requestFormat)
	}

	switch profileFormat {
	case profile.SignatureFormatRAW:
		return protobuf.SignatureFormat_SIGNATURE_RAW, nil
	case profile.SignatureFormatDER:
		return protobuf.SignatureFormat_SIGNATURE_DER, nil
	case profile.SignatureFormatPEM:
		return protobuf.SignatureFormat_SIGNATURE_PEM, nil
	default:
		return protobuf.SignatureFormat_SIGNATURE_RAW, ArgumentError("unsupported profile signature format %q", profileFormat)
	}
}

func validateSignatureFormat(format protobuf.SignatureFormat) (protobuf.SignatureFormat, error) {
	switch format {
	case protobuf.SignatureFormat_SIGNATURE_RAW, protobuf.SignatureFormat_SIGNATURE_DER, protobuf.SignatureFormat_SIGNATURE_PEM:
		return format, nil
	default:
		return protobuf.SignatureFormat_SIGNATURE_RAW, ArgumentError("signatureFormat %s is not currently supported", format.String())
	}
}

func encodeSignature(format protobuf.SignatureFormat, key any, signature []byte) ([]byte, error) {
	encoded := signature
	if format == protobuf.SignatureFormat_SIGNATURE_RAW {
		var err error
		encoded, err = ecdsaDERToRaw(key, signature)
		if err != nil {
			return nil, err
		}
	}
	if format == protobuf.SignatureFormat_SIGNATURE_PEM {
		return pem.EncodeToMemory(&pem.Block{Type: signaturePEMBlockType, Bytes: encoded}), nil
	}
	return encoded, nil
}

func decodeSignature(format protobuf.SignatureFormat, key any, signature []byte) ([]byte, error) {
	decoded := signature
	if format == protobuf.SignatureFormat_SIGNATURE_PEM {
		block, rest := pem.Decode(signature)
		if block == nil || block.Type != signaturePEMBlockType || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ArgumentError("signature must be a single %s PEM block", signaturePEMBlockType)
		}
		decoded = block.Bytes
	}
	if format == protobuf.SignatureFormat_SIGNATURE_RAW {
		return ecdsaRawToDER(key, decoded)
	}
	return decoded, nil
}

func ecdsaDERToRaw(key any, signature []byte) ([]byte, error) {
	publicKey, ok := ecdsaPublicKey(key)
	if !ok {
		return signature, nil
	}

	var parsed ecdsaSignature
	rest, err := asn1.Unmarshal(signature, &parsed)
	if err != nil || len(rest) != 0 || !validECDSAValues(publicKey, parsed) {
		return nil, ArgumentError("invalid ECDSA DER signature")
	}

	componentSize := (publicKey.Curve.Params().BitSize + 7) / 8
	raw := make([]byte, componentSize*2)
	parsed.R.FillBytes(raw[:componentSize])
	parsed.S.FillBytes(raw[componentSize:])
	return raw, nil
}

func ecdsaRawToDER(key any, signature []byte) ([]byte, error) {
	publicKey, ok := ecdsaPublicKey(key)
	if !ok {
		return signature, nil
	}

	componentSize := (publicKey.Curve.Params().BitSize + 7) / 8
	if len(signature) != componentSize*2 {
		return nil, ArgumentError("invalid ECDSA RAW signature length")
	}
	parsed := ecdsaSignature{
		R: new(big.Int).SetBytes(signature[:componentSize]),
		S: new(big.Int).SetBytes(signature[componentSize:]),
	}
	if !validECDSAValues(publicKey, parsed) {
		return nil, ArgumentError("invalid ECDSA RAW signature")
	}
	der, err := asn1.Marshal(parsed)
	if err != nil {
		return nil, fmt.Errorf("marshal ECDSA signature: %w", err)
	}
	return der, nil
}

func ecdsaPublicKey(key any) (*ecdsa.PublicKey, bool) {
	switch signingKey := key.(type) {
	case *ecdsa.PrivateKey:
		return &signingKey.PublicKey, true
	case *ecdsa.PublicKey:
		return signingKey, true
	default:
		return nil, false
	}
}

func validECDSAValues(publicKey *ecdsa.PublicKey, signature ecdsaSignature) bool {
	return signature.R != nil && signature.S != nil && signature.R.Sign() > 0 && signature.S.Sign() > 0 && signature.R.Cmp(publicKey.Curve.Params().N) < 0 && signature.S.Cmp(publicKey.Curve.Params().N) < 0
}
