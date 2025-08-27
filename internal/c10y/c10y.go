// Package c10y stands for cryptography. Contains utilities related with cryptography.
package c10y

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

const (
	// LibNative predefined keyword for native cryptographic library (go std lib)
	LibNative = "native"
)

// predefined keywords for supported key usages
const (
	KeyUsageDigitalSignature  = "digitalSignature"
	KeyUsageContentCommitment = "contentCommitment"
	KeyUsageNonRepudiation    = "nonRepudiation"
	KeyUsageKeyEncipherment   = "keyEncipherment"
	KeyUsageDataEncipherment  = "dataEncipherment"
	KeyUsageKeyAgreement      = "keyAgreement"
	KeyUsageKeyCertSign       = "keyCertSign"
	KeyUsageCRLSign           = "cRLSign"
	KeyUsageEncipherOnly      = "encipherOnly"
	KeyUsageDecipherOnly      = "decipherOnly"
)

// predefined keywords for supported extended key usages
const (
	ExtKeyUsageServerAuth      = "serverAuth"
	ExtKeyUsageClientAuth      = "clientAuth"
	ExtKeyUsageCodeSigning     = "codeSigning"
	ExtKeyUsageEmailProtection = "emailProtection"
	ExtKeyUsageTimeStamping    = "timeStamping"
	ExtKeyUsageOCSPSigning     = "OCSPSigning"
)

// Hash is base 16 (hexadecimal), lower-case, two characters per byte string.
//
// For example SHA-512 produces a fixed-size output of 512 bits, which is equivalent to 64 bytes,
// therefore Hash will be 128-character hexadecimal string.
type Hash string

// SignAPIOpts represents all information required in certificate signing process provided from API call
type SignAPIOpts struct {
	CACert                *x509.Certificate
	PrivateKey            any
	CSR                   *x509.CertificateRequest
	Subject               pkix.Name
	CrlDistributionPoints []string
}

// SignProfileOpts represents all information required in certificate signing process provided from profile
type SignProfileOpts struct {
	SignatureAlgorithm x509.SignatureAlgorithm
	Validity           SignProfileValidity
	KeyUsage           []x509.KeyUsage
	ExtendedKeyUsage   []x509.ExtKeyUsage
	BasicConstraints   SignProfileBasicConstraints
}

type SignProfileValidity struct {
	NotBefore time.Duration
	NotAfter  time.Duration
}

type SignProfileBasicConstraints struct {
	IsCA              bool
	PathLenConstraint int
}

// SupportedCryptographicLibraries predefined list of supported cryptographic libraries by c10y pkg
var SupportedCryptographicLibraries = []string{LibNative}

// SupportedKeyUsages predefined list of supported key usages
var SupportedKeyUsages = []string{KeyUsageKeyEncipherment, KeyUsageCRLSign, KeyUsageKeyCertSign, KeyUsageDataEncipherment,
	KeyUsageDecipherOnly, KeyUsageDigitalSignature, KeyUsageEncipherOnly, KeyUsageKeyAgreement, KeyUsageContentCommitment, KeyUsageNonRepudiation}

// SupportedExtKeyUsages predefined list of supported extended key usages
var SupportedExtKeyUsages = []string{ExtKeyUsageClientAuth, ExtKeyUsageCodeSigning, ExtKeyUsageEmailProtection,
	ExtKeyUsageOCSPSigning, ExtKeyUsageServerAuth, ExtKeyUsageTimeStamping}

// ParseX509Cert accepts raw certificate bytes in PEM format and parses it onto *x509.Certificate struct
func ParseX509Cert(rawCert []byte) (*x509.Certificate, error) {
	pemBlock, _ := pem.Decode(rawCert)
	if pemBlock == nil || pemBlock.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	return x509.ParseCertificate(pemBlock.Bytes)
}

// ParsePrivateKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 private key
// The function tries to parse the key first in PKCS1 format, then PKCS8, finally EC format.
func ParsePrivateKeyFromPEM(key []byte) (any, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("key must be PEM encoded")
	}

	var parsedKey any
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			if parsedKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
				return nil, err
			}
		}
	}

	return parsedKey, nil
}

func ParseSubjectFromString(subject string) (pkix.Name, error) {
	newSubject := pkix.Name{}
	fields := strings.Split(subject, ",")
	if len(fields) < 2 {
		// Split by semicolon instead
		fields = strings.Split(subject, ";")
	}
	if len(fields) < 2 {
		return pkix.Name{}, fmt.Errorf("invalid separator used. Only single comma ',' or semicolon ';' are valid subject separators. Subject: %s", subject)
	}
	for _, v := range fields {
		arr := strings.Split(v, "=")
		if len(arr) != 2 {
			return pkix.Name{}, fmt.Errorf("invalid subject component %s. Only the 'key=value,key=value' format is accepted as string.", v)
		}
		key, val := strings.TrimSpace(arr[0]), strings.TrimSpace(arr[1])
		switch key {
		case "CN":
			newSubject.CommonName = val
		case "SERIALNUMBER":
			newSubject.SerialNumber = val
		case "C":
			newSubject.Country = append(newSubject.Country, val)
		case "L":
			newSubject.Locality = append(newSubject.Locality, val)
		case "ST", "S":
			newSubject.Province = append(newSubject.Province, val)
		case "STREET":
			newSubject.StreetAddress = append(newSubject.StreetAddress, val)
		case "O":
			newSubject.Organization = append(newSubject.Organization, val)
		case "OU":
			newSubject.OrganizationalUnit = append(newSubject.OrganizationalUnit, val)
		default:
			// Unknown attribute, return an error
			return pkix.Name{}, fmt.Errorf("Error while parsing custom subject, unkown attribute %s:%s", key, val)
		}
	}
	return newSubject, nil
}

// MapKeyUsageToExtension maps x509.KeyUsage to pkix.Extension or returns non-nil error if any
func MapKeyUsageToExtension(usage x509.KeyUsage) (pkix.Extension, error) {
	bitString := asn1.BitString{
		Bytes:     []byte{byte(usage), byte(usage >> 8)},
		BitLength: 9,
	}

	encoded, err := asn1.Marshal(bitString)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal key usage: %w", err)
	}

	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15}, // OID for keyUsage
		Critical: true,
		Value:    encoded,
	}, nil
}

// MapStringToKeyUsage maps profile used keyword to x509.KeyUsage
func MapStringToKeyUsage(in string) (x509.KeyUsage, error) {
	switch in {
	case KeyUsageDigitalSignature:
		return x509.KeyUsageDigitalSignature, nil
	case KeyUsageContentCommitment, KeyUsageNonRepudiation:
		return x509.KeyUsageContentCommitment, nil
	case KeyUsageCRLSign:
		return x509.KeyUsageCRLSign, nil
	case KeyUsageKeyCertSign:
		return x509.KeyUsageCertSign, nil
	case KeyUsageDataEncipherment:
		return x509.KeyUsageDataEncipherment, nil
	case KeyUsageDecipherOnly:
		return x509.KeyUsageDecipherOnly, nil
	case KeyUsageEncipherOnly:
		return x509.KeyUsageEncipherOnly, nil
	case KeyUsageKeyAgreement:
		return x509.KeyUsageKeyAgreement, nil
	case KeyUsageKeyEncipherment:
		return x509.KeyUsageKeyEncipherment, nil
	default:
		return x509.KeyUsage(0), fmt.Errorf("unsupported key usage %s", in)
	}
}

// MapExtKeyUsage maps keyword to x509.ExtKeyUsage
func MapExtKeyUsage(in string) (x509.ExtKeyUsage, error) {
	switch in {
	case ExtKeyUsageServerAuth:
		return x509.ExtKeyUsageServerAuth, nil
	case ExtKeyUsageClientAuth:
		return x509.ExtKeyUsageClientAuth, nil
	case ExtKeyUsageCodeSigning:
		return x509.ExtKeyUsageCodeSigning, nil
	case ExtKeyUsageEmailProtection:
		return x509.ExtKeyUsageEmailProtection, nil
	case ExtKeyUsageTimeStamping:
		return x509.ExtKeyUsageTimeStamping, nil
	case ExtKeyUsageOCSPSigning:
		return x509.ExtKeyUsageOCSPSigning, nil
	default:
		return x509.ExtKeyUsage(0), fmt.Errorf("unsupported extended key usage: %s", in)
	}
}

// ComposeSignatureAlgorithm takes two Algorithms and compose x509.SignatureAlgorithm out of them.
// Returned value should be considered supported by crypto broker.
// Sometimes two Algorithms may be valid, but they would produce unsupported x509.SignatureAlgorithm value
// in that case function will return non-nil error.
func ComposeSignatureAlgorithm(signAlg, hashAlg Algorithm) (x509.SignatureAlgorithm, error) {
	switch signAlg {
	case ECDSA:
		if hashAlg == SHA_256 {
			return x509.ECDSAWithSHA256, nil
		}

		if hashAlg == SHA_384 {
			return x509.ECDSAWithSHA384, nil
		}

		if hashAlg == SHA_512 {
			return x509.ECDSAWithSHA512, nil
		}

		return 0, fmt.Errorf("unsupported hashing algorithm %s in conjunction with %s", hashAlg, signAlg)
	case RSA:
		if hashAlg == SHA_256 {
			return x509.SHA256WithRSA, nil
		}

		if hashAlg == SHA_384 {
			return x509.SHA384WithRSA, nil
		}

		if hashAlg == SHA_512 {
			return x509.SHA512WithRSA, nil
		}

		return 0, fmt.Errorf("unsupported hashing algorithm %s in conjunction with %s", hashAlg, signAlg)
	default:
		return 0, fmt.Errorf("unsupported signature algorithm that consist of following pair: %s and %s", signAlg, hashAlg)
	}
}

type BitSizeConstraints struct {
	MinKeySize int
	MaxKeySize int
}

// ValidatePublicKey takes public key from CSR and
// checks its underlying algorithm against acceptable interval of bit size
func ValidatePublicKey(pubKey any, constraintsByAlg map[Algorithm]BitSizeConstraints) error {
	switch pkey := pubKey.(type) {
	case *ecdsa.PublicKey:
		constraints, ok := constraintsByAlg[ECDSA]
		if !ok {
			return fmt.Errorf("missing key constraints for %s", ECDSA)
		}

		params := pkey.Params()
		if params.BitSize < constraints.MinKeySize {
			return fmt.Errorf("expected public key to be at least %d size, got: %d",
				constraints.MinKeySize, params.BitSize)
		}

		if params.BitSize > constraints.MaxKeySize {
			return fmt.Errorf("expected public key to be at most %d size, got: %d",
				constraints.MaxKeySize, params.BitSize)
		}
		return nil

	case *rsa.PublicKey:
		constraints, ok := constraintsByAlg[RSA]
		if !ok {
			return fmt.Errorf("missing key constraints for %s", RSA)
		}

		bitSize := pkey.N.BitLen()
		if bitSize < constraints.MinKeySize {
			return fmt.Errorf("expected public key to be at least %d size, got: %d",
				constraints.MinKeySize, bitSize)
		}

		if bitSize > constraints.MaxKeySize {
			return fmt.Errorf("expected public key to be at most %d size, got: %d",
				constraints.MaxKeySize, bitSize)
		}
		return nil

	default:
		return fmt.Errorf("unsupported signature algorithm (public key) of type %T", pubKey)
	}
}

// ValidatePrivateKey takes the private key from the CA and
// checks its underlying algorithm against acceptable interval of bit size
func ValidatePrivateKey(privKey any, constraintsByAlg map[Algorithm]BitSizeConstraints) error {
	switch pkey := privKey.(type) {
	case *ecdsa.PrivateKey:
		constraints, ok := constraintsByAlg[ECDSA]
		if !ok {
			return fmt.Errorf("missing key constraints for %s", ECDSA)
		}

		params := pkey.Params()
		if params.BitSize < constraints.MinKeySize {
			return fmt.Errorf("expected private key to be at least %d size, got: %d",
				constraints.MinKeySize, params.BitSize)
		}

		if params.BitSize > constraints.MaxKeySize {
			return fmt.Errorf("expected private key to be at most %d size, got: %d",
				constraints.MaxKeySize, params.BitSize)
		}
		return nil

	case *rsa.PrivateKey:
		constraints, ok := constraintsByAlg[RSA]
		if !ok {
			return fmt.Errorf("missing key constraints for %s", RSA)
		}

		bitSize := pkey.N.BitLen()
		if bitSize < constraints.MinKeySize {
			return fmt.Errorf("expected private key to be at least %d size, got: %d",
				constraints.MinKeySize, bitSize)
		}

		if bitSize > constraints.MaxKeySize {
			return fmt.Errorf("expected private key to be at most %d size, got: %d",
				constraints.MaxKeySize, bitSize)
		}
		return nil

	default:
		return fmt.Errorf("unsupported private key algorithm of type %T", privKey)
	}
}
