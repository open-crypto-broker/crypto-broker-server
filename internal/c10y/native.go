package c10y

import (
	"crypto/rand"
	// #nosec G505 G401 -- SHA-1 is required for Subject Key Identifier per RFC 5280
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// LibraryNative is entity that knows how to perform cryptographic operations using std golang lib
type LibraryNative struct{}

type SignCertificateInput struct {
	KeyUsage              x509.KeyUsage
	ExtendedKeyUsage      []x509.ExtKeyUsage
	NotBefore             time.Time
	NotAfter              time.Time
	CSR                   *x509.CertificateRequest
	Subject               string
	CrlDistributionPoints []string
	IsCA                  bool
	PathLenConstraint     int
	SignatureAlgorithm    x509.SignatureAlgorithm
	CACert                *x509.Certificate
	PrivateKey            any
}

var (
	oidMap = map[string]asn1.ObjectIdentifier{
		"C":  {2, 5, 4, 6},
		"ST": {2, 5, 4, 8},
		"O":  {2, 5, 4, 10},
		"OU": {2, 5, 4, 11},
		"L":  {2, 5, 4, 7},
		"CN": {2, 5, 4, 3},
	}

	oidBasicConstraints     = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidSubjectKeyIdentifier = asn1.ObjectIdentifier{2, 5, 29, 14}
)

// NewLibraryNative returns pointer to Native.
func NewLibraryNative() *LibraryNative {
	return &LibraryNative{}
}

// Sign certificate signs provided CSR using std go lib as crypto engine.
// As a result method returns signed certificate in DEF format or non-nil error if any.
func (service *LibraryNative) SignCertificate(input SignCertificateInput) ([]byte, error) {
	if err := input.CSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid certificate request signature, err: %w", err)
	}

	if input.NotBefore.IsZero() {
		return nil, fmt.Errorf("notBefore is zero")
	}
	if input.NotAfter.IsZero() {
		return nil, fmt.Errorf("notAfter is zero")
	}

	if input.NotBefore.UTC().After(input.NotAfter.UTC()) {
		return nil, fmt.Errorf("notBefore (%s) is after notAfter (%s)", input.NotBefore.UTC().String(), input.NotAfter.UTC().String())
	}

	// Note that serial number is auto generated as desired by CreateCertificate when SerialNumber key is set to nil
	clientCRTTemplate := x509.Certificate{
		SignatureAlgorithm:    input.SignatureAlgorithm,
		NotBefore:             input.NotBefore.UTC(), // default value
		NotAfter:              input.NotAfter.UTC(),  // default value
		KeyUsage:              input.KeyUsage,
		ExtKeyUsage:           input.ExtendedKeyUsage,
		CRLDistributionPoints: input.CrlDistributionPoints,
		BasicConstraintsValid: true,
		IsCA:                  input.IsCA,
		MaxPathLen:            input.PathLenConstraint,
		MaxPathLenZero:        input.PathLenConstraint == 0,
	}

	if !input.IsCA {
		extension, err := service.buildBasicConstraintsExtension(false)
		if err != nil {
			return nil, fmt.Errorf("failed to build basic constraints extension: %w", err)
		}
		clientCRTTemplate.ExtraExtensions = append(clientCRTTemplate.ExtraExtensions, extension)
	}

	// Add Subject Key Identifier (SKI) extension
	// RFC 5280: The keyIdentifier is composed of the 160-bit SHA-1 hash of the
	// value of the BIT STRING subjectPublicKey (excluding the tag, length, and
	// number of unused bits).
	ski, err := service.computeSubjectKeyIdentifier(input.CSR.RawSubjectPublicKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to compute subject key identifier: %w", err)
	}

	skiDER, err := asn1.Marshal(ski)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal subject key identifier: %w", err)
	}

	clientCRTTemplate.ExtraExtensions = append(clientCRTTemplate.ExtraExtensions, pkix.Extension{
		Id:       oidSubjectKeyIdentifier,
		Critical: false,
		Value:    skiDER,
	})

	if input.Subject != "" {
		rawSubject, err := service.buildRawSubjectExactOrder(input.Subject, ",")
		if err != nil {
			return nil, fmt.Errorf("error while building subject from string: %w", err)
		}

		clientCRTTemplate.RawSubject = rawSubject
	} else {
		clientCRTTemplate.RawSubject = input.CSR.RawSubject
	}

	// create client certificate from template and CA public key - DER format
	return x509.CreateCertificate(rand.Reader, &clientCRTTemplate, input.CACert, input.CSR.PublicKey, input.PrivateKey)
}

// HashSHA3_256 returns sha3-256 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA3_256(dataToHash []byte) (Hash, error) {
	sum := sha3.Sum256(dataToHash)
	return Hash(hex.EncodeToString(sum[:])), nil
}

// HashSHA3_384 returns sha3-384 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA3_384(dataToHash []byte) (Hash, error) {
	sum := sha3.Sum384(dataToHash)
	return Hash(hex.EncodeToString(sum[:])), nil
}

// HashSHA3_512 returns sha3-512 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA3_512(dataToHash []byte) (Hash, error) {
	sum := sha3.Sum512(dataToHash)
	return Hash(hex.EncodeToString(sum[:])), nil
}

// HashSHA_256 returns sha-256 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA_256(dataToHash []byte) (Hash, error) {
	sum := sha256.Sum256(dataToHash)
	return Hash(hex.EncodeToString(sum[:])), nil
}

// HashSHA_384 returns sha-384 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA_384(dataToHash []byte) (Hash, error) {
	sum := sha512.Sum384(dataToHash)
	return Hash(hex.EncodeToString(sum[:])), nil
}

// HashSHA_512 returns sha-512 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA_512(dataToHash []byte) (Hash, error) {
	sum := sha512.Sum512(dataToHash)
	return Hash(hex.EncodeToString(sum[:])), nil
}

// HashSHA_512_256 returns sha512/256 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA_512_256(dataToHash []byte) (Hash, error) {
	sum := sha512.Sum512_256(dataToHash)
	return Hash(hex.EncodeToString(sum[:])), nil
}

// HashShake_128 returns Shake128 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashShake_128(size int, dataToHash []byte) (Hash, error) {
	shake := sha3.NewSHAKE128()
	if _, err := shake.Write(dataToHash); err != nil {
		return Hash(""), fmt.Errorf("failed to write data to shake: %w", err)
	}

	output := make([]byte, size)
	if _, err := shake.Read(output); err != nil {
		return Hash(""), fmt.Errorf("failed to read data from shake: %w", err)
	}

	return Hash(hex.EncodeToString(output)), nil
}

// HashShake_256 returns Shake256 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashShake_256(size int, dataToHash []byte) (Hash, error) {
	shake := sha3.NewSHAKE256()
	if _, err := shake.Write(dataToHash); err != nil {
		return Hash(""), fmt.Errorf("failed to write data to shake: %w", err)
	}

	output := make([]byte, size)
	if _, err := shake.Read(output); err != nil {
		return Hash(""), fmt.Errorf("failed to read data from shake: %w", err)
	}

	return Hash(hex.EncodeToString(output)), nil
}

// buildRawSubjectExactOrder parses a subject and returns a DER encoded RDNSequence preserving order and duplicates.
func (service *LibraryNative) buildRawSubjectExactOrder(input, sep string) ([]byte, error) {
	parts := strings.Split(input, sep)
	var rdns pkix.RDNSequence

	for _, part := range parts {
		rdn, err := service.composeAttributeTypeAndValue(part)
		if err != nil {
			return nil, fmt.Errorf("error while building raw subject: %w", err)
		}

		if rdn != nil {
			rdns = append(rdns, rdn)
		}
	}

	return asn1.Marshal(rdns)
}

// computeSubjectKeyIdentifier computes the Subject Key Identifier (SKI) from SubjectPublicKeyInfo bytes.
// According to RFC 5280 and OpenSSL's default behavior, the SKI is the SHA-1 hash of the
// subjectPublicKey BIT STRING value (excluding the tag, length, and unused-bits octet).
func (service *LibraryNative) computeSubjectKeyIdentifier(spkiDER []byte) ([]byte, error) {
	// Parse the SPKI structure to get the subjectPublicKey BIT STRING
	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	rest, err := asn1.Unmarshal(spkiDER, &spki)
	if err != nil || len(rest) != 0 {
		return nil, fmt.Errorf("failed to unmarshal SPKI: %w", err)
	}

	// Compute SHA-1 of the public key bytes
	// #nosec G505 G401 -- SHA-1 is required for Subject Key Identifier per RFC 5280
	hash := sha1.Sum(spki.SubjectPublicKey.Bytes)
	return hash[:], nil
}

// buildBasicConstraintsExtension creates a non-critical Basic Constraints extension.
func (service *LibraryNative) buildBasicConstraintsExtension(isCA bool) (pkix.Extension, error) {
	basicConstraints := struct {
		CA bool `asn1:"optional"`
	}{
		CA: isCA,
	}

	encodedBytes, err := asn1.Marshal(basicConstraints)
	if err != nil {
		return pkix.Extension{}, fmt.Errorf("failed to marshal basic constraints: %w", err)
	}

	return pkix.Extension{
		Id:       oidBasicConstraints,
		Critical: false,
		Value:    encodedBytes,
	}, nil
}

// composeAttributeTypeAndValue composes a AttributeTypeAndValue from a part of the subject
func (service *LibraryNative) composeAttributeTypeAndValue(part string) ([]pkix.AttributeTypeAndValue, error) {
	part = strings.TrimSpace(part)
	if part == "" {
		return nil, nil
	}

	kv := strings.SplitN(part, "=", 2)
	if len(kv) != 2 {
		return nil, fmt.Errorf("invalid subject component: %q", part)
	}

	k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
	oid, ok := oidMap[k]
	if !ok {
		return nil, fmt.Errorf("unsupported subject attribute: %q", k)
	}

	return []pkix.AttributeTypeAndValue{{Type: oid, Value: v}}, nil
}

// parseRSAPrivateKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 private key
func (service *LibraryNative) parseRSAPrivateKeyFromPEM(key []byte) (any, error) {
	var err error

	// Parse PEM block
	var block *pem.Block
	if block, _ = pem.Decode(key); block == nil {
		return nil, fmt.Errorf("key must be PEM encoded")
	}

	var parsedKey any
	if parsedKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, err
		}
	}

	return parsedKey, nil
}
