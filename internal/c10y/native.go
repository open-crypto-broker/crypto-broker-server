package c10y

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"strings"
	"time"
)

// LibraryNative is entity that knows how to perform cryptographic operations using std golang lib
type LibraryNative struct{}

var oidMap = map[string]asn1.ObjectIdentifier{
	"C":  {2, 5, 4, 6},
	"ST": {2, 5, 4, 8},
	"O":  {2, 5, 4, 10},
	"OU": {2, 5, 4, 11},
	"L":  {2, 5, 4, 7},
	"CN": {2, 5, 4, 3},
}

// NewLibraryNative returns pointer to Native.
func NewLibraryNative() *LibraryNative {
	return &LibraryNative{}
}

// ParseRSAPrivateKeyFromPEM parses a PEM encoded PKCS1 or PKCS8 private key
func (service *LibraryNative) ParseRSAPrivateKeyFromPEM(key []byte) (any, error) {
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

// Sign certificate signs provided CSR using std go lib as crypto engine.
// As a result method returns signed certificate in DEF format or non-nil error if any.
func (service *LibraryNative) SignCertificate(profileOpts SignProfileOpts, apiOpts SignAPIOpts) ([]byte, error) {
	now := time.Now()
	notBefore := now.Add(profileOpts.Validity.NotBefore)
	notAfter := now.Add(profileOpts.Validity.NotAfter)

	var finalKU x509.KeyUsage
	for _, ku := range profileOpts.KeyUsage {
		finalKU = finalKU | ku
	}

	// Note that serial number is auto generated as desired by CreateCertificate when SerialNumber key is set to nil
	clientCRTTemplate := x509.Certificate{
		SignatureAlgorithm:    profileOpts.SignatureAlgorithm,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              finalKU,
		ExtKeyUsage:           profileOpts.ExtendedKeyUsage,
		CRLDistributionPoints: apiOpts.CrlDistributionPoints,
		BasicConstraintsValid: true,
		IsCA:                  profileOpts.BasicConstraints.IsCA,
		MaxPathLen:            profileOpts.BasicConstraints.PathLenConstraint,
		MaxPathLenZero:        profileOpts.BasicConstraints.PathLenConstraint == 0,
	}

	if apiOpts.Subject != "" {
		rawSubject, err := service.buildRawSubjectExactOrder(apiOpts.Subject, ",")
		if err != nil {
			return nil, fmt.Errorf("error while building subject from string: %w", err)
		}

		clientCRTTemplate.RawSubject = rawSubject
	} else {
		clientCRTTemplate.Subject = apiOpts.CSR.Subject
	}

	// create client certificate from template and CA public key - DER format
	return x509.CreateCertificate(rand.Reader, &clientCRTTemplate, apiOpts.CACert, apiOpts.CSR.PublicKey, apiOpts.PrivateKey)
}

// HashSHA3_256 returns sha3-256 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA3_256(dataToHash []byte) (Hash, error) {
	return service.hashSHA3(sha3.New256(), dataToHash)
}

// HashSHA3_384 returns sha3-384 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA3_384(dataToHash []byte) (Hash, error) {
	return service.hashSHA3(sha3.New384(), dataToHash)
}

// HashSHA3_512 returns sha3-512 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA3_512(dataToHash []byte) (Hash, error) {
	return service.hashSHA3(sha3.New512(), dataToHash)
}

// HashSHA_256 returns sha-256 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA_256(dataToHash []byte) (Hash, error) {
	return Hash(fmt.Sprintf("%x", sha256.Sum256(dataToHash))), nil
}

// HashSHA_384 returns sha-384 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA_384(dataToHash []byte) (Hash, error) {
	return Hash(fmt.Sprintf("%x", sha512.Sum384(dataToHash))), nil
}

// HashSHA_512 returns sha-512 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA_512(dataToHash []byte) (Hash, error) {
	return Hash(fmt.Sprintf("%x", sha512.Sum512(dataToHash))), nil
}

// HashSHA_512_256 returns sha512/256 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashSHA_512_256(dataToHash []byte) (Hash, error) {
	return Hash(fmt.Sprintf("%x", sha512.Sum512_256(dataToHash))), nil
}

// HashShake_128 returns Shake128 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashShake_128(size int, dataToHash []byte) (Hash, error) {
	shake := sha3.NewSHAKE128()
	shake.Write(dataToHash)
	output := make([]byte, size)
	shake.Read(output)

	return Hash(fmt.Sprintf("%x", output)), nil
}

// HashShake_256 returns Shake256 hash of provided bytes or non-nil error if any.
func (service *LibraryNative) HashShake_256(size int, dataToHash []byte) (Hash, error) {
	shake := sha3.NewSHAKE256()
	shake.Write(dataToHash)
	output := make([]byte, size)
	shake.Read(output)

	return Hash(fmt.Sprintf("%x", output)), nil
}

// hashSHA3 returns SHA-3 hash of dataToHash
func (service *LibraryNative) hashSHA3(sha3 *sha3.SHA3, dataToHash []byte) (Hash, error) {
	if _, err := sha3.Write(dataToHash); err != nil {
		return Hash(""), fmt.Errorf("failure absorbing more state into hash : %w", err)
	}

	return Hash(fmt.Sprintf("%x", sha3.Sum(nil))), nil
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
