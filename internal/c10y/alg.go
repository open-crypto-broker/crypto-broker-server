package c10y

import (
	"slices"
	"strings"
)

// Here are listed all algorithms. Please note that particular Operation
// supports only subset of them. Please use [IsSupported] method to examine
// whether particual Algorithm is supported in particular operation.
// Predefined Algorithm value should be denoted as normalized strings.
// Please see [normalize] before adding new constant here.
const (
	SHA3_256    Algorithm = "sha3-256"
	SHA3_384    Algorithm = "sha3-384"
	SHA3_512    Algorithm = "sha3-512"
	SHA_256     Algorithm = "sha-256"
	SHA_384     Algorithm = "sha-384"
	SHA_512     Algorithm = "sha-512"
	SHA_512_256 Algorithm = "sha-512/256"
	SHAKE_128   Algorithm = "shake-128"
	SHAKE_256   Algorithm = "shake-256"
	ECDSA       Algorithm = "ecdsa"
	RSA         Algorithm = "rsa"
)

// Here are listed all operations that are part of various APIs
const (

	// HashData represents operation performed in hashData API
	HashData Operation = "hashData"

	// SignCertificateSigning represents signing operation in SignCertificate API
	SignCertificateSigning Operation = "signCertificateSigning"

	// SignCertificateHashing represents hashing operation in SignCertificate API
	SignCertificateHashing Operation = "signCertificateHashing"
)

// HashDataAlgorithmsSupported predefined list of supported hashing algorithms by c10y pkg
var HashDataAlgorithmsSupported = []Algorithm{
	SHA3_256, SHA3_384, SHA3_512, SHA_256, SHA_384,
	SHA_512, SHA_512_256, SHAKE_128, SHAKE_256}

// SignCertificateSigningAlgorithmsSupported list of supported signing algorithms in SignCertificate API
var SignCertificateSigningAlgorithmsSupported = []Algorithm{
	RSA, ECDSA,
}

// SignCertificateHashingAlgorithmsSupported list of supported hashing algorithms in SignCertificate API
var SignCertificateHashingAlgorithmsSupported = []Algorithm{
	SHA_256, SHA_384, SHA_512,
}

// Algorithm represents string that is keyword of cryptographic algorithm used by crypto broker.
// Value of that type should be only created through [NewAlgorithm] constructor
// and therefore considered to be already normalized.
type Algorithm string

// Operation represents step/operation/unit of work done in particular API.
type Operation string

// NewAlgorithm takes string representation of algorithm, normalizes it and return Algorithm
func NewAlgorithm(algorithm string) Algorithm {
	return Algorithm(normalize(algorithm))
}

// IsSupported tells whether given algorithm is supported by particular Operation.
// Please provide only predefined Operation from package constants.
func (alg Algorithm) IsSupported(operation Operation) bool {
	switch operation {
	case SignCertificateSigning:
		return slices.Contains(SignCertificateSigningAlgorithmsSupported, alg)
	case SignCertificateHashing:
		return slices.Contains(SignCertificateHashingAlgorithmsSupported, alg)
	case HashData:
		return slices.Contains(HashDataAlgorithmsSupported, alg)
	default:
		return false
	}
}

// String implements Stringer interface.
func (alg Algorithm) String() string {
	return string(alg)
}

// normalize is function that mutates given algorithm in order to adjust it to crypto broker needs
func normalize(alg string) string {
	return strings.ToLower(alg)
}
