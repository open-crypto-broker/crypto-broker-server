package profile

import (
	"crypto/x509"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
)

// Profile represents profile concept.
// It should be obtained from rawProfile's Retrieve() method.
type Profile struct {
	Name     string
	Settings ProfileSettings
	API      ProfileAPI
}

type ProfileSettings struct {
	CryptoLibrary string
}

type ProfileAPI struct {
	SignCertificate ProfileAPISignCertificate
	HashData        ProfileAPIHashData
	SignData        ProfileAPISignData
}

type ProfileAPIHashData struct {
	HashAlg c10y.Algorithm
}

type ProfileAPISignData struct {
	SignAlg c10y.Algorithm
}

type ProfileAPISignCertificate struct {
	SignAlg            c10y.Algorithm
	HashAlg            c10y.Algorithm
	SignatureAlgorithm x509.SignatureAlgorithm
	Validity           ProfileAPISignCertificateValidity
	KeyConstraints     ProfileAPISignCertificateKeyConstraints
	KeyUsage           []x509.KeyUsage
	ExtendedKeyUsage   []x509.ExtKeyUsage
	BasicConstraints   ProfileAPISignCertificateBasicConstraints
}

type ProfileAPISignCertificateValidity struct {
	NotBeforeOffset time.Duration
	NotAfterOffset  time.Duration
}

type ProfileAPISignCertificateKeyConstraints struct {
	Subject map[c10y.Algorithm]c10y.BitSizeConstraints
	Issuer  map[c10y.Algorithm]c10y.BitSizeConstraints
}

type ProfileAPISignCertificateBasicConstraints struct {
	CA                bool
	PathLenConstraint int
}
