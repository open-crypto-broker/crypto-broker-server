package procedure

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)


type Sign struct {
	cryptographicEngineNative *c10y.LibraryNative
}

// signRequest represents the input for the sign method from the client
type signRequest struct {
	csr                   *x509.CertificateRequest
	caPrivateKey          any
	caCert                *x509.Certificate
	validNotBefore        *time.Time
	validNotAfter         *time.Time
	subject               *string
	CrlDistributionPoints []string
}

func NewSign(cryptographicEngineNative *c10y.LibraryNative) *Sign {
	return &Sign{cryptographicEngineNative: cryptographicEngineNative}
}

func (procedure *Sign) Execute(req *protobuf.SignRequest) (*protobuf.SignResponse, error) {
	reqProfile, err := profile.Retrieve(req.Profile)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve profile, err: %w", err)
	}

	input, err := procedure.parseRawSignRequest(req)
	if err != nil {
		return nil, fmt.Errorf("error parsing request data: %w", err)
	}

	clientCRTRaw, err := procedure.sign(input, reqProfile)
	if err != nil {
		return nil, fmt.Errorf("error while signing data: %w", err)
	}

	return &protobuf.SignResponse{
		SignedCertificate: base64.StdEncoding.EncodeToString(clientCRTRaw),
		Metadata:          req.Metadata,
	}, nil
}

// sign contains logic that signs CSR and returns signed certificate or non-nil error if any.
func (procedure *Sign) sign(clientInput signRequest, p profile.Profile) (certDER []byte, err error) {
	type signer interface {
		SignCertificate(c10y.SignProfileOpts, c10y.SignAPIOpts) ([]byte, error)
	}

	var s signer
	switch p.Settings.CryptoLibrary {
	case c10y.LibNative:
		s = procedure.cryptographicEngineNative
	default:
		return nil, fmt.Errorf("unknown '%s' cryptographic engine, available values: %v",
			p.Settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
	}

	var subject string
	if clientInput.subject != nil {
		subject = *clientInput.subject
	}

	optsProfile := c10y.SignProfileOpts{
		SignatureAlgorithm: p.API.SignCertificate.SignatureAlgorithm,
		Validity: c10y.SignProfileValidity{
			NotBeforeOffset: p.API.SignCertificate.Validity.NotBeforeOffset,
			NotAfterOffset:  p.API.SignCertificate.Validity.NotAfterOffset,
		},
		KeyUsage:         p.API.SignCertificate.KeyUsage,
		ExtendedKeyUsage: p.API.SignCertificate.ExtendedKeyUsage,
		BasicConstraints: c10y.SignProfileBasicConstraints{
			IsCA:              p.API.SignCertificate.BasicConstraints.CA,
			PathLenConstraint: p.API.SignCertificate.BasicConstraints.PathLenConstraint,
		},
		SubjectKeyConstraints: p.API.SignCertificate.KeyConstraints.Subject,
	}

	optsAPI := c10y.SignAPIOpts{
		CACert:                clientInput.caCert,
		PrivateKey:            clientInput.caPrivateKey,
		CSR:                   clientInput.csr,
		Subject:               subject,
		CrlDistributionPoints: clientInput.CrlDistributionPoints,
		ValidNotBefore:        clientInput.validNotBefore,
		ValidNotAfter:         clientInput.validNotAfter,
	}
	clientCRTRaw, err := s.SignCertificate(optsProfile, optsAPI)
	if err != nil {
		return nil, fmt.Errorf("could not create certificate, err: %s", err)
	}

	return clientCRTRaw, nil
}

// parseRawSignRequest parses the request and returns the signClientInput
func (procedure *Sign) parseRawSignRequest(req *protobuf.SignRequest) (signRequest, error) {
	block, _ := pem.Decode([]byte(req.Csr))
	if block == nil {
		return signRequest{}, fmt.Errorf("could not decode CSR as PEM file")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return signRequest{}, fmt.Errorf("could not parse certificate request, err: %s", err)
	}

	caPrivateKey, err := c10y.ParsePrivateKeyFromPEM([]byte(req.CaPrivateKey))
	if err != nil {
		return signRequest{}, fmt.Errorf("could not parse private key, err: %s", err)
	}

	cert, err := c10y.ParseX509Cert([]byte(req.CaCert))
	if err != nil {
		return signRequest{}, fmt.Errorf("could not parse x.509 CA cert from request, err: %w", err)
	}

	input := signRequest{
		csr:                   csr,
		caPrivateKey:          caPrivateKey,
		caCert:                cert,
		subject:               req.Subject,
		CrlDistributionPoints: req.CrlDistributionPoints,
	}

	if req.ValidNotBefore != nil {
		startValidity := time.Unix(int64(*req.ValidNotBefore), 0)
		input.validNotBefore = &startValidity
	}

	if req.ValidNotAfter != nil {
		endValidity := time.Unix(int64(*req.ValidNotAfter), 0)
		input.validNotAfter = &endValidity
	}

	return input, nil
}
