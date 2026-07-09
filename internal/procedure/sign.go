package procedure

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/cache"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

// SignCertificate defines the procedure for signing a certificate
type SignCertificate struct {
	cryptographicEngineNative *c10y.LibraryNative
	caCertCache               cache.Cache[string, *x509.Certificate]
}

// signCertificateRequest represents the input for the sign certificate method from the client
type signCertificateRequest struct {
	csr                   *x509.CertificateRequest
	caPrivateKey          any
	caCert                *x509.Certificate
	validNotBefore        *time.Time
	validNotAfter         *time.Time
	subject               *string
	CrlDistributionPoints []string
}

func NewSignCertificate(cryptographicEngineNative *c10y.LibraryNative, caCertCache cache.Cache[string, *x509.Certificate]) *SignCertificate {
	return &SignCertificate{cryptographicEngineNative: cryptographicEngineNative, caCertCache: caCertCache}
}

// Execute executes the sign certificate procedure
func (procedure *SignCertificate) Execute(req *protobuf.SignCertificateRequest) (*protobuf.SignCertificateResponse, error) {
	reqProfile, err := profile.Retrieve(req.GetProfile())
	if err != nil {
		return nil, ArgumentError("could not retrieve profile, err: %w", err)
	}

	input, err := procedure.parseRawSignRequest(req)
	if err != nil {
		return nil, ArgumentError("error parsing request data: %w", err)
	}

	clientCRTRaw, err := procedure.signCertificate(input, reqProfile)
	if err != nil {
		return nil, fmt.Errorf("error while signing data: %w", err)
	}

	resp := &protobuf.SignCertificateResponse{Metadata: req.GetMetadata()}
	switch req.GetOutputFormat() {
	case protobuf.SignOutputFormat_PEM:
		block := &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw}
		resp.SignedCertificate = &protobuf.SignCertificateResponse_Pem{
			Pem: string(pem.EncodeToMemory(block)),
		}
	case protobuf.SignOutputFormat_DER:
		resp.SignedCertificate = &protobuf.SignCertificateResponse_Der{
			Der: clientCRTRaw,
		}
	default:
		resp.SignedCertificate = &protobuf.SignCertificateResponse_Der{
			Der: clientCRTRaw,
		}
	}

	return resp, nil
}

// signCertificate contains logic that signs CSR and returns signed certificate or non-nil error if any.
func (procedure *SignCertificate) signCertificate(req signCertificateRequest, p profile.Profile) (certDER []byte, err error) {
	type signer interface {
		SignCertificate(c10y.SignCertificateInput) ([]byte, error)
	}

	var s signer
	switch p.Settings.CryptoLibrary {
	case c10y.LibNative:
		s = procedure.cryptographicEngineNative
	default:
		return nil, ArgumentError("unknown '%s' cryptographic engine, available values: %v",
			p.Settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
	}

	var subject string
	if req.subject != nil {
		subject = *req.subject
	}

	if err = c10y.ValidatePublicKey(req.csr.PublicKey, p.API.SignCertificate.KeyConstraints.Subject); err != nil {
		if errors.Is(err, c10y.ErrMissingKeyConstraints) {
			return nil, ArgumentError("profile does not contain key constraints for algorithm used in the CSR's public key, err: %w", err)
		}

		return nil, ArgumentError("invalid public key, err: %w", err)
	}

	// Check whether the private key from the CA is secure enough according to profile
	if err = c10y.ValidatePrivateKey(req.caPrivateKey, p.API.SignCertificate.KeyConstraints.Issuer); err != nil {
		if errors.Is(err, c10y.ErrMissingKeyConstraints) {
			return nil, fmt.Errorf("profile does not contain key constraints for algorithm used in the CA's private key, err: %w", err)
		}

		return nil, err
	}

	now := time.Now().UTC()
	notBeforeConstraint := now.Add(p.API.SignCertificate.Validity.NotBeforeOffset)
	notAfterConstraint := now.Add(p.API.SignCertificate.Validity.NotAfterOffset)

	if req.validNotBefore != nil && req.validNotBefore.Before(notBeforeConstraint) {
		return nil, fmt.Errorf("certificate validity (valid not before) %s is earlier than the allowed by the profile %s", req.validNotBefore.String(), notBeforeConstraint.String())
	}

	if req.validNotAfter != nil && req.validNotAfter.After(notAfterConstraint) {
		return nil, fmt.Errorf("certificate end validity (valid not after) %s is later than the allowed by the profile %s", req.validNotAfter.String(), notAfterConstraint.String())
	}

	var finalKU x509.KeyUsage
	for _, ku := range p.API.SignCertificate.KeyUsage {
		finalKU |= ku
	}

	input := c10y.SignCertificateInput{
		KeyUsage:              finalKU,
		ExtendedKeyUsage:      p.API.SignCertificate.ExtendedKeyUsage,
		NotBefore:             now.Add(p.API.SignCertificate.Validity.NotBeforeOffset),
		NotAfter:              now.Add(p.API.SignCertificate.Validity.NotAfterOffset),
		CSR:                   req.csr,
		CACert:                req.caCert,
		PrivateKey:            req.caPrivateKey,
		Subject:               subject,
		CrlDistributionPoints: req.CrlDistributionPoints,
		IsCA:                  p.API.SignCertificate.BasicConstraints.CA,
		PathLenConstraint:     p.API.SignCertificate.BasicConstraints.PathLenConstraint,
		SignatureAlgorithm:    p.API.SignCertificate.SignatureAlgorithm,
	}

	if req.validNotBefore != nil {
		input.NotBefore = req.validNotBefore.UTC()
	}
	if req.validNotAfter != nil {
		input.NotAfter = req.validNotAfter.UTC()
	}

	return s.SignCertificate(input)
}

// parseRawSignRequest parses the request and returns the signClientInput
func (procedure *SignCertificate) parseRawSignRequest(req *protobuf.SignCertificateRequest) (signCertificateRequest, error) {
	block, _ := pem.Decode([]byte(req.GetCsr()))
	if block == nil {
		return signCertificateRequest{}, ArgumentError("could not decode CSR as PEM file")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return signCertificateRequest{}, ArgumentError("could not parse certificate request, err: %w", err)
	}

	// Copy the PEM-encoded CA private key into a mutable buffer so it can be
	// explicitly zeroed once parsing finishes. Go's GC does not scrub freed
	// memory, so without this the key bytes could linger on the heap (core
	// dumps, swap, process memory). Defer guarantees scrubbing on all paths.
	// Note: this only clears this transient copy; the immutable protobuf string
	// and the parsed key's big.Int material are out of reach here and are
	// addressed by the upcoming key-management redesign.
	rawCAPrivateKey := []byte(req.GetCaPrivateKey())
	defer c10y.ZeroBytes(rawCAPrivateKey)

	caPrivateKey, err := c10y.ParsePrivateKeyFromPEM(rawCAPrivateKey)
	if err != nil {
		return signCertificateRequest{}, ArgumentError("could not parse private key, err: %w", err)
	}

	pemCACert := req.GetCaCert()
	cert, ok := procedure.caCertCache.Get(pemCACert)
	if !ok {
		cert, err = c10y.ParseX509Cert([]byte(pemCACert))
		if err != nil {
			return signCertificateRequest{}, ArgumentError("could not parse x.509 CA cert from request, err: %w", err)
		}

		// TTL bound to the certificate's own validity: an expired CA cert must
		// not linger in the cache. cost=1 -> one slot per cached cert.
		if ttl := time.Until(cert.NotAfter); ttl > 0 {
			procedure.caCertCache.SetWithTTL(pemCACert, cert, 1, ttl)
		}
	}

	input := signCertificateRequest{
		csr:                   csr,
		caPrivateKey:          caPrivateKey,
		caCert:                cert,
		subject:               req.Subject,
		CrlDistributionPoints: req.GetCrlDistributionPoints(),
	}

	if req.ValidNotBefore != nil {
		startValidity := time.Unix(int64(req.GetValidNotBefore()), 0).UTC()
		input.validNotBefore = &startValidity
	}

	if req.ValidNotAfter != nil {
		endValidity := time.Unix(int64(req.GetValidNotAfter()), 0).UTC()
		input.validNotAfter = &endValidity
	}

	return input, nil
}
