package api

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

// CryptoBrokerServer defines crypto broker's server
type CryptoBrokerServer struct {
	logger *log.Logger
	protobuf.CryptoBrokerServer
	cryptographicEngineNative *c10y.LibraryNative
}

func NewCryptoBrokerServer(c10yNative *c10y.LibraryNative, logger *log.Logger) *CryptoBrokerServer {
	return &CryptoBrokerServer{cryptographicEngineNative: c10yNative, logger: logger}
}

// Hash contains data hashing logic
func (server *CryptoBrokerServer) Hash(ctx context.Context, req *protobuf.HashRequest) (*protobuf.HashResponse, error) {
	timestampEndpointStart := time.Now()

	reqProfile, err := profile.Retrieve(req.Profile)
	if err != nil {
		return nil, fmt.Errorf("could not retireve profile, err: %w", err)
	}

	hashedBytes, err := server.hash(req.Input, reqProfile)
	if err != nil {
		return nil, fmt.Errorf("error while hashing data: %s", err.Error())
	}

	timestampEndpointEnd := time.Now()
	durationElapsedEndpoint := timestampEndpointEnd.Sub(timestampEndpointStart)

	server.logDuration("Hash", durationElapsedEndpoint)

	return &protobuf.HashResponse{
		HashValue:     string(hashedBytes),
		HashAlgorithm: reqProfile.API.HashData.HashAlg.String(),
		Metadata:      req.Metadata,
	}, nil
}

// Sign contains certificate signing logic
func (server *CryptoBrokerServer) Sign(ctx context.Context, req *protobuf.SignRequest) (*protobuf.SignResponse, error) {
	timestampEndpointStart := time.Now()

	reqProfile, err := profile.Retrieve(req.Profile)
	if err != nil {
		return nil, fmt.Errorf("could not retireve profile, err: %w", err)
	}

	input := signClientInput{
		csr:                   req.Csr,
		caPrivateKey:          req.CaPrivateKey,
		caCert:                req.CaCert,
		validNotBeforeOffset:  req.ValidNotBeforeOffset,
		validNotAfterOffset:   req.ValidNotAfterOffset,
		subject:               req.Subject,
		CrlDistributionPoints: req.CrlDistributionPoints,
	}
	clientCRTRaw, err := server.sign(input, reqProfile)
	if err != nil {
		return nil, fmt.Errorf("error while signing data: %s", err.Error())
	}

	timestampEndpointEnd := time.Now()
	durationElapsedEndpoint := timestampEndpointEnd.Sub(timestampEndpointStart)

	server.logDuration("Sign", durationElapsedEndpoint)

	return &protobuf.SignResponse{
		SignedCertificate: base64.StdEncoding.EncodeToString(clientCRTRaw),
		Metadata:          req.Metadata,
	}, nil
}

type signClientInput struct {
	csr                   string
	caPrivateKey          string
	caCert                string
	validNotBeforeOffset  *string
	validNotAfterOffset   *string
	subject               *string
	CrlDistributionPoints []string
}

// sign contains logic that signs CSR and returns signed certificate or non-nil error if any.
func (server *CryptoBrokerServer) sign(clientInput signClientInput, p profile.Profile) (certDER []byte, err error) {
	type signer interface {
		SignCertificate(c10y.SignProfileOpts, c10y.SignAPIOpts) ([]byte, error)
	}

	var s signer
	switch p.Settings.CryptoLibrary {
	case c10y.LibNative:
		s = server.cryptographicEngineNative
	default:
		err := fmt.Errorf("unknown '%s' library value, available values: %v",
			p.Settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
		server.logger.Println(err)

		return nil, err
	}

	block, _ := pem.Decode([]byte(clientInput.csr))
	if block == nil {
		err := fmt.Errorf("could not decode CSR as PEM file")
		server.logger.Println(err)

		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		err := fmt.Errorf("could not parse certificate request, err: %s", err)
		server.logger.Println(err)

		return nil, err
	}

	if err = csr.CheckSignature(); err != nil {
		err := fmt.Errorf("invalid certificate request signature, err: %s", err)
		server.logger.Println(err)

		return nil, err
	}

	// Check whether the public key in CSR is secure enough according to profile
	if err = c10y.ValidatePublicKey(csr.PublicKey, p.API.SignCertificate.KeyConstraints.Subject); err != nil {
		server.logger.Println(err)
		return nil, err
	}

	caPrivateKey, err := c10y.ParsePrivateKeyFromPEM([]byte(clientInput.caPrivateKey))
	if err != nil {
		err := fmt.Errorf("could not parse private key, err: %s", err)
		server.logger.Println(err)

		return nil, err
	}

	// Check whether the private key from the CA is secure enough according to profile
	if err = c10y.ValidatePrivateKey(caPrivateKey, p.API.SignCertificate.KeyConstraints.Issuer); err != nil {
		server.logger.Println(err)
		return nil, err
	}

	cert, err := c10y.ParseX509Cert([]byte(clientInput.caCert))
	if err != nil {
		err = fmt.Errorf("could not parse x.509 CA cert from request, err: %w", err)
		server.logger.Println(err)

		return nil, err
	}

	// Parse the custom durations
	var notBeforeOffset, notAfterOffset time.Duration
	if clientInput.validNotBeforeOffset != nil {
		notBeforeOffset, err = time.ParseDuration(*clientInput.validNotBeforeOffset)
		if err != nil {
			return nil, fmt.Errorf("error while parsing the User's defined notBeforeOffset %w", err)
		}
		if notBeforeOffset-p.API.SignCertificate.Validity.NotBeforeOffset < 0 {
			return nil, fmt.Errorf("error: user's beforeOffset %s is earlier than the allowed by the profile %s", notBeforeOffset.String(), p.API.SignCertificate.Validity.NotBeforeOffset.String())
		}
	} else {
		notBeforeOffset = p.API.SignCertificate.Validity.NotBeforeOffset
	}
	if clientInput.validNotAfterOffset != nil {
		notAfterOffset, err = time.ParseDuration(*clientInput.validNotAfterOffset)
		if err != nil {
			return nil, fmt.Errorf("error while parsing the User's defined notAfterOffset %w", err)
		}
		if notAfterOffset-p.API.SignCertificate.Validity.NotAfterOffset > 0 {
			return nil, fmt.Errorf("error: user's afterOffset %s is later than the allowed by the profile %s", notAfterOffset.String(), p.API.SignCertificate.Validity.NotAfterOffset.String())
		}
	} else {
		notAfterOffset = p.API.SignCertificate.Validity.NotAfterOffset
	}

	var subject pkix.Name
	if clientInput.subject != nil {
		subject, err = c10y.ParseSubjectFromString(*clientInput.subject)
		if err != nil {
			return nil, fmt.Errorf("error while parsing the custom subject %w", err)
		}
	} else {
		subject = csr.Subject
	}

	optsProfile := c10y.SignProfileOpts{
		SignatureAlgorithm: p.API.SignCertificate.SignatureAlgorithm,
		Validity: c10y.SignProfileValidity{
			NotBefore: notBeforeOffset,
			NotAfter:  notAfterOffset,
		},
		KeyUsage:         p.API.SignCertificate.KeyUsage,
		ExtendedKeyUsage: p.API.SignCertificate.ExtendedKeyUsage,
		BasicConstraints: c10y.SignProfileBasicConstraints{
			IsCA:              p.API.SignCertificate.BasicConstraints.CA,
			PathLenConstraint: p.API.SignCertificate.BasicConstraints.PathLenConstraint,
		},
	}
	optsAPI := c10y.SignAPIOpts{
		CACert:                cert,
		PrivateKey:            caPrivateKey,
		CSR:                   csr,
		Subject:               subject,
		CrlDistributionPoints: clientInput.CrlDistributionPoints,
	}
	clientCRTRaw, err := s.SignCertificate(optsProfile, optsAPI)
	if err != nil {
		err := fmt.Errorf("could not create certificate, err: %s", err)
		server.logger.Println(err)

		return nil, err
	}

	return clientCRTRaw, nil
}

// hash hashes provided data according to profile rules
func (server *CryptoBrokerServer) hash(data []byte, p profile.Profile) (c10y.Hash, error) {

	// hasher defines abstraction over hashing library/engine.
	type hasher interface {
		HashSHA3_256(dataToHash []byte) (c10y.Hash, error)
		HashSHA3_384(dataToHash []byte) (c10y.Hash, error)
		HashSHA3_512(dataToHash []byte) (c10y.Hash, error)
		HashSHA_256(dataToHash []byte) (c10y.Hash, error)
		HashSHA_384(dataToHash []byte) (c10y.Hash, error)
		HashSHA_512(dataToHash []byte) (c10y.Hash, error)
		HashSHA_512_256(dataToHash []byte) (c10y.Hash, error)
		HashShake_128(size int, dataToHash []byte) (c10y.Hash, error)
		HashShake_256(size int, dataToHash []byte) (c10y.Hash, error)
	}

	var h hasher
	switch p.Settings.CryptoLibrary {
	case c10y.LibNative:
		h = server.cryptographicEngineNative
	default:
		err := fmt.Errorf("unknown '%s' library value, available values: %v",
			p.Settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
		server.logger.Println(err)

		return "", err
	}

	var (
		hash c10y.Hash
		err  error
	)
	switch p.API.HashData.HashAlg {
	case c10y.SHA3_256:
		hash, err = h.HashSHA3_256(data)
	case c10y.SHA3_384:
		hash, err = h.HashSHA3_384(data)
	case c10y.SHA3_512:
		hash, err = h.HashSHA3_512(data)
	case c10y.SHA_256:
		hash, err = h.HashSHA_256(data)
	case c10y.SHA_384:
		hash, err = h.HashSHA_384(data)
	case c10y.SHA_512:
		hash, err = h.HashSHA_512(data)
	case c10y.SHA_512_256:
		hash, err = h.HashSHA_512_256(data)
	case c10y.SHAKE_128:
		hash, err = h.HashShake_128(16, data)
	case c10y.SHAKE_256:
		hash, err = h.HashShake_256(32, data)
	default:
		err := fmt.Errorf("unknown '%s' algorithm value, available values: %v", p.API.HashData.HashAlg, c10y.HashDataAlgorithmsSupported)
		server.logger.Println(err)

		return "", err
	}

	if err != nil {
		err := fmt.Errorf("could not hash provided bytes, err: %s", err)
		server.logger.Println(err)

		return "", err
	}

	return hash, nil
}

func (srv *CryptoBrokerServer) logDuration(methodName string, duration time.Duration) {
	srv.logger.Printf("Server's %s method took: %fµs\n", methodName, float64(duration.Nanoseconds())/1000.0)
}
