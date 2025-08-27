package profile

import (
	"crypto/x509"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
)

// rawProfile struct convenient for YAML encoded profile parsing.
// It is primarly used to parse YAML formatted profile and generate
// exported, ready to use Profile out of it, through Profile() method.
type rawProfile struct {
	Name     string             `yaml:"Name"`
	Settings rawProfileSettings `yaml:"Settings"`
	API      rawProfileAPI      `yaml:"API"`
}

type rawProfileSettings struct {
	CryptoLibrary string `yaml:"CryptoLibrary"`
}

type rawProfileAPI struct {
	SignCertificate rawProfileAPISignCertificate `yaml:"SignCertificate"`
	HashData        rawProfileAPIHashData        `yaml:"HashData"`
	SignData        rawProfileAPISignData        `yaml:"SignData"`
}

type rawProfileAPIHashData struct {
	HashAlg string `yaml:"HashAlg"`
}

type rawProfileAPISignData struct {
	SignAlg string `yaml:"SignAlg"`
}

type rawProfileAPISignCertificate struct {
	SignAlg          string                                       `yaml:"SignAlg"`
	HashAlg          string                                       `yaml:"HashAlg"`
	Validity         rawProfileAPISignCertificateValidity         `yaml:"Validity"`
	KeyConstraints   rawProfileAPISignCertificateKeyConstraints   `yaml:"KeyConstraints"`
	KeyUsage         []string                                     `yaml:"KeyUsage"`
	ExtendedKeyUsage []string                                     `yaml:"ExtendedKeyUsage"`
	BasicConstraints rawProfileAPISignCertificateBasicConstraints `yaml:"BasicConstraints"`
}

type rawProfileAPISignCertificateValidity struct {
	NotBeforeOffset string `yaml:"ValidNotBeforeOffset"`
	NotAfterOffset  string `yaml:"ValidNotAfterOffset"`
}

type rawProfileAPISignCertificateKeyConstraints struct {
	Subject map[string]rawProfileAPISignCertificateKeyConstraintsLimits `yaml:"Subject"`
	Issuer  map[string]rawProfileAPISignCertificateKeyConstraintsLimits `yaml:"Issuer"`
}
type rawProfileAPISignCertificateKeyConstraintsLimits struct {
	MinKeySize int `yaml:"MinKeySize"`
	MaxKeySize int `yaml:"MaxKeySize"`
}

type rawProfileAPISignCertificateBasicConstraints struct {
	CA                bool `yaml:"CA"`
	PathLenConstraint *int `yaml:"PathLenConstraint,omitempty"` // Optional, only set if CA is true
}

// mapToProfile returns Profile struct out of rawProfile or non-nil error if any
func (p rawProfile) mapToProfile() (Profile, error) {
	if err := p.validate(); err != nil {
		return Profile{}, fmt.Errorf("raw profile is invalid, err: %w", err)
	}

	api := ProfileAPI{}
	if !reflect.DeepEqual(p.API.HashData, rawProfileAPIHashData{}) {
		api.HashData = ProfileAPIHashData{
			HashAlg: c10y.NewAlgorithm(p.API.HashData.HashAlg),
		}
	}

	if !reflect.DeepEqual(p.API.SignData, rawProfileAPISignData{}) {
		api.SignData = ProfileAPISignData{
			SignAlg: c10y.NewAlgorithm(p.API.SignData.SignAlg),
		}
	}

	if !reflect.DeepEqual(p.API.SignCertificate, rawProfileAPISignCertificate{}) {
		// Validity parsing
		notBeforeOffset, err := time.ParseDuration(p.API.SignCertificate.Validity.NotBeforeOffset)
		if err != nil {
			return Profile{}, fmt.Errorf("could not convert not before offset to %T, err: %w", time.Duration(1), err)
		}

		notAfterOffset, err := time.ParseDuration(p.API.SignCertificate.Validity.NotAfterOffset)
		if err != nil {
			return Profile{}, fmt.Errorf("could not convert not after offset to %T, err: %w", time.Duration(1), err)
		}
		// Key constraints
		subjectContraints := make(map[c10y.Algorithm]c10y.BitSizeConstraints, len(p.API.SignCertificate.KeyConstraints.Subject))
		for alg, kc := range p.API.SignCertificate.KeyConstraints.Subject {
			subjectContraints[c10y.NewAlgorithm(alg)] = c10y.BitSizeConstraints{
				MinKeySize: kc.MinKeySize,
				MaxKeySize: kc.MaxKeySize,
			}
		}
		issuerContraints := make(map[c10y.Algorithm]c10y.BitSizeConstraints, len(p.API.SignCertificate.KeyConstraints.Issuer))
		for alg, kc := range p.API.SignCertificate.KeyConstraints.Issuer {
			issuerContraints[c10y.NewAlgorithm(alg)] = c10y.BitSizeConstraints{
				MinKeySize: kc.MinKeySize,
				MaxKeySize: kc.MaxKeySize,
			}
		}
		// Key usage
		ckus := []x509.KeyUsage{}
		for _, cku := range p.API.SignCertificate.KeyUsage {
			parsedKeyUsage, err := c10y.MapStringToKeyUsage(cku)
			if err != nil {
				return Profile{}, fmt.Errorf("could not map critical key usage string into its golang representation, err: %w", err)
			}

			ckus = append(ckus, parsedKeyUsage)
		}
		// Extended key usage
		ekus := []x509.ExtKeyUsage{}
		for _, eku := range p.API.SignCertificate.ExtendedKeyUsage {
			ku, err := c10y.MapExtKeyUsage(eku)
			if err != nil {
				return Profile{}, fmt.Errorf("could not map extended key usage into its golang representation, err: %w", err)
			}

			ekus = append(ekus, ku)
		}

		signAlg, hashAlg := c10y.NewAlgorithm(p.API.SignCertificate.SignAlg), c10y.NewAlgorithm(p.API.SignCertificate.HashAlg)
		signatureAlgorithm, err := c10y.ComposeSignatureAlgorithm(signAlg, hashAlg)
		if err != nil {
			return Profile{}, fmt.Errorf("problem with signature algorithm, err: %w", err)
		}

		pathLenConstraint := -1 // Default value, equivalent to unset in the certificate
		if p.API.SignCertificate.BasicConstraints.PathLenConstraint != nil {
			pathLenConstraint = *p.API.SignCertificate.BasicConstraints.PathLenConstraint
		}

		api.SignCertificate = ProfileAPISignCertificate{
			SignAlg:            signAlg,
			HashAlg:            hashAlg,
			SignatureAlgorithm: signatureAlgorithm,
			Validity: ProfileAPISignCertificateValidity{
				NotBeforeOffset: notBeforeOffset,
				NotAfterOffset:  notAfterOffset,
			},
			KeyConstraints: ProfileAPISignCertificateKeyConstraints{
				Subject: subjectContraints,
				Issuer:  issuerContraints,
			},
			KeyUsage:         ckus,
			ExtendedKeyUsage: ekus,
			BasicConstraints: ProfileAPISignCertificateBasicConstraints{
				CA:                p.API.SignCertificate.BasicConstraints.CA,
				PathLenConstraint: pathLenConstraint,
			},
		}
	}

	return Profile{
		Name: p.Name,
		Settings: ProfileSettings{
			CryptoLibrary: strings.ToLower(p.Settings.CryptoLibrary),
		},
		API: api,
	}, nil
}

func (p rawProfile) validate() error {
	return errors.Join(p.Settings.validate(), p.API.validate())
}

func (settings rawProfileSettings) validate() error {
	if !slices.Contains(c10y.SupportedCryptographicLibraries, strings.ToLower(settings.CryptoLibrary)) {
		return fmt.Errorf("unknown cryptographic library: %s, available values: %v",
			settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
	}

	return nil
}

func (API rawProfileAPI) validate() error {
	if reflect.DeepEqual(API.SignData, rawProfileAPISignData{}) && reflect.DeepEqual(API.HashData, rawProfileAPIHashData{}) && reflect.DeepEqual(API.SignCertificate, rawProfileAPISignCertificate{}) {
		return errors.New("profile should contain at least one API")
	}

	var err error
	if !reflect.DeepEqual(API.SignData, rawProfileAPISignData{}) {
		err = errors.Join(err, API.SignData.validate())
	}

	if !reflect.DeepEqual(API.HashData, rawProfileAPIHashData{}) {
		err = errors.Join(err, API.HashData.validate())
	}

	if !reflect.DeepEqual(API.SignCertificate, rawProfileAPISignCertificate{}) {
		err = errors.Join(err, API.SignCertificate.validate())
	}

	return err
}

func (API rawProfileAPISignData) validate() error {
	return nil
}

func (dataHashing rawProfileAPIHashData) validate() error {
	alg := c10y.NewAlgorithm(dataHashing.HashAlg)
	if !alg.IsSupported(c10y.HashData) {
		return fmt.Errorf("unsupported algorithm: %s for operation %s, available algorithms: %v",
			alg, c10y.HashData, c10y.HashDataAlgorithmsSupported)
	}

	return nil
}

func (certGeneration rawProfileAPISignCertificate) validate() error {
	var err error

	// Check correctness of algorithms
	signAlg, hashAlg := c10y.NewAlgorithm(certGeneration.SignAlg), c10y.NewAlgorithm(certGeneration.HashAlg)
	if _, errSignAlg := c10y.ComposeSignatureAlgorithm(signAlg, hashAlg); errSignAlg != nil {
		err = errors.Join(err, errSignAlg)
	}

	// Check key Usage
	for _, cku := range certGeneration.KeyUsage {
		if !slices.Contains(c10y.SupportedKeyUsages, cku) {
			err = errors.Join(err, fmt.Errorf("%s is not supported key usage", cku))
		}
	}
	// Check extended Key Usage
	for _, eku := range certGeneration.ExtendedKeyUsage {
		if !slices.Contains(c10y.SupportedExtKeyUsages, eku) {
			err = errors.Join(err, fmt.Errorf("%s is not supported extended key usage", eku))
		}
	}

	return errors.Join(err,
		certGeneration.Validity.validate(),
		certGeneration.KeyConstraints.validate(),
		certGeneration.BasicConstraints.validate())
}

func (validity rawProfileAPISignCertificateValidity) validate() error {
	after, err := time.ParseDuration(validity.NotAfterOffset)
	if err != nil {
		return fmt.Errorf("could not parse NotAfterOffset as %T, err: %w", time.Duration(1), err)
	}

	before, err := time.ParseDuration(validity.NotBeforeOffset)
	if err != nil {
		return fmt.Errorf("could not parse NotBeforeOffset as %T, err: %w", time.Duration(1), err)
	}

	if after-before < 0 {
		return fmt.Errorf("AfterOffset (%s) is earlier in time than BeforeOffset (%s)", after, before)
	}

	return nil
}

func (keyConstraints rawProfileAPISignCertificateKeyConstraints) validate() error {
	var err error

	for _, limits := range keyConstraints.Subject {
		if limits.MinKeySize < 0 {
			errors.Join(err, errors.New("minKeySize in Subject is negative"))
		}
		if limits.MaxKeySize < 0 {
			errors.Join(err, errors.New("maxKeySize in Subject is negative"))
		}
	}

	for _, limits := range keyConstraints.Issuer {
		if limits.MinKeySize < 0 {
			errors.Join(err, errors.New("minKeySize in Issuer is negative"))
		}
		if limits.MaxKeySize < 0 {
			errors.Join(err, errors.New("maxKeySize in Issuer is negative"))
		}
	}

	return err
}

func (basicConstraint rawProfileAPISignCertificateBasicConstraints) validate() error {
	if !basicConstraint.CA && basicConstraint.PathLenConstraint != nil {
		return fmt.Errorf("PathLenConstraint is set to %d but the CA field is false, which is not allowed.\nPlease delete the PathLenConstraint or set CA to true", *basicConstraint.PathLenConstraint)
	}
	return nil
}
