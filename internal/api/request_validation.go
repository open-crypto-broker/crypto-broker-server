package api

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func invalidArg(field, msg string) error {
	if field == "" {
		return status.Error(codes.InvalidArgument, msg)
	}
	return status.Errorf(codes.InvalidArgument, "%s: %s", field, msg)
}

func checkMaxLen(field string, valueLen, max int) error {
	if valueLen > max {
		return invalidArg(field, fmt.Sprintf("too large (max %d)", max))
	}
	return nil
}

func checkPrintableASCII(field, value string) error {
	for _, r := range value {
		if r < ' ' || r > '~' {
			return invalidArg(field, "must contain only printable ASCII characters (0x20-0x7E)")
		}
	}

	return nil
}

func validateMetadataIdentifier(field, value string, maxLen int) error {
	if err := checkMaxLen(field, len(value), maxLen); err != nil {
		return err
	}

	return checkPrintableASCII(field, value)
}

func validateURL(rawURL string) bool {
	// 1. Parse the string using the RFC-compliant standard parser
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	// 2. Validate the Network Scheme (typically http or https)
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return false
	}

	// 3. Ensure the Host is not empty
	if u.Host == "" {
		return false
	}

	return true
}

func validateProfileName(profileName string) error {
	if err := profile.ValidateName(profileName); err != nil {
		return invalidArg("profile", err.Error())
	}
	return nil
}

func validateMetadata(m *pb.Metadata) error {
	if m == nil {
		return nil
	}
	if err := validateMetadataIdentifier("metadata.id", m.GetId(), maxMetadataIdLen); err != nil {
		return err
	}

	tc := m.GetTraceContext()
	if tc == nil {
		return nil
	}

	fields := []struct {
		name  string
		value string
		max   int
	}{
		{"metadata.traceContext.traceId", tc.GetTraceId(), maxTraceIdLen},
		{"metadata.traceContext.spanId", tc.GetSpanId(), maxSpanIdLen},
		{"metadata.traceContext.traceFlags", tc.GetTraceFlags(), maxTraceFlagsLen},
		{"metadata.traceContext.traceState", tc.GetTraceState(), maxTraceStateLen},
	}
	for _, f := range fields {
		if err := checkMaxLen(f.name, len(f.value), f.max); err != nil {
			return err
		}
	}
	return validateMetadataIdentifier("metadata.traceContext.correlationId", tc.GetCorrelationId(), maxCorrelationIdLen)
}

func validateHashDataRequest(req *pb.HashDataRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	if err := validateProfileName(req.GetProfile()); err != nil {
		return err
	}
	// Empty hash input is allowed.
	if err := checkMaxLen("input", len(req.GetInput()), maxHashInputBytes); err != nil {
		return err
	}
	return validateMetadata(req.GetMetadata())
}

func validateSignCertificateRequest(req *pb.SignCertificateRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	if err := validateProfileName(req.GetProfile()); err != nil {
		return err
	}

	csr := req.GetCsr()
	if csr == "" {
		return invalidArg("csr", "required")
	}
	if err := checkMaxLen("csr", len(csr), maxCSRBytes); err != nil {
		return err
	}

	caKey := req.GetCaPrivateKey()
	if caKey == "" {
		return invalidArg("caPrivateKey", "required")
	}
	if err := checkMaxLen("caPrivateKey", len(caKey), maxCAPrivateKeyBytes); err != nil {
		return err
	}

	caCert := req.GetCaCert()
	if caCert == "" {
		return invalidArg("caCert", "required")
	}
	if err := checkMaxLen("caCert", len(caCert), maxCACertBytes); err != nil {
		return err
	}

	if err := checkMaxLen("subject", len(req.GetSubject()), maxSubjectLen); err != nil {
		return err
	}

	crl := req.GetCrlDistributionPoints()
	if len(crl) > maxCRLDistributionPoints {
		return invalidArg("crlDistributionPoints", fmt.Sprintf("too many entries (max %d)", maxCRLDistributionPoints))
	}

	for i, v := range crl {
		if len(v) > maxCRLDistributionPointLen {
			return invalidArg(fmt.Sprintf("crlDistributionPoints[%d]", i), fmt.Sprintf("too large (max %d)", maxCRLDistributionPointLen))
		}

		if !validateURL(v) {
			return invalidArg(fmt.Sprintf("crlDistributionPoints[%d]", i), "is not valid URL")
		}
	}

	return validateMetadata(req.GetMetadata())
}

func validateEncryptDataRequest(req *pb.EncryptDataRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	if err := validateProfileName(req.GetProfile()); err != nil {
		return err
	}
	if err := validateKeySource(req.GetKeySource()); err != nil {
		return err
	}
	if err := checkMaxLen("plaintext", len(req.GetPlaintext()), maxEncryptionDataBytes); err != nil {
		return err
	}

	if err := validateKMSConfiguration(req.GetKeySource(), req.GetProfile()); err != nil {
		return err
	}

	metadata := req.GetEncryptMetadata()
	if metadata == nil {
		return invalidArg("encryptMetadata", "required")
	}
	if err := checkMaxLen("encryptMetadata.nonce", len(metadata.GetNonce()), maxEncryptionNonceBytes); err != nil {
		return err
	}
	if err := checkMaxLen("encryptMetadata.aad", len(metadata.GetAad()), maxEncryptionAADBytes); err != nil {
		return err
	}

	return validateMetadata(req.GetMetadata())
}

func validateDecryptDataRequest(req *pb.DecryptDataRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	if err := validateProfileName(req.GetProfile()); err != nil {
		return err
	}
	if err := validateKeySource(req.GetKeySource()); err != nil {
		return err
	}
	if err := checkMaxLen("ciphertext", len(req.GetCiphertext()), maxEncryptionDataBytes); err != nil {
		return err
	}
	if err := validateKMSConfiguration(req.GetKeySource(), req.GetProfile()); err != nil {
		return err
	}

	metadata := req.GetDecryptMetadata()
	if metadata == nil {
		return invalidArg("decryptMetadata", "required")
	}
	if err := checkMaxLen("decryptMetadata.nonce", len(metadata.GetNonce()), maxEncryptionNonceBytes); err != nil {
		return err
	}
	if err := checkMaxLen("decryptMetadata.aad", len(metadata.GetAad()), maxEncryptionAADBytes); err != nil {
		return err
	}
	if err := checkMaxLen("decryptMetadata.tag", len(metadata.GetTag()), maxEncryptionTagBytes); err != nil {
		return err
	}
	return validateMetadata(req.GetMetadata())
}

func validateKeySource(keySource *pb.KeySource) error {
	if keySource == nil || keySource.GetSource() == nil {
		return invalidArg("keySource", "required")
	}
	if rawKey := keySource.GetRawKey(); rawKey != nil {
		return checkMaxLen("keySource.rawKey", len(rawKey), maxEncryptionKeyBytes)
	}
	return nil
}

func validateKMSConfiguration(keySource *pb.KeySource, profileName string) error {
	keyID := keySource.GetKeyId()
	if keyID == "" {
		return nil
	}

	profile, err := profile.Retrieve(profileName)
	if err != nil {
		return err
	}

	configured := profile.KMS.Client != "" && profile.KMS.Config != ""

	if !configured {
		return status.Errorf(codes.FailedPrecondition, "KMS is not configured for profile %q", profile.Name)
	}

	return nil
}
