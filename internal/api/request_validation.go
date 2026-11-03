package api

import (
	"fmt"
	"net/url"
	"strings"

	pb "github.com/open-crypto-broker/crypto-broker-server/internal/gen/cryptobroker/v1"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
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

	if err := validateCertificateSignKeySource(req.GetKeySource()); err != nil {
		return err
	}

	single := req.GetKeySource().GetSingle()
	caCert := req.GetCaCert()
	if single.GetKeyId() != "" {
		if caCert != "" {
			return invalidArg("caCert", "must be empty when keySource.single.keyId is set")
		}
		if err := validateKMSConfiguration(single, req.GetProfile()); err != nil {
			return err
		}
	} else {
		if caCert == "" {
			return invalidArg("caCert", "required")
		}
		if err := checkMaxLen("caCert", len(caCert), maxCACertBytes); err != nil {
			return err
		}
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

func validateSignDataRequest(req *pb.SignDataRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	if err := validateProfileName(req.GetProfile()); err != nil {
		return err
	}
	if err := validateSignKeySource(req.GetKeySource()); err != nil {
		return err
	}
	if err := checkMaxLen("input", len(req.GetInput()), maxSigningDataBytes); err != nil {
		return err
	}
	if req.GetSignatureFormat() == pb.SignatureFormat_SIGNATURE_FORMAT_CMS {
		return invalidArg("signatureFormat", "SIGNATURE_CMS is not currently supported")
	}
	return validateMetadata(req.GetMetadata())
}

func validateVerifyDataRequest(req *pb.VerifyDataRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	if err := validateProfileName(req.GetProfile()); err != nil {
		return err
	}
	if err := validateSignKeySource(req.GetKeySource()); err != nil {
		return err
	}
	if err := checkMaxLen("input", len(req.GetInput()), maxSigningDataBytes); err != nil {
		return err
	}
	if len(req.GetSignature()) == 0 {
		return invalidArg("signature", "required")
	}
	if err := checkMaxLen("signature", len(req.GetSignature()), maxSignatureBytes); err != nil {
		return err
	}
	if req.GetSignatureFormat() == pb.SignatureFormat_SIGNATURE_FORMAT_CMS {
		return invalidArg("signatureFormat", "SIGNATURE_CMS is not currently supported")
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
	return checkMaxLen("keySource.keyId", len(keySource.GetKeyId()), maxEncryptionKeyIDLen)
}

func validateSignKeySource(keySource *pb.SignKeySource) error {
	if keySource == nil || keySource.GetSource() == nil {
		return invalidArg("keySource", "required")
	}
	if keySource.GetComponentKeys() != nil {
		return invalidArg("keySource.componentKeys", "hybrid signing is not currently supported")
	}
	single := keySource.GetSingle()
	if single == nil || single.GetSource() == nil {
		return invalidArg("keySource.single", "required")
	}
	if len(single.GetRawKey()) == 0 {
		if single.GetKeyId() != "" {
			return invalidArg("keySource.single.keyId", "KMS-backed signing is not currently supported")
		}
		return invalidArg("keySource.single.rawKey", "required")
	}
	return checkMaxLen("keySource.single.rawKey", len(single.GetRawKey()), maxSigningKeyBytes)
}

func validateCertificateSignKeySource(keySource *pb.SignKeySource) error {
	if keySource == nil || keySource.GetSource() == nil {
		return invalidArg("keySource", "required")
	}

	if keySource.GetComponentKeys() != nil {
		return invalidArg("keySource.componentKeys", "hybrid signing is not currently supported")
	}

	single := keySource.GetSingle()
	if single == nil || single.GetSource() == nil {
		return invalidArg("keySource.single", "required")
	}

	rawKey := single.GetRawKey()
	if rawKey != nil {
		if len(rawKey) == 0 {
			return invalidArg("keySource.single.rawKey", "required")
		}
		return checkMaxLen("keySource.single.rawKey", len(rawKey), maxCAPrivateKeyBytes)
	}

	if single.GetKeyId() == "" {
		return invalidArg("keySource.single.keyId", "required")
	}
	return checkMaxLen("keySource.single.keyId", len(single.GetKeyId()), maxEncryptionKeyIDLen)
}

func validateKMSConfiguration(keySource *pb.KeySource, profileName string) error {
	keyID := keySource.GetKeyId()
	if keyID == "" {
		return nil
	}

	configuredProfile, err := profile.Retrieve(profileName)

	if err != nil {
		return err
	}

	if !configuredProfile.KMS.Configured() {
		return status.Error(codes.FailedPrecondition, "KMS is disabled or not configured")
	}

	return nil
}
