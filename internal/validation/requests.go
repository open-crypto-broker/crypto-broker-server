package validation

import (
	"fmt"

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

func validateProfile(profileName string) error {
	if profileName == "" {
		return invalidArg("profile", "required")
	}
	if err := checkMaxLen("profile", len(profileName), MaxProfileLen); err != nil {
		return err
	}
	if _, err := profile.Retrieve(profileName); err != nil {
		return invalidArg("profile", "unknown")
	}
	return nil
}

func validateMetadata(m *pb.Metadata) error {
	if m == nil {
		return nil
	}
	if err := checkMaxLen("metadata.id", len(m.GetId()), MaxMetadataIdLen); err != nil {
		return err
	}
	if err := checkMaxLen("metadata.createdAt", len(m.GetCreatedAt()), MaxMetadataCreatedAtLen); err != nil {
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
		{"metadata.traceContext.traceId", tc.GetTraceId(), MaxTraceIdLen},
		{"metadata.traceContext.spanId", tc.GetSpanId(), MaxSpanIdLen},
		{"metadata.traceContext.traceFlags", tc.GetTraceFlags(), MaxTraceFlagsLen},
		{"metadata.traceContext.traceState", tc.GetTraceState(), MaxTraceStateLen},
		{"metadata.traceContext.correlationId", tc.GetCorrelationId(), MaxCorrelationIdLen},
	}
	for _, f := range fields {
		if err := checkMaxLen(f.name, len(f.value), f.max); err != nil {
			return err
		}
	}
	return nil
}

func ValidateHashRequest(req *pb.HashRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	if err := validateProfile(req.GetProfile()); err != nil {
		return err
	}
	// Empty hash input is allowed.
	if err := checkMaxLen("input", len(req.GetInput()), MaxHashInputBytes); err != nil {
		return err
	}
	return validateMetadata(req.GetMetadata())
}

func ValidateSignRequest(req *pb.SignRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	if err := validateProfile(req.GetProfile()); err != nil {
		return err
	}

	csr := req.GetCsr()
	if csr == "" {
		return invalidArg("csr", "required")
	}
	if err := checkMaxLen("csr", len(csr), MaxCSRBytes); err != nil {
		return err
	}

	caKey := req.GetCaPrivateKey()
	if caKey == "" {
		return invalidArg("caPrivateKey", "required")
	}
	if err := checkMaxLen("caPrivateKey", len(caKey), MaxCAPrivateKeyBytes); err != nil {
		return err
	}

	caCert := req.GetCaCert()
	if caCert == "" {
		return invalidArg("caCert", "required")
	}
	if err := checkMaxLen("caCert", len(caCert), MaxCACertBytes); err != nil {
		return err
	}

	if err := checkMaxLen("subject", len(req.GetSubject()), MaxSubjectLen); err != nil {
		return err
	}

	crl := req.GetCrlDistributionPoints()
	if len(crl) > MaxCRLDistributionPoints {
		return invalidArg("crlDistributionPoints", fmt.Sprintf("too many entries (max %d)", MaxCRLDistributionPoints))
	}
	for i, v := range crl {
		if len(v) > MaxCRLDistributionPointLen {
			return invalidArg(fmt.Sprintf("crlDistributionPoints[%d]", i), fmt.Sprintf("too large (max %d)", MaxCRLDistributionPointLen))
		}
	}

	return validateMetadata(req.GetMetadata())
}

func ValidateBenchmarkRequest(req *pb.BenchmarkRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	return validateMetadata(req.GetMetadata())
}

func ValidateFakeEndpointRequest(req *pb.FakeEndpointRequest) error {
	if req == nil {
		return invalidArg("request", "required")
	}
	return validateMetadata(req.GetMetadata())
}
