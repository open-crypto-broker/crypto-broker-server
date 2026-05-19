package api

import (
	"fmt"

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

func validateProfileName(profileName string) error {
	if profileName == "" {
		return invalidArg("profile", "required")
	}
	return checkMaxLen("profile", len(profileName), maxProfileLen)
}

func validateMetadata(m *pb.Metadata) error {
	if m == nil {
		return nil
	}
	if err := checkMaxLen("metadata.id", len(m.GetId()), maxMetadataIdLen); err != nil {
		return err
	}
	if err := checkMaxLen("metadata.createdAt", len(m.GetCreatedAt()), maxMetadataCreatedAtLen); err != nil {
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
		{"metadata.traceContext.correlationId", tc.GetCorrelationId(), maxCorrelationIdLen},
	}
	for _, f := range fields {
		if err := checkMaxLen(f.name, len(f.value), f.max); err != nil {
			return err
		}
	}
	return nil
}

func validateHashRequest(req *pb.HashRequest) error {
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

func validateSignRequest(req *pb.SignRequest) error {
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
	}

	return validateMetadata(req.GetMetadata())
}
