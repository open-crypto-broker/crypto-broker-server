package api

import (
	"strings"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidateRequests_RejectNil(t *testing.T) {
	tests := []struct {
		name     string
		validate func() error
	}{
		{
			name: "hash data",
			validate: func() error {
				return validateHashDataRequest(nil)
			},
		},
		{
			name: "sign certificate",
			validate: func() error {
				return validateSignCertificateRequest(nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertInvalidArgument(t, tt.validate(), "request")
		})
	}
}

func TestValidateHashRequest(t *testing.T) {
	tests := []struct {
		name      string
		req       *pb.HashDataRequest
		wantField string
	}{
		{
			name: "allows empty input",
			req:  &pb.HashDataRequest{Profile: "Default", Input: nil},
		},
		{
			name: "allows unknown profile name",
			req:  &pb.HashDataRequest{Profile: "DoesNotExist", Input: []byte("x")},
		},
		{
			name:      "rejects missing profile",
			req:       &pb.HashDataRequest{Input: []byte("x")},
			wantField: "profile",
		},
		{
			name:      "rejects oversized profile",
			req:       &pb.HashDataRequest{Profile: strings.Repeat("A", profile.MaxNameLen+1)},
			wantField: "profile",
		},
		{
			name:      "rejects oversized input",
			req:       &pb.HashDataRequest{Profile: "Default", Input: make([]byte, maxHashInputBytes+1)},
			wantField: "input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHashDataRequest(tt.req)
			if tt.wantField == "" {
				assertNoError(t, err)
				return
			}
			assertInvalidArgument(t, err, tt.wantField)
		})
	}
}

func TestValidateSignRequest_RejectsRequiredFields(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*pb.SignCertificateRequest)
		wantField string
	}{
		{
			name: "profile",
			mutate: func(req *pb.SignCertificateRequest) {
				req.Profile = ""
			},
			wantField: "profile",
		},
		{
			name: "csr",
			mutate: func(req *pb.SignCertificateRequest) {
				req.Csr = ""
			},
			wantField: "csr",
		},
		{
			name: "ca private key",
			mutate: func(req *pb.SignCertificateRequest) {
				req.CaPrivateKey = ""
			},
			wantField: "caPrivateKey",
		},
		{
			name: "ca cert",
			mutate: func(req *pb.SignCertificateRequest) {
				req.CaCert = ""
			},
			wantField: "caCert",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validSignRequest()
			tt.mutate(req)

			assertInvalidArgument(t, validateSignCertificateRequest(req), tt.wantField)
		})
	}
}

func TestValidateSignRequest_RejectsSizeLimits(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*pb.SignCertificateRequest)
		wantField string
	}{
		{
			name: "profile",
			mutate: func(req *pb.SignCertificateRequest) {
				req.Profile = strings.Repeat("A", profile.MaxNameLen+1)
			},
			wantField: "profile",
		},
		{
			name: "csr",
			mutate: func(req *pb.SignCertificateRequest) {
				req.Csr = strings.Repeat("A", maxCSRBytes+1)
			},
			wantField: "csr",
		},
		{
			name: "ca private key",
			mutate: func(req *pb.SignCertificateRequest) {
				req.CaPrivateKey = strings.Repeat("A", maxCAPrivateKeyBytes+1)
			},
			wantField: "caPrivateKey",
		},
		{
			name: "ca cert",
			mutate: func(req *pb.SignCertificateRequest) {
				req.CaCert = strings.Repeat("A", maxCACertBytes+1)
			},
			wantField: "caCert",
		},
		{
			name: "subject",
			mutate: func(req *pb.SignCertificateRequest) {
				req.Subject = stringPtr(strings.Repeat("A", maxSubjectLen+1))
			},
			wantField: "subject",
		},
		{
			name: "too many crl distribution points",
			mutate: func(req *pb.SignCertificateRequest) {
				req.CrlDistributionPoints = make([]string, maxCRLDistributionPoints+1)
			},
			wantField: "crlDistributionPoints",
		},
		{
			name: "oversized crl distribution point",
			mutate: func(req *pb.SignCertificateRequest) {
				prefix := "https://example.com/"
				req.CrlDistributionPoints = []string{prefix + strings.Repeat("a", maxCRLDistributionPointLen+1)}
			},
			wantField: "crlDistributionPoints[0]",
		},
		{
			name: "invalid crl distribution URL",
			mutate: func(req *pb.SignCertificateRequest) {
				req.CrlDistributionPoints = []string{"https://google.com", "google.com"}
			},
			wantField: "crlDistributionPoints[1]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validSignRequest()
			tt.mutate(req)

			assertInvalidArgument(t, validateSignCertificateRequest(req), tt.wantField)
		})
	}
}

func TestValidateSignRequest_AllowsValidBoundaryRequest(t *testing.T) {
	subject := strings.Repeat("A", maxSubjectLen)
	req := validSignRequest()
	req.Profile = strings.Repeat("A", profile.MaxNameLen)
	req.Csr = strings.Repeat("A", maxCSRBytes)
	req.CaPrivateKey = strings.Repeat("A", maxCAPrivateKeyBytes)
	req.CaCert = strings.Repeat("A", maxCACertBytes)
	req.Subject = &subject

	crlDistributionPoints := make([]string, maxCRLDistributionPoints)

	prefix := "https://example.com/"
	url := prefix + strings.Repeat("A", maxCRLDistributionPointLen-len(prefix))

	for i := range crlDistributionPoints {
		crlDistributionPoints[i] = url
	}

	req.CrlDistributionPoints = crlDistributionPoints
	assertNoError(t, validateSignCertificateRequest(req))
}

func TestValidateMetadata(t *testing.T) {
	tests := []struct {
		name      string
		metadata  *pb.Metadata
		wantField string
	}{
		{
			name: "allows nil",
		},
		{
			name:     "allows metadata without trace context",
			metadata: &pb.Metadata{Id: strings.Repeat("A", maxMetadataIdLen)},
		},
		{
			name:     "allows uuid-shaped id and correlation id",
			metadata: &pb.Metadata{Id: "550e8400-e29b-41d4-a716-446655440000", TraceContext: &pb.TraceContext{CorrelationId: "6ba7b810-9dad-11d1-80b4-00c04fd430c8"}},
		},
		{
			name:      "rejects oversized id",
			metadata:  &pb.Metadata{Id: strings.Repeat("A", maxMetadataIdLen+1)},
			wantField: "metadata.id",
		},
		{
			name:      "rejects id with control character",
			metadata:  &pb.Metadata{Id: "id\x00"},
			wantField: "metadata.id",
		},
		{
			name:      "rejects id with newline",
			metadata:  &pb.Metadata{Id: "id\n"},
			wantField: "metadata.id",
		},
		{
			name:      "rejects id with tab",
			metadata:  &pb.Metadata{Id: "id\t"},
			wantField: "metadata.id",
		},
		{
			name:      "rejects id with non-ascii",
			metadata:  &pb.Metadata{Id: "café"},
			wantField: "metadata.id",
		},
		{
			name:      "rejects oversized trace id",
			metadata:  &pb.Metadata{TraceContext: &pb.TraceContext{TraceId: strings.Repeat("A", maxTraceIdLen+1)}},
			wantField: "metadata.traceContext.traceId",
		},
		{
			name:      "rejects oversized span id",
			metadata:  &pb.Metadata{TraceContext: &pb.TraceContext{SpanId: strings.Repeat("A", maxSpanIdLen+1)}},
			wantField: "metadata.traceContext.spanId",
		},
		{
			name:      "rejects oversized trace flags",
			metadata:  &pb.Metadata{TraceContext: &pb.TraceContext{TraceFlags: strings.Repeat("A", maxTraceFlagsLen+1)}},
			wantField: "metadata.traceContext.traceFlags",
		},
		{
			name:      "rejects oversized trace state",
			metadata:  &pb.Metadata{TraceContext: &pb.TraceContext{TraceState: strings.Repeat("A", maxTraceStateLen+1)}},
			wantField: "metadata.traceContext.traceState",
		},
		{
			name:      "rejects oversized correlation id",
			metadata:  &pb.Metadata{TraceContext: &pb.TraceContext{CorrelationId: strings.Repeat("A", maxCorrelationIdLen+1)}},
			wantField: "metadata.traceContext.correlationId",
		},
		{
			name:      "rejects correlation id with control character",
			metadata:  &pb.Metadata{TraceContext: &pb.TraceContext{CorrelationId: "corr\x1b"}},
			wantField: "metadata.traceContext.correlationId",
		},
		{
			name:      "rejects correlation id with newline",
			metadata:  &pb.Metadata{TraceContext: &pb.TraceContext{CorrelationId: "corr\n"}},
			wantField: "metadata.traceContext.correlationId",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMetadata(tt.metadata)
			if tt.wantField == "" {
				assertNoError(t, err)
				return
			}
			assertInvalidArgument(t, err, tt.wantField)
		})
	}
}

func validSignRequest() *pb.SignCertificateRequest {
	return &pb.SignCertificateRequest{
		Profile:      "Default",
		Csr:          "csr",
		CaPrivateKey: "key",
		CaCert:       "cert",
	}
}

func stringPtr(s string) *string {
	return &s
}

func assertNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func assertInvalidArgument(t *testing.T, err error, field string) {
	t.Helper()
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v for error %v", status.Code(err), err)
	}
	if !strings.Contains(err.Error(), field) {
		t.Fatalf("expected %q field in error, got %q", field, err.Error())
	}
}
