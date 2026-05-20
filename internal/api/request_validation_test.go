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
			name: "hash",
			validate: func() error {
				return validateHashRequest(nil)
			},
		},
		{
			name: "sign",
			validate: func() error {
				return validateSignRequest(nil)
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
		req       *pb.HashRequest
		wantField string
	}{
		{
			name: "allows empty input",
			req:  &pb.HashRequest{Profile: "Default", Input: nil},
		},
		{
			name: "allows unknown profile name",
			req:  &pb.HashRequest{Profile: "DoesNotExist", Input: []byte("x")},
		},
		{
			name:      "rejects missing profile",
			req:       &pb.HashRequest{Input: []byte("x")},
			wantField: "profile",
		},
		{
			name:      "rejects oversized profile",
			req:       &pb.HashRequest{Profile: strings.Repeat("A", profile.MaxNameLen+1)},
			wantField: "profile",
		},
		{
			name:      "rejects oversized input",
			req:       &pb.HashRequest{Profile: "Default", Input: make([]byte, maxHashInputBytes+1)},
			wantField: "input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHashRequest(tt.req)
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
		mutate    func(*pb.SignRequest)
		wantField string
	}{
		{
			name: "profile",
			mutate: func(req *pb.SignRequest) {
				req.Profile = ""
			},
			wantField: "profile",
		},
		{
			name: "csr",
			mutate: func(req *pb.SignRequest) {
				req.Csr = ""
			},
			wantField: "csr",
		},
		{
			name: "ca private key",
			mutate: func(req *pb.SignRequest) {
				req.CaPrivateKey = ""
			},
			wantField: "caPrivateKey",
		},
		{
			name: "ca cert",
			mutate: func(req *pb.SignRequest) {
				req.CaCert = ""
			},
			wantField: "caCert",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validSignRequest()
			tt.mutate(req)

			assertInvalidArgument(t, validateSignRequest(req), tt.wantField)
		})
	}
}

func TestValidateSignRequest_RejectsSizeLimits(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*pb.SignRequest)
		wantField string
	}{
		{
			name: "profile",
			mutate: func(req *pb.SignRequest) {
				req.Profile = strings.Repeat("A", profile.MaxNameLen+1)
			},
			wantField: "profile",
		},
		{
			name: "csr",
			mutate: func(req *pb.SignRequest) {
				req.Csr = strings.Repeat("A", maxCSRBytes+1)
			},
			wantField: "csr",
		},
		{
			name: "ca private key",
			mutate: func(req *pb.SignRequest) {
				req.CaPrivateKey = strings.Repeat("A", maxCAPrivateKeyBytes+1)
			},
			wantField: "caPrivateKey",
		},
		{
			name: "ca cert",
			mutate: func(req *pb.SignRequest) {
				req.CaCert = strings.Repeat("A", maxCACertBytes+1)
			},
			wantField: "caCert",
		},
		{
			name: "subject",
			mutate: func(req *pb.SignRequest) {
				req.Subject = stringPtr(strings.Repeat("A", maxSubjectLen+1))
			},
			wantField: "subject",
		},
		{
			name: "too many crl distribution points",
			mutate: func(req *pb.SignRequest) {
				req.CrlDistributionPoints = make([]string, maxCRLDistributionPoints+1)
			},
			wantField: "crlDistributionPoints",
		},
		{
			name: "oversized crl distribution point",
			mutate: func(req *pb.SignRequest) {
				req.CrlDistributionPoints = []string{strings.Repeat("A", maxCRLDistributionPointLen+1)}
			},
			wantField: "crlDistributionPoints[0]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validSignRequest()
			tt.mutate(req)

			assertInvalidArgument(t, validateSignRequest(req), tt.wantField)
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
	req.CrlDistributionPoints = make([]string, maxCRLDistributionPoints)
	for i := range req.CrlDistributionPoints {
		req.CrlDistributionPoints[i] = strings.Repeat("A", maxCRLDistributionPointLen)
	}

	assertNoError(t, validateSignRequest(req))
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
			metadata: &pb.Metadata{Id: strings.Repeat("A", maxMetadataIdLen), CreatedAt: strings.Repeat("A", maxMetadataCreatedAtLen)},
		},
		{
			name:      "rejects oversized id",
			metadata:  &pb.Metadata{Id: strings.Repeat("A", maxMetadataIdLen+1)},
			wantField: "metadata.id",
		},
		{
			name:      "rejects oversized created at",
			metadata:  &pb.Metadata{CreatedAt: strings.Repeat("A", maxMetadataCreatedAtLen+1)},
			wantField: "metadata.createdAt",
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

func validSignRequest() *pb.SignRequest {
	return &pb.SignRequest{
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
