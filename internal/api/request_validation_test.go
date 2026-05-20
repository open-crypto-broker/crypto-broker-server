package api

import (
	"strings"
	"testing"

	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidateHashRequest_AllowsEmptyInput(t *testing.T) {
	err := validateHashRequest(&pb.HashRequest{Profile: "Default", Input: nil})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestValidateHashRequest_RejectsOversizeInput(t *testing.T) {
	big := make([]byte, maxHashInputBytes+1)

	err := validateHashRequest(&pb.HashRequest{Profile: "Default", Input: big})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
	if !strings.Contains(err.Error(), "input") {
		t.Fatalf("expected input field in error, got %q", err.Error())
	}
}

func TestValidateHashRequest_RejectsMissingProfile(t *testing.T) {
	err := validateHashRequest(&pb.HashRequest{Input: []byte("x")})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Fatalf("expected profile field in error, got %q", err.Error())
	}
}

func TestValidateSignRequest_RejectsOversizeCSR(t *testing.T) {
	csr := strings.Repeat("A", maxCSRBytes+1)
	key := "k"
	cert := "c"

	err := validateSignRequest(&pb.SignRequest{Profile: "Default", Csr: csr, CaPrivateKey: key, CaCert: cert})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
	if !strings.Contains(err.Error(), "csr") {
		t.Fatalf("expected csr field in error, got %q", err.Error())
	}
}
