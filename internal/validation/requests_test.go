package validation

import (
	"strings"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestValidateHashRequest_AllowsEmptyInput(t *testing.T) {
	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles: %v", err)
	}

	err := ValidateHashRequest(&pb.HashRequest{Profile: "Default", Input: nil})
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestValidateHashRequest_RejectsOversizeInput(t *testing.T) {
	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles: %v", err)
	}

	big := make([]byte, MaxHashInputBytes+1)
	err := ValidateHashRequest(&pb.HashRequest{Profile: "Default", Input: big})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
	if !strings.Contains(err.Error(), "input") {
		t.Fatalf("expected error to mention input, got %v", err)
	}
}

func TestValidateHashRequest_RejectsUnknownProfile(t *testing.T) {
	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles: %v", err)
	}

	err := ValidateHashRequest(&pb.HashRequest{Profile: "DoesNotExist", Input: []byte("x")})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
	if !strings.Contains(err.Error(), "profile") {
		t.Fatalf("expected error to mention profile, got %v", err)
	}
}

func TestValidateSignRequest_RejectsOversizeCSR(t *testing.T) {
	if err := profile.LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatalf("could not load profiles: %v", err)
	}

	csr := strings.Repeat("A", MaxCSRBytes+1)
	key := "k"
	cert := "c"
	err := ValidateSignRequest(&pb.SignRequest{Profile: "Default", Csr: csr, CaPrivateKey: key, CaCert: cert})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", status.Code(err))
	}
}
