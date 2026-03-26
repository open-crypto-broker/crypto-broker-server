package procedure

import (
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestNewFakeEndpoint(t *testing.T) {
	p := NewFakeEndpoint()
	if p == nil {
		t.Fatalf("expected non-nil")
	}
}

func TestFakeEndpoint_Execute(t *testing.T) {
	p := NewFakeEndpoint()
	req := &protobuf.FakeEndpointRequest{}

	for i := 1; i <= 4; i++ {
		_, err := p.Execute(req)
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("call %d: code = %v, want %v (err=%v)", i, status.Code(err), codes.Unavailable, err)
		}
	}

	resp, err := p.Execute(req)
	if err != nil {
		t.Fatalf("call 5: expected success, got err: %v", err)
	}
	if resp.Message == "" {
		t.Fatalf("expected non-empty message")
	}
}
