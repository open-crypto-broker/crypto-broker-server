package procedure

import (
	"sync"

	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FakeEndpoint defines the procedure for the fake endpoint
type FakeEndpoint struct {
	callCount int
	mu        sync.Mutex
}

func NewFakeEndpoint() *FakeEndpoint {
	return &FakeEndpoint{
		callCount: 0,
	}
}

// Execute executes the fake endpoint procedure
func (procedure *FakeEndpoint) Execute(req *protobuf.FakeEndpointRequest) (*protobuf.FakeEndpointResponse, error) {
	procedure.mu.Lock()
	defer procedure.mu.Unlock()

	procedure.callCount++

	if procedure.callCount%5 != 0 {
		return nil, status.Error(codes.Unavailable, "fake endpoint is temporarily down")
	}

	return &protobuf.FakeEndpointResponse{
		Message:  "Fake endpoint called successfully",
		Metadata: req.Metadata,
	}, nil
}
