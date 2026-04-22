package procedure

import (
	"fmt"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// argumentError wraps a standard Go error and maps it to a gRPC InvalidArgument status.
type argumentError struct {
	err error
}

func (e *argumentError) Error() string {
	return e.err.Error()
}

// Unwrap exposes the wrapped error for errors.Is / errors.As support.
func (e *argumentError) Unwrap() error {
	return e.err
}

// GRPCStatus converts this error into a gRPC status with code InvalidArgument (3).
func (e *argumentError) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.err.Error())
}

// ArgumentError creates a new argumentError using fmt-style formatting.
// Supports %w for error wrapping.
func ArgumentError(format string, args ...any) error {
	return &argumentError{
		err: fmt.Errorf(format, args...),
	}
}
