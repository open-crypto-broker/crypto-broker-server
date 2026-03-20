// Package grpcmw provides gRPC server middleware helpers.
package grpcmw

import (
	"context"

	"google.golang.org/grpc"
)

type correlationCtxKey struct{}

// UnaryCorrelationInterceptor attaches metadata.traceContext.correlationId to ctx for grpc
// access logs. Register after UnaryRemoteTraceInterceptor so propagation order matches cmd/server.
func UnaryCorrelationInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(withCorrelationID(ctx, CorrelationIDFromProtoRequest(req)), req)
	}
}

func withCorrelationID(ctx context.Context, id string) context.Context {
	if id == "" {
		return ctx
	}
	return context.WithValue(ctx, correlationCtxKey{}, id)
}

// CorrelationIDFromContext returns the correlation ID attached by UnaryCorrelationInterceptor, or "".
func CorrelationIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(correlationCtxKey{}).(string)
	return v
}

// CorrelationIDFromProtoRequest returns metadata.traceContext.correlationId when present.
func CorrelationIDFromProtoRequest(req any) string {
	tc := traceContextFromRequest(req)
	if tc == nil {
		return ""
	}
	return tc.GetCorrelationId()
}
