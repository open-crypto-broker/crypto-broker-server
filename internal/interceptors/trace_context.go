package interceptors

import (
	"context"

	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
)

// UnaryRemoteTraceInterceptor links the incoming context to the client trace when
// metadata.traceContext carries valid trace/span IDs. Register before correlation and logging
// interceptors so handlers and request logs see the propagated trace.
func UnaryRemoteTraceInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		return handler(ContextWithRemoteTraceFromProtoRequest(ctx, req), req)
	}
}

// ContextWithRemoteTraceFromProtoRequest links ctx to the client trace when
// metadata.traceContext carries valid W3C hex traceId and spanId. Server spans
// created with tracer.Start(ctx, ...) then become children of that remote span.
func ContextWithRemoteTraceFromProtoRequest(ctx context.Context, req any) context.Context {
	tc := traceContextFromRequest(req)
	if tc == nil {
		return ctx
	}
	traceID, err := trace.TraceIDFromHex(tc.GetTraceId())
	if err != nil {
		return ctx
	}
	spanID, err := trace.SpanIDFromHex(tc.GetSpanId())
	if err != nil {
		return ctx
	}
	remoteSpanContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    traceID,
		SpanID:     spanID,
		TraceFlags: trace.FlagsSampled,
		Remote:     true,
	})
	return trace.ContextWithRemoteSpanContext(ctx, remoteSpanContext)
}

func traceContextFromRequest(req any) *pb.TraceContext {
	switch r := req.(type) {
	case *pb.HashRequest:
		return traceContextFromMetadata(r.GetMetadata())
	case *pb.SignRequest:
		return traceContextFromMetadata(r.GetMetadata())
	case *pb.BenchmarkRequest:
		return traceContextFromMetadata(r.GetMetadata())
	case *pb.FakeEndpointRequest:
		return traceContextFromMetadata(r.GetMetadata())
	default:
		return nil
	}
}

func traceContextFromMetadata(m *pb.Metadata) *pb.TraceContext {
	if m == nil {
		return nil
	}
	return m.GetTraceContext()
}
