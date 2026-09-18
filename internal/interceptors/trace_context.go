package interceptors

import (
	"context"

	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// UnaryRemoteTraceInterceptor keeps a valid W3C transport trace context. When
// transport propagation is absent or invalid, it uses metadata.traceContext as a
// fallback. Register before correlation and logging interceptors so handlers and
// request logs see the propagated trace.
func UnaryRemoteTraceInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if hasValidTransportTraceContext(ctx) {
			return handler(ctx, req)
		}
		return handler(ContextWithRemoteTraceFromProtoRequest(ctx, req), req)
	}
}

func hasValidTransportTraceContext(ctx context.Context) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	traceparent := md.Get("traceparent")
	if len(traceparent) == 0 {
		return false
	}
	extracted := propagation.TraceContext{}.Extract(
		context.Background(),
		propagation.MapCarrier{"traceparent": traceparent[0]},
	)
	return trace.SpanContextFromContext(extracted).IsValid()
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
	case *pb.HashDataRequest:
		return traceContextFromMetadata(r.GetMetadata())
	case *pb.SignCertificateRequest:
		return traceContextFromMetadata(r.GetMetadata())
	case *pb.BenchmarkRequest:
		return traceContextFromMetadata(r.GetMetadata())
	case *pb.FakeEndpointRequest:
		return traceContextFromMetadata(r.GetMetadata())
	case *pb.EncryptDataRequest:
		return traceContextFromMetadata(r.GetMetadata())
	case *pb.DecryptDataRequest:
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
