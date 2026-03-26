package interceptors

import (
	"context"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
)

func TestUnaryCorrelationInterceptor(t *testing.T) {
	interceptor := UnaryCorrelationInterceptor()

	req := &protobuf.HashRequest{
		Metadata: &protobuf.Metadata{
			TraceContext: &protobuf.TraceContext{
				CorrelationId: "corr-123",
			},
		},
	}

	_, err := interceptor(context.Background(), req, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
		if got := CorrelationIDFromContext(ctx); got != "corr-123" {
			t.Fatalf("CorrelationIDFromContext() = %q, want %q", got, "corr-123")
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
}

func TestCorrelationIDFromContext(t *testing.T) {
	if got := CorrelationIDFromContext(context.Background()); got != "" {
		t.Fatalf("CorrelationIDFromContext() = %q, want empty string for plain context", got)
	}
}

func TestCorrelationIDFromProtoRequest(t *testing.T) {
	req := &protobuf.SignRequest{
		Metadata: &protobuf.Metadata{
			TraceContext: &protobuf.TraceContext{
				CorrelationId: "abc-correlation-id",
			},
		},
	}

	got := CorrelationIDFromProtoRequest(req)
	if got != "abc-correlation-id" {
		t.Fatalf("CorrelationIDFromProtoRequest() = %q, want %q", got, "abc-correlation-id")
	}
}

func TestUnaryRemoteTraceInterceptor(t *testing.T) {
	interceptor := UnaryRemoteTraceInterceptor()
	req := &protobuf.HashRequest{
		Metadata: &protobuf.Metadata{
			TraceContext: &protobuf.TraceContext{
				TraceId: "0af7651916cd43dd8448eb211c80319c",
				SpanId:  "b9c7c989f97918e1",
			},
		},
	}

	_, err := interceptor(context.Background(), req, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
		sc := trace.SpanContextFromContext(ctx)
		if !sc.IsValid() {
			t.Fatalf("expected valid span context in handler")
		}
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor returned error: %v", err)
	}
}

func TestContextWithRemoteTraceFromProtoRequest(t *testing.T) {
	req := &protobuf.BenchmarkRequest{
		Metadata: &protobuf.Metadata{
			TraceContext: &protobuf.TraceContext{
				TraceId: "0af7651916cd43dd8448eb211c80319c",
				SpanId:  "b9c7c989f97918e1",
			},
		},
	}

	ctx := ContextWithRemoteTraceFromProtoRequest(context.Background(), req)
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		t.Fatalf("expected valid span context")
	}
	if !sc.IsRemote() {
		t.Fatalf("expected remote span context")
	}
}
