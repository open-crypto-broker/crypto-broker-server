package interceptors

import (
	"context"
	"errors"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestUnaryCorrelationInterceptor(t *testing.T) {
	interceptor := UnaryCorrelationInterceptor()

	req := &protobuf.HashDataRequest{
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
	req := &protobuf.SignCertificateRequest{
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
	req := &protobuf.HashDataRequest{
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

func TestUnaryRemoteTraceInterceptorFallsBackForInvalidTransportContext(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("traceparent", "invalid"))
	req := &protobuf.HashDataRequest{
		Metadata: &protobuf.Metadata{
			TraceContext: &protobuf.TraceContext{
				TraceId: "0af7651916cd43dd8448eb211c80319c",
				SpanId:  "b9c7c989f97918e1",
			},
		},
	}

	_, err := UnaryRemoteTraceInterceptor()(ctx, req, &grpc.UnaryServerInfo{}, func(ctx context.Context, _ any) (any, error) {
		got := trace.SpanContextFromContext(ctx)
		if !got.IsValid() || !got.IsRemote() {
			t.Fatalf("span context = %s/%s, want valid remote protobuf context", got.TraceID(), got.SpanID())
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

func TestUnaryRequestLifecycleObservabilityInterceptor(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(recorder),
	)
	t.Cleanup(func() {
		if err := provider.Shutdown(context.Background()); err != nil {
			t.Errorf("shutdown tracer provider: %v", err)
		}
	})

	interceptor := unaryRequestLifecycleObservabilityInterceptor(provider.Tracer("test"), false)
	_, err := interceptor(context.Background(), &protobuf.HashDataRequest{}, &grpc.UnaryServerInfo{
		FullMethod: "/CryptoBroker.CryptoGrpc/HashData",
	}, func(context.Context, any) (any, error) {
		return nil, errors.New("hash failed")
	})
	if err == nil {
		t.Fatal("expected interceptor to return handler error")
	}

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("ended spans = %d, want 1", len(spans))
	}
	span := spans[0]
	if span.Name() != "/CryptoBroker.CryptoGrpc/HashData" {
		t.Errorf("span name = %q", span.Name())
	}
	if span.SpanKind() != trace.SpanKindInternal {
		t.Errorf("span kind = %s, want internal", span.SpanKind())
	}
	if span.Status().Code != codes.Error {
		t.Errorf("span status = %s, want error", span.Status().Code)
	}
	if !hasAttribute(span.Attributes(), "rpc.method", "HashData") {
		t.Errorf("span does not include rpc.method=HashData")
	}
}

func hasAttribute(attributes []attribute.KeyValue, key, value string) bool {
	for _, attribute := range attributes {
		if string(attribute.Key) == key && attribute.Value.AsString() == value {
			return true
		}
	}
	return false
}
