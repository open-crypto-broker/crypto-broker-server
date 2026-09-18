package main

import (
	"context"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/interceptors"
	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
)

func TestGRPCServerStatsHandlerPreservesTransportTraceTopology(t *testing.T) {
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

	const (
		clientTraceID = "0af7651916cd43dd8448eb211c80319c"
		clientSpanID  = "1111111111111111"
		method        = "/CryptoBroker.CryptoGrpc/HashData"
	)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"traceparent", "00-"+clientTraceID+"-"+clientSpanID+"-01",
	))
	handler := newGRPCServerStatsHandler(otelgrpc.WithTracerProvider(provider))
	ctx = handler.TagRPC(ctx, &stats.RPCTagInfo{FullMethodName: method})
	handler.HandleRPC(ctx, &stats.Begin{})

	req := &pb.HashDataRequest{Metadata: &pb.Metadata{TraceContext: &pb.TraceContext{
		TraceId: "22222222222222222222222222222222",
		SpanId:  "3333333333333333",
	}}}
	info := &grpc.UnaryServerInfo{FullMethod: method}
	_, err := interceptors.UnaryRemoteTraceInterceptor()(ctx, req, info, func(ctx context.Context, req any) (any, error) {
		_, lifecycleSpan := provider.Tracer("test").Start(ctx, "lifecycle", trace.WithSpanKind(trace.SpanKindInternal))
		lifecycleSpan.End()
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("interceptor chain returned error: %v", err)
	}
	handler.HandleRPC(ctx, &stats.End{})

	spans := recorder.Ended()
	if len(spans) != 2 {
		t.Fatalf("ended spans = %d, want 2", len(spans))
	}
	var serverSpan, lifecycleSpan sdktrace.ReadOnlySpan
	for _, span := range spans {
		switch span.SpanKind() {
		case trace.SpanKindServer:
			serverSpan = span
		case trace.SpanKindInternal:
			lifecycleSpan = span
		default:
			continue
		}
	}
	if serverSpan == nil || lifecycleSpan == nil {
		t.Fatalf("span kinds = %s, %s; want server and internal", spans[0].SpanKind(), spans[1].SpanKind())
	}
	if got := serverSpan.SpanContext().TraceID().String(); got != clientTraceID {
		t.Errorf("server trace ID = %s, want %s", got, clientTraceID)
	}
	if got := serverSpan.Parent().SpanID().String(); got != clientSpanID {
		t.Errorf("server parent span ID = %s, want %s", got, clientSpanID)
	}
	if !serverSpan.Parent().IsRemote() {
		t.Error("server parent is not remote")
	}
	if got := lifecycleSpan.Parent().SpanID(); got != serverSpan.SpanContext().SpanID() {
		t.Errorf("lifecycle parent span ID = %s, want server span ID %s", got, serverSpan.SpanContext().SpanID())
	}
}
