package interceptors

import (
	"context"
	"path"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

// UnaryRequestLifecycleObservabilityInterceptor records shared request telemetry for unary RPCs.
func UnaryRequestLifecycleObservabilityInterceptor(metricsEnabled bool) grpc.UnaryServerInterceptor {
	return unaryRequestLifecycleObservabilityInterceptor(otel.GetGlobalTracer(), metricsEnabled)
}

func unaryRequestLifecycleObservabilityInterceptor(tracer trace.Tracer, metricsEnabled bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		method := path.Base(info.FullMethod)
		ctx, span := tracer.Start(ctx, info.FullMethod,
			trace.WithSpanKind(trace.SpanKindInternal),
			trace.WithAttributes(otel.AttributeRpcMethod.String(method)),
		)
		defer span.End()

		start := time.Now()
		response, err := handler(ctx, req)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, err.Error())
		} else {
			span.SetStatus(codes.Ok, "RPC completed successfully")
		}

		if metricsEnabled {
			recordRequestMetrics(ctx, method, err, time.Since(start))
		}

		return response, err
	}
}

func recordRequestMetrics(ctx context.Context, method string, err error, duration time.Duration) {
	statusValue := otel.StatusSuccess
	if err != nil {
		statusValue = otel.StatusError
		otel.OperationsErrorsTotal.Add(ctx, 1, metric.WithAttributes(
			attribute.String("rpc_method", method),
			attribute.String("error_type", status.Code(err).String()),
		))
	}

	attributes := metric.WithAttributes(
		attribute.String("rpc_method", method),
		attribute.String("status", statusValue),
	)
	otel.RequestsTotal.Add(ctx, 1, attributes)
	otel.RequestDuration.Record(ctx, duration.Seconds(), attributes)
}
