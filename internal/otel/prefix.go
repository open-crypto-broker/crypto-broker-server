package otel

import (
	"context"
	"strings"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// NewResource returns the resource shared by all Crypto Broker telemetry signals.
func NewResource(ctx context.Context) (*resource.Resource, error) {
	return resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(serviceVersion),
			semconv.ServiceNamespaceKey.String("crypto-broker"),
		),
	)
}

type prefixedMetricExporter struct {
	sdkmetric.Exporter
}

func (e prefixedMetricExporter) Export(ctx context.Context, metrics *metricdata.ResourceMetrics) error {
	for i := range metrics.ScopeMetrics {
		for j := range metrics.ScopeMetrics[i].Metrics {
			metrics.ScopeMetrics[i].Metrics[j].Name = TelemetryName(metrics.ScopeMetrics[i].Metrics[j].Name)
		}
	}

	return e.Exporter.Export(ctx, metrics)
}

type prefixSpanProcessor struct{}

func (prefixSpanProcessor) OnStart(_ context.Context, span sdktrace.ReadWriteSpan) {
	span.SetName(TelemetryName(span.Name()))
}

func (prefixSpanProcessor) OnEnd(sdktrace.ReadOnlySpan) {}

func (prefixSpanProcessor) Shutdown(context.Context) error {
	return nil
}

func (prefixSpanProcessor) ForceFlush(context.Context) error {
	return nil
}

// TelemetryName prefixes a metric or span name configured with OTEL_PREFIX.
func TelemetryName(name string) string {
	if prefix == "" || name == "" {
		return name
	}

	if strings.HasPrefix(name, prefix) {
		return name
	}

	return prefix + name
}
