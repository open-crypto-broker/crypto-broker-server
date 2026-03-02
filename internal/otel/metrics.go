package otel

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
	"go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

// MeterProvider holds the OpenTelemetry meter provider
type MeterProvider struct {
	mp *sdkmetric.MeterProvider
}

// GetGlobalMeter returns the global meter for the service
func GetGlobalMeter(serviceName string) metric.Meter {
	return otel.Meter(serviceName)
}

// NewMeterProvider creates and initializes a new OpenTelemetry meter provider
func NewMeterProvider(ctx context.Context, serviceName, serviceVersion string) (*MeterProvider, error) {
	if serviceName == "" {
		ServiceName = os.Getenv(env.OTEL_SERVICE_NAME)
		if ServiceName == "" {
			ServiceName = defaultServiceName
		}
	} else {
		ServiceName = serviceName
	}

	if serviceVersion == "" {
		serviceVersion = os.Getenv(env.OTEL_SERVICE_VERSION)
		if serviceVersion == "" {
			serviceVersion = defaultServiceVersion
		}
	}

	metricsExporter := os.Getenv(env.OTEL_METRICS_EXPORTER)
	if metricsExporter == "" {
		metricsExporter = keyExporterConsole
	}

	if strings.ToLower(strings.TrimSpace(metricsExporter)) == "none" {
		slog.Info("OpenTelemetry metrics disabled by configuration",
			slog.String("exporter", metricsExporter))
		return nil, nil
	}

	// Parse metrics interval
	intervalStr := os.Getenv(env.OTEL_METRICS_INTERVAL)
	if intervalStr == "" {
		intervalStr = "30s"
	}

	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse metrics interval %q: %w", intervalStr, err)
	}

	exporterNames := strings.Split(strings.ToLower(metricsExporter), ",")
	for i, name := range exporterNames {
		exporterNames[i] = strings.TrimSpace(name)
	}

	otlpEndpoint := os.Getenv(env.OTEL_EXPORTER_OTLP_ENDPOINT)
	var readers []sdkmetric.Reader
	if slices.Contains(exporterNames, keyExporterOTLPHTTP) {
		if otlpEndpoint == "" {
			return nil, fmt.Errorf("%s is not set", env.OTEL_EXPORTER_OTLP_ENDPOINT)
		}

		readerHTTP, err := getMetricReadersHTTP(ctx, otlpEndpoint, interval)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP OTLP metric exporter: %w", err)
		}

		readers = append(readers, readerHTTP)
	}

	if slices.Contains(exporterNames, keyExporterOTLPGRPC) {
		if otlpEndpoint == "" {
			return nil, fmt.Errorf("%s is not set", env.OTEL_EXPORTER_OTLP_ENDPOINT)
		}

		readerGRPC, err := getMetricReadersGRPC(ctx, otlpEndpoint, interval)
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC OTLP metric exporter: %w", err)
		}

		readers = append(readers, readerGRPC)
	}

	if slices.Contains(exporterNames, keyExporterConsole) {
		readerConsole, err := getMetricReadersConsole(interval)
		if err != nil {
			return nil, fmt.Errorf("failed to create console metric exporter: %w", err)
		}
		readers = append(readers, readerConsole)
	}

	if len(readers) == 0 {
		slog.Info("No valid metric exporters configured, using no-op meter provider",
			slog.String("requested_exporters", metricsExporter))
		mp := sdkmetric.NewMeterProvider()
		return &MeterProvider{mp: mp}, nil
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(serviceVersion),
			semconv.ServiceNamespaceKey.String("crypto-broker"),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	options := []sdkmetric.Option{
		sdkmetric.WithResource(res),
	}

	for _, reader := range readers {
		options = append(options, sdkmetric.WithReader(reader))
	}

	mp := sdkmetric.NewMeterProvider(options...)
	otel.SetMeterProvider(mp)

	// Start collecting Go runtime metrics
	if err := runtime.Start(runtime.WithMeterProvider(mp)); err != nil {
		return nil, fmt.Errorf("failed to start runtime metrics collection: %w", err)
	}

	slog.Info("OpenTelemetry meter provider initialized",
		slog.String("service_name", serviceName),
		slog.String("service_version", serviceVersion),
		slog.String("exporters", metricsExporter),
		slog.String("interval", interval.String()))

	return &MeterProvider{mp: mp}, nil
}

// getMetricReadersHTTP creates HTTP metric readers
func getMetricReadersHTTP(ctx context.Context, otlpEndpoint string, interval time.Duration) (sdkmetric.Reader, error) {
	var endpointHost string
	var urlPath string
	useSecure := true

	if strings.HasPrefix(otlpEndpoint, "http://") {
		otlpEndpoint = strings.TrimPrefix(otlpEndpoint, "http://")
		useSecure = false
	} else if strings.HasPrefix(otlpEndpoint, "https://") {
		otlpEndpoint = strings.TrimPrefix(otlpEndpoint, "https://")
		useSecure = true
	}

	parts := strings.SplitN(otlpEndpoint, "/", 2)
	endpointHost = parts[0]
	if len(parts) > 1 {
		urlPath = "/" + parts[1]
	}

	// Remove /v1/metrics suffix if present, as otlpmetrichttp will add it automatically
	urlPath = strings.TrimSuffix(urlPath, "/v1/metrics")

	headers := make(map[string]string)

	if apiToken := os.Getenv(env.OTEL_EXPORTER_OTLP_HEADERS_AUTHORIZATION); apiToken != "" {
		headers["Authorization"] = apiToken
		slog.Info("Dynatrace API token configured for OTLP HTTP metric exporter")
	}

	opts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(endpointHost),
		otlpmetrichttp.WithHeaders(headers),
	}

	if !useSecure {
		opts = append(opts, otlpmetrichttp.WithInsecure())
	}

	if urlPath != "" {
		opts = append(opts, otlpmetrichttp.WithURLPath(urlPath+"/v1/metrics"))
	}

	exporter, err := otlpmetrichttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP OTLP metric exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(interval))

	slog.Info("HTTP OTLP metric exporter configured", slog.String("endpoint", endpointHost), slog.String("path", urlPath))

	return reader, nil
}

// getMetricReadersGRPC creates gRPC metric readers
func getMetricReadersGRPC(ctx context.Context, otlpEndpoint string, interval time.Duration) (sdkmetric.Reader, error) {
	exporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(otlpEndpoint),
		otlpmetricgrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create gRPC OTLP metric exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(interval))

	slog.Info("gRPC OTLP metric exporter configured", slog.String("endpoint", otlpEndpoint))

	return reader, nil
}

// getMetricReadersConsole creates console metric readers
func getMetricReadersConsole(interval time.Duration) (sdkmetric.Reader, error) {
	exporter, err := stdoutmetric.New(stdoutmetric.WithPrettyPrint())
	if err != nil {
		return nil, fmt.Errorf("failed to create console metric exporter: %w", err)
	}

	reader := sdkmetric.NewPeriodicReader(exporter, sdkmetric.WithInterval(interval))

	slog.Info("Console metric exporter configured")

	return reader, nil
}

// Shutdown gracefully shuts down the meter provider
func (mp *MeterProvider) Shutdown(ctx context.Context) error {
	if mp.mp != nil {
		return mp.mp.Shutdown(ctx)
	}
	return nil
}

// GetMeter returns a meter with the given name
func (mp *MeterProvider) GetMeter(name string, opts ...metric.MeterOption) metric.Meter {
	return mp.mp.Meter(name, opts...)
}
