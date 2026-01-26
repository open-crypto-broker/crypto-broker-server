package otel

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

var ServiceName string

// default values for OTEL configurations
const (
	defaultServiceName    = "crypto-broker-server"
	defaultServiceVersion = "unknown service version"
	defaultTracesExporter = "console"
)

// keys representing OTEL exporters
const (
	keyExporterOTLP     = "otlp"
	keyExporterConsole  = "console"
	keyExporterOTLPHTTP = "otlphttp"
)

// TracerProvider holds the OpenTelemetry tracer provider
type TracerProvider struct {
	tp *sdktrace.TracerProvider
}

// GetGlobalTracer returns the global tracer for the service
func GetGlobalTracer(serviceName string) trace.Tracer {
	return otel.Tracer(serviceName)
}

// NewTracerProvider creates and initializes a new OpenTelemetry tracer provider
func NewTracerProvider(ctx context.Context, serviceName, serviceVersion string) (*TracerProvider, error) {
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

	tracesExporter := os.Getenv(env.OTEL_TRACES_EXPORTER)
	if tracesExporter == "" {
		tracesExporter = defaultTracesExporter
	}

	exporterNames := strings.Split(strings.ToLower(tracesExporter), ",")
	for i, name := range exporterNames {
		exporterNames[i] = strings.TrimSpace(name)
	}

	var batchers []sdktrace.TracerProviderOption
	// Check for HTTP OTLP exporter (required for Dynatrace)
	if slices.Contains(exporterNames, keyExporterOTLPHTTP) {
		otlpEndpoint := os.Getenv(env.OTEL_EXPORTER_OTLP_ENDPOINT)
		if otlpEndpoint == "" {
			return nil, fmt.Errorf("%s is not set", env.OTEL_EXPORTER_OTLP_ENDPOINT)
		}

		// Parse the endpoint URL to extract host:port and path
		// For Dynatrace: "https://trc17344.live.dynatrace.com/api/v2/otlp"
		// Endpoint should only be "trc17344.live.dynatrace.com"
		// Path should be "/api/v2/otlp"
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

		// Split endpoint and path
		parts := strings.SplitN(otlpEndpoint, "/", 2)
		endpointHost = parts[0]
		if len(parts) > 1 {
			urlPath = "/" + parts[1]
		}

		// Remove /v1/traces suffix if present in the path, as otlptracehttp will add it automatically
		urlPath = strings.TrimSuffix(urlPath, "/v1/traces")

		// Build headers for HTTP OTLP exporter
		headers := make(map[string]string)

		// Check for Dynatrace API token
		if apiToken := os.Getenv(env.OTEL_EXPORTER_OTLP_HEADERS_AUTHORIZATION); apiToken != "" {
			headers["Authorization"] = apiToken
			slog.Info("Dynatrace API token configured for OTLP HTTP exporter")
		}

		opts := []otlptracehttp.Option{
			otlptracehttp.WithEndpoint(endpointHost),
			otlptracehttp.WithHeaders(headers),
		}

		// Use insecure (HTTP) only if explicitly specified with http:// scheme
		// For HTTPS (recommended for production like Dynatrace), don't add WithInsecure()
		if !useSecure {
			// For HTTP endpoints (typically for local development only)
			opts = append(opts, otlptracehttp.WithInsecure())
		}

		// Add custom URL path if present
		if urlPath != "" {
			opts = append(opts, otlptracehttp.WithURLPath(urlPath+"/v1/traces"))
		}

		otlpExporter, err := otlptracehttp.New(ctx, opts...)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP OTLP exporter: %w", err)
		}
		batchers = append(batchers, sdktrace.WithBatcher(otlpExporter))
		slog.Info("HTTP OTLP exporter configured", slog.String("endpoint", endpointHost), slog.String("path", urlPath))
	} else if slices.Contains(exporterNames, keyExporterOTLP) {
		otlpEndpoint := os.Getenv(env.OTEL_EXPORTER_OTLP_ENDPOINT)
		if otlpEndpoint == "" {
			return nil, fmt.Errorf("%s is not set", env.OTEL_EXPORTER_OTLP_ENDPOINT)
		}

		otlpExporter, err := otlptracegrpc.New(ctx,
			otlptracegrpc.WithEndpoint(otlpEndpoint),
			otlptracegrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create gRPC OTLP exporter: %w", err)
		}
		batchers = append(batchers, sdktrace.WithBatcher(otlpExporter))
		slog.Info("gRPC OTLP exporter configured", slog.String("endpoint", otlpEndpoint))
	}

	if slices.Contains(exporterNames, keyExporterConsole) {
		consoleExporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return nil, fmt.Errorf("failed to create console exporter: %w", err)
		}
		batchers = append(batchers, sdktrace.WithBatcher(consoleExporter))
		slog.Info("Console exporter configured")
	}

	if len(batchers) == 0 {
		slog.Info("No valid exporters configured, using no-op tracer provider",
			slog.String("requested_exporters", tracesExporter))
		tp := sdktrace.NewTracerProvider()
		otel.SetTracerProvider(tp)
		return &TracerProvider{tp: tp}, nil
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

	sampler := sdktrace.AlwaysSample()
	samplerName := os.Getenv(env.OTEL_TRACES_SAMPLER)
	if samplerName == "" {
		samplerName = "always_on"
	}

	switch samplerName {
	case "always_on", "always":
		sampler = sdktrace.AlwaysSample()
	case "always_off", "never":
		sampler = sdktrace.NeverSample()
	case "traceidratio", "ratio":
		samplingRatio := 1.0 // Default to 100%
		if ratio := os.Getenv(env.OTEL_TRACES_SAMPLER_ARG); ratio != "" {
			if parsedRatio, err := parseFloat64(ratio); err == nil && parsedRatio >= 0.0 && parsedRatio <= 1.0 {
				samplingRatio = parsedRatio
			}
		}
		sampler = sdktrace.TraceIDRatioBased(samplingRatio)
	case "parentbased_always_on":
		sampler = sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "parentbased_always_off":
		sampler = sdktrace.ParentBased(sdktrace.NeverSample())
	case "parentbased_traceidratio":
		samplingRatio := 1.0 // Default to 100%
		if ratio := os.Getenv(env.OTEL_TRACES_SAMPLER_ARG); ratio != "" {
			if parsedRatio, err := parseFloat64(ratio); err == nil && parsedRatio >= 0.0 && parsedRatio <= 1.0 {
				samplingRatio = parsedRatio
			}
		}
		sampler = sdktrace.ParentBased(sdktrace.TraceIDRatioBased(samplingRatio))
	default:
		slog.Warn("Unknown OTEL_TRACES_SAMPLER value, using always_on", slog.String("sampler", samplerName))
		sampler = sdktrace.AlwaysSample()
	}

	options := append(batchers, sdktrace.WithResource(res), sdktrace.WithSampler(sampler))
	tp := sdktrace.NewTracerProvider(options...)
	otel.SetTracerProvider(tp)

	slog.Info("OpenTelemetry tracer provider initialized",
		slog.String("service_name", serviceName),
		slog.String("service_version", serviceVersion),
		slog.String("exporters", tracesExporter),
		slog.String("sampler", samplerName))

	return &TracerProvider{tp: tp}, nil
}

// Shutdown gracefully shuts down the tracer provider
func (tp *TracerProvider) Shutdown(ctx context.Context) error {
	if tp.tp != nil {
		return tp.tp.Shutdown(ctx)
	}
	return nil
}

// GetTracer returns a tracer with the given name
func (tp *TracerProvider) GetTracer(name string, opts ...trace.TracerOption) trace.Tracer {
	return tp.tp.Tracer(name, opts...)
}

// parseFloat64 parses a string to float64
func parseFloat64(s string) (float64, error) {
	return strconv.ParseFloat(s, 64)
}
