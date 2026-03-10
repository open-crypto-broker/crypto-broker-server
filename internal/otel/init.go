package otel

import (
	"os"
	
	"github.com/open-crypto-broker/crypto-broker-server/internal/env"

)

var (
	serviceName = defaultServiceName
	serviceVersion = defaultServiceVersion
	metricsExporter = keyExporterConsole
	tracesExporter = defaultTracesExporter
	intervalStr = "30s"
	otlpEndpoint = ""
	apiToken = ""
	samplerName = samplerAlwaysOn
	samplingRatio = 1.0
)

func init() {
	if customServiceName := os.Getenv(env.OTEL_SERVICE_NAME); customServiceName != "" {
		serviceName = customServiceName
	} 

	if customServiceVersion := os.Getenv(env.OTEL_SERVICE_VERSION); customServiceVersion != "" {	
		serviceVersion = customServiceVersion
	}

	if customMetricsExporter := os.Getenv(env.OTEL_METRICS_EXPORTER); customMetricsExporter != "" {
		metricsExporter = customMetricsExporter
	}

	if customTracesExporter := os.Getenv(env.OTEL_TRACES_EXPORTER); customTracesExporter != "" {
		tracesExporter = customTracesExporter
	}

	if customInterval := os.Getenv(env.OTEL_METRICS_INTERVAL); customInterval != "" {
		intervalStr = customInterval
	}

	if customSamplerName := os.Getenv(env.OTEL_TRACES_SAMPLER); customSamplerName != "" {
		samplerName = customSamplerName
	}

	if customSamplingRatio := os.Getenv(env.OTEL_TRACES_SAMPLER_ARG); customSamplingRatio != "" {
		if parsedRatio, err := parseFloat64(customSamplingRatio); err == nil && parsedRatio >= 0.0 && parsedRatio <= 1.0 {
			samplingRatio = parsedRatio
		}
	}

	apiToken = os.Getenv(env.OTEL_EXPORTER_OTLP_HEADERS_AUTHORIZATION)
	otlpEndpoint = os.Getenv(env.OTEL_EXPORTER_OTLP_ENDPOINT)
}