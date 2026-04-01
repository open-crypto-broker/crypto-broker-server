package otel

import (
	"context"
	"testing"
)

func TestNewMeterProvider_None_ReturnsNil(t *testing.T) {
	metricsExporter = keyExporterNone
	intervalStr = "30s"
	otlpEndpoint = ""

	mp, err := NewMeterProvider(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if mp != nil {
		t.Fatalf("expected nil meter provider for exporter=none")
	}
}

func TestNewMeterProvider_InvalidIntervalStr_ReturnsError(t *testing.T) {
	metricsExporter = keyExporterConsole
	intervalStr = "not-a-duration"
	otlpEndpoint = ""

	_, err := NewMeterProvider(context.Background())
	if err == nil {
		t.Fatalf("expected error for invalid intervalStr")
	}
}

func TestNewMeterProvider_NoValidExportersConfigured_ReturnsNoopProvider(t *testing.T) {
	metricsExporter = "definitely-not-an-exporter"
	intervalStr = "30s"
	otlpEndpoint = ""

	mp, err := NewMeterProvider(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if mp == nil || mp.mp == nil {
		t.Fatalf("expected non-nil meter provider even with no valid exporters")
	}
}

func TestNewMeterProvider_Console_ReturnsProvider(t *testing.T) {
	metricsExporter = keyExporterConsole
	intervalStr = "30s"
	otlpEndpoint = ""

	mp, err := NewMeterProvider(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if mp == nil || mp.mp == nil {
		t.Fatalf("expected non-nil meter provider")
	}

	if err := mp.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestNewTracerProvider_NoValidExporter_ReturnsNoopProvider(t *testing.T) {
	tracesExporter = "none"
	otlpEndpoint = ""

	tp, err := NewTracerProvider(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if tp == nil || tp.tp == nil {
		t.Fatalf("expected non-nil tracer provider")
	}
}

func TestNewTracerProvider_ConsoleExporter_ReturnsProvider(t *testing.T) {
	tracesExporter = keyExporterConsole
	otlpEndpoint = ""
	samplerName = samplerAlwaysOn
	samplingRatio = 1.0

	tp, err := NewTracerProvider(context.Background())
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if tp == nil || tp.tp == nil {
		t.Fatalf("expected non-nil tracer provider")
	}

	if err := tp.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}
}

func TestDefineSampler_Selection(t *testing.T) {
	t.Run("always_off", func(t *testing.T) {
		samplerName = samplerAlwaysOff
		s := defineSampler()
		if s.Description() == "" {
			t.Fatalf("expected non-empty sampler description")
		}
	})

	t.Run("ratio", func(t *testing.T) {
		samplerName = samplerRatio
		samplingRatio = 0.25
		s := defineSampler()
		if s.Description() == "" {
			t.Fatalf("expected non-empty sampler description")
		}
	})

	t.Run("unknown_defaults_to_always_on", func(t *testing.T) {
		samplerName = "definitely-not-a-sampler"
		s := defineSampler()
		if s.Description() == "" {
			t.Fatalf("expected non-empty sampler description")
		}
	})
}
