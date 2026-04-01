package clog

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
)

func TestLoadConfigFromEnv_LogLevel_PanicsOnInvalid(t *testing.T) {
	t.Setenv(env.LOG_LEVEL, "definitely-not-a-level")

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for invalid %s", env.LOG_LEVEL)
		}
	}()

	loadConfigFromEnv()
}

func TestLoadConfigFromEnv_LogOutput_PanicsOnInvalid(t *testing.T) {
	t.Setenv(env.LOG_OUTPUT, "definitely-not-an-output")

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for invalid %s", env.LOG_OUTPUT)
		}
	}()

	loadConfigFromEnv()
}

func TestLoadConfigFromEnv_LogFormat_PanicsOnInvalid(t *testing.T) {
	t.Setenv(env.LOG_FORMAT, "definitely-not-a-format")

	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for invalid %s", env.LOG_FORMAT)
		}
	}()

	loadConfigFromEnv()
}

func TestSetupGlobalLogger_Console_DefaultsWhenUnset(t *testing.T) {
	t.Setenv(env.OTEL_LOGS_EXPORTER, "")
	t.Setenv(env.LOG_LEVEL, "")
	t.Setenv(env.LOG_OUTPUT, "")
	t.Setenv(env.LOG_FORMAT, "")
	loadConfigFromEnv()

	logger := SetupGlobalLogger(context.Background())
	if logger == nil {
		t.Fatalf("expected non-nil logger")
	}
}

func TestSetupGlobalLogger_InvalidExporterFallsBackToConsole(t *testing.T) {
	t.Setenv(env.OTEL_LOGS_EXPORTER, "not-a-real-exporter")
	loadConfigFromEnv()

	logger := SetupGlobalLogger(context.Background())
	if logger == nil {
		t.Fatalf("expected non-nil logger")
	}
}

func TestSetupGlobalLogger_Multi_ConsoleAndOTLP_FallsBackWithoutEndpoint(t *testing.T) {
	t.Setenv(env.OTEL_LOGS_EXPORTER, "console,otlphttp")
	t.Setenv(env.OTEL_EXPORTER_OTLP_ENDPOINT, "")
	loadConfigFromEnv()

	if otlpEndpoint != "" {
		t.Fatalf("expected empty otlpEndpoint in test, got %q (env %s)", otlpEndpoint, env.OTEL_EXPORTER_OTLP_ENDPOINT)
	}

	logger := SetupGlobalLogger(context.Background())
	if logger == nil {
		t.Fatalf("expected non-nil logger")
	}

	if logOutput == nil || logOutput == (*os.File)(nil) {
		t.Fatalf("expected valid logOutput")
	}
}

type recordingHandler struct {
	enabled bool
	handled int
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return h.enabled }
func (h *recordingHandler) Handle(context.Context, slog.Record) error {
	h.handled++
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

func TestMultiHandler_EnabledAndHandle(t *testing.T) {
	h1 := &recordingHandler{enabled: false}
	h2 := &recordingHandler{enabled: true}

	mh := &multiHandler{handlers: []slog.Handler{h1, h2}}
	if !mh.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatalf("expected Enabled=true when any handler enabled")
	}

	rec := slog.NewRecord(time.Now(), slog.LevelInfo, "msg", 0)
	if err := mh.Handle(context.Background(), rec); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if h1.handled != 0 {
		t.Fatalf("expected disabled handler not to Handle, got %d", h1.handled)
	}
	if h2.handled != 1 {
		t.Fatalf("expected enabled handler to Handle once, got %d", h2.handled)
	}

	_ = mh.WithAttrs([]slog.Attr{slog.String("k", "v")})
	_ = mh.WithGroup("g")
}
