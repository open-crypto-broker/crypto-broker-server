package otel

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	gootel "go.opentelemetry.io/otel"
)

type capturedLogRecord struct {
	level   slog.Level
	message string
	attrs   []slog.Attr
}

type captureHandler struct {
	records []capturedLogRecord
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *captureHandler) Handle(_ context.Context, record slog.Record) error {
	attrs := make([]slog.Attr, 0, record.NumAttrs())
	record.Attrs(func(attr slog.Attr) bool {
		attrs = append(attrs, attr)
		return true
	})
	h.records = append(h.records, capturedLogRecord{
		level:   record.Level,
		message: record.Message,
		attrs:   attrs,
	})
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *captureHandler) WithGroup(string) slog.Handler {
	return h
}

func TestConfigureErrorHandler_LogsOpenTelemetryErrors(t *testing.T) {
	handler := &captureHandler{}
	ConfigureErrorHandler(slog.New(handler))

	gootel.Handle(errors.New("collector unavailable"))

	if len(handler.records) != 1 {
		t.Fatalf("expected one log record, got %d", len(handler.records))
	}

	record := handler.records[0]
	if record.level != slog.LevelError {
		t.Errorf("level = %v, want %v", record.level, slog.LevelError)
	}
	if record.message != "OpenTelemetry telemetry export failed" {
		t.Errorf("message = %q, want %q", record.message, "OpenTelemetry telemetry export failed")
	}
	if len(record.attrs) != 1 || record.attrs[0].Key != "error" || record.attrs[0].Value.String() != "collector unavailable" {
		t.Errorf("attrs = %v, want error=collector unavailable", record.attrs)
	}
}
