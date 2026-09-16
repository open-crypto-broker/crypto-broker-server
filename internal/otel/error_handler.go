package otel

import (
	"log/slog"

	gootel "go.opentelemetry.io/otel"
)

// ConfigureErrorHandler routes OpenTelemetry SDK errors through the server logger.
func ConfigureErrorHandler(logger *slog.Logger) {
	gootel.SetErrorHandler(gootel.ErrorHandlerFunc(func(err error) {
		logger.Error("OpenTelemetry telemetry export failed", slog.String("error", err.Error()))
	}))
}
