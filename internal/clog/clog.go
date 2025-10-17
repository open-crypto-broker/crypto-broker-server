// Package clog stands for crypto broker logger. Contains utilities related with logging.
package clog

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
)

// predefined keywords representing log level, log format and log output
const (
	logLevelDebug = "debug"
	logLevelInfo  = "info"
	logLevelWarn  = "warn"
	logLevelError = "error"

	logFormatJSON = "json"
	logFormatText = "text"

	logOutputStdout = "stdout"
	logOutputStderr = "stderr"
)

// SetupGlobalLogger initializes the crypto broker logger.
// It predefines defaults for logger. If user provides custom values that are not supported by the logger, it panics.
// It sets the logger to the default global logger.
func SetupGlobalLogger() *slog.Logger {
	logLevel := slog.LevelInfo // default
	userProvidedLogLevel := strings.ToLower(os.Getenv(env.LOG_LEVEL))
	if userProvidedLogLevel != "" {
		switch userProvidedLogLevel {
		case strings.ToLower(logLevelDebug):
			logLevel = slog.LevelDebug
		case strings.ToLower(logLevelInfo):
			logLevel = slog.LevelInfo
		case strings.ToLower(logLevelWarn):
			logLevel = slog.LevelWarn
		case strings.ToLower(logLevelError):
			logLevel = slog.LevelError
		default:
			panic(fmt.Sprintf("invalid log level provided: %s, available levels: %s, %s, %s, %s",
				userProvidedLogLevel, logLevelDebug, logLevelInfo, logLevelWarn, logLevelError))
		}
	}

	var logOutput *os.File
	logOutput = os.Stdout // default
	userProvidedLogOutput := strings.ToLower(os.Getenv(env.LOG_OUTPUT))
	if userProvidedLogOutput != "" {
		switch userProvidedLogOutput {
		case strings.ToLower(logOutputStdout):
			logOutput = os.Stdout
		case strings.ToLower(logOutputStderr):
			logOutput = os.Stderr
		default:
			panic(fmt.Sprintf("invalid log output provided: %s, available outputs: %s, %s",
				userProvidedLogOutput, logOutputStdout, logOutputStderr))
		}
	}

	var logHandler slog.Handler
	logHandler = slog.NewJSONHandler(logOutput, &slog.HandlerOptions{Level: logLevel}) // default
	userProvidedLogFormat := strings.ToLower(os.Getenv(env.LOG_FORMAT))
	if userProvidedLogFormat != "" {
		switch userProvidedLogFormat {
		case strings.ToLower(logFormatJSON):
			logHandler = slog.NewJSONHandler(logOutput, &slog.HandlerOptions{Level: logLevel})
		case strings.ToLower(logFormatText):
			logHandler = slog.NewTextHandler(logOutput, &slog.HandlerOptions{Level: logLevel})
		default:
			panic(fmt.Sprintf("invalid log format provided: %s, available formats: %s, %s",
				userProvidedLogFormat, logFormatJSON, logFormatText))
		}
	}

	logger := slog.New(logHandler)
	fixedLogger := logger.With(slog.String("service", "crypto-broker-server"))
	slog.SetDefault(fixedLogger)

	return fixedLogger
}
