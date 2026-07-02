package otel

import (
	"go.opentelemetry.io/otel/metric"
)

// Global metric instruments
var (
	// Request metrics
	RequestsTotal   metric.Int64Counter
	RequestDuration metric.Float64Histogram

	// Cryptographic operation metrics
	HashDataOperationsTotal        metric.Int64Counter
	SignCertificateOperationsTotal metric.Int64Counter
	OperationsErrorsTotal          metric.Int64Counter

	// Performance metrics
	OperationBytesProcessed metric.Int64Counter
	MemoryUsage             metric.Int64ObservableGauge
)

// InitializeInstruments initializes all metric instruments
func InitializeInstruments(meter metric.Meter) error {
	var err error

	// Request metrics
	RequestsTotal, err = meter.Int64Counter(
		"crypto_requests_total",
		metric.WithDescription("Total number of crypto requests"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	RequestDuration, err = meter.Float64Histogram(
		"crypto_request_duration_seconds",
		metric.WithDescription("Duration of crypto requests in seconds"),
		metric.WithUnit("s"),
	)
	if err != nil {
		return err
	}

	// Cryptographic operation metrics
	HashDataOperationsTotal, err = meter.Int64Counter(
		"crypto_hash_data_operations_total",
		metric.WithDescription("Total number of hash data operations by algorithm"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	SignCertificateOperationsTotal, err = meter.Int64Counter(
		"crypto_sign_certificate_operations_total",
		metric.WithDescription("Total number of certificate signing operations"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	OperationsErrorsTotal, err = meter.Int64Counter(
		"crypto_operations_errors_total",
		metric.WithDescription("Total number of crypto operation errors"),
		metric.WithUnit("1"),
	)
	if err != nil {
		return err
	}

	// Performance metrics
	OperationBytesProcessed, err = meter.Int64Counter(
		"crypto_operation_bytes_processed_total",
		metric.WithDescription("Total bytes processed by crypto operations"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return err
	}

	MemoryUsage, err = meter.Int64ObservableGauge(
		"crypto_memory_usage_bytes",
		metric.WithDescription("Current memory usage in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return err
	}

	MemoryUsage, err = meter.Int64ObservableGauge(
		"crypto_memory_usage_bytes",
		metric.WithDescription("Current memory usage in bytes"),
		metric.WithUnit("By"),
	)
	if err != nil {
		return err
	}

	return nil
}
