## Overview

This document describes how to work with & configure OTEL related stuff in `crypto-broker-server`

### OpenTelemetry Tracing

The Crypto Broker Server includes OpenTelemetry (OTEL) tracing support for distributed observability. Traces are automatically generated for all gRPC requests and include detailed spans for cryptographic operations.

#### Exporter Options

The `OTEL_TRACES_EXPORTER` variable supports several values:

* **`otlpgrpc`** (default): Export traces to an OTLP-compatible collector via gRPC
* **`otlphttp`** (default): Export traces to an OTLP-compatible collector via HTTP(s)
* **`console`**: Export traces to stdout/stderr in human-readable format (useful for development)
* **Comma-separated**: `console,otlpgrpc`

#### OTEL Setup Examples

**Export to OTLP collector only:**

```bash
export OTEL_TRACES_EXPORTER="otlpgrpc"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://otel-collector:4317"
export OTEL_TRACES_SAMPLER="traceidratio"
export OTEL_TRACES_SAMPLER_ARG="0.1"  # Sample 10% of traces
```

**Console export for local development:**

```bash
export OTEL_TRACES_EXPORTER="console"
export OTEL_TRACES_SAMPLER="always_on"  # See all traces in console
```

**Export to both console and OTLP:**

```bash
export OTEL_TRACES_EXPORTER="otlpgrpc,console"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://otel-collector:4317"
# Traces will appear in both console and be sent to collector
```

#### Trace Information

The server generates the following trace spans:

* **gRPC Server Spans**: Automatic spans for each gRPC request (created by OTEL gRPC instrumentation)
* **RPC Method Spans**: Custom spans for each RPC method (`Hash`, `Sign`, `Benchmark`) with operation-specific attributes
* **Attributes Included**(full list in [attr.go](./internal/otel/attr.go)]):
    * `rpc.method`: The gRPC method name
    * `crypto.profile`: The cryptographic profile used
    * `correlationId`: The optional correlation ID from `TraceContext` (included only when non-empty)

Traces include error information and span status codes for failed operations.

### OpenTelemetry Logging

The Crypto Broker Server includes OpenTelemetry (OTEL) logging support for centralized log aggregation and correlation with traces. Logs are automatically structured and can be exported to both console and OTLP-compatible backends simultaneously.

Following environment variables are related with logging, for more info please see [envs.md](./envs.md):

* `CRYPTO_BROKER_LOG_LEVEL`
* `CRYPTO_BROKER_LOG_FORMAT`
* `CRYPTO_BROKER_LOG_OUTPUT`
* `OTEL_LOGS_EXPORTER` 

#### Log Exporter Options

The `OTEL_LOGS_EXPORTER` variable supports several values:

* **`console`** (default): Export logs to stdout/stderr in structured format (JSON recommended for production)
* **`otlp`**: Export logs to an OTLP-compatible endpoint. Protocol is auto-detected:
    * **HTTP**: When endpoint starts with `http://` or `https://` (direct Dynatrace API)
    * **gRPC**: When endpoint is `host:port` format (Dynatrace collector)
* **`otlphttp`**: Force HTTP protocol for OTLP logs (direct Dynatrace API)
* **`otlpgrpc`**: Force gRPC protocol for OTLP logs (Dynatrace collector)
* **Comma-separated**: `otlp,console`, `otlphttp,console`, `otlpgrpc,console` - Export to both OTLP and console simultaneously

#### OTEL Logging Setup Examples

**Console logging only (default):**

```bash
export OTEL_LOGS_EXPORTER="console"
export CRYPTO_BROKER_LOG_LEVEL="info"
export CRYPTO_BROKER_LOG_FORMAT="json"
# Logs will appear in stdout as structured JSON
```

**Export to both console and OTLP:**

```bash
export OTEL_LOGS_EXPORTER="otlp,console"
export OTEL_EXPORTER_OTLP_ENDPOINT="https://<TENANT>.live.dynatrace.com/api/v2/otlp"
export OTEL_EXPORTER_OTLP_HEADERS_AUTHORIZATION="Api-Token dt0c01.xxx..."
export CRYPTO_BROKER_LOG_LEVEL="debug"
export CRYPTO_BROKER_LOG_FORMAT="json"
```

#### Log Information

The server generates structured logs with the following characteristics:

* **Structured Format**: All logs include consistent fields like `timestamp`, `level`, `msg`, `service`
* **Configurable Levels**: Debug, Info, Warn, Error levels supported
* **Multiple Formats**: JSON (recommended for production) and text formats available
* **Multi-destination**: Can simultaneously log to console and external systems

### OpenTelemetry Metrics

The Crypto Broker Server includes OpenTelemetry (OTEL) metrics support for monitoring performance, throughput, and system health. Metrics are automatically collected for all operations and can be exported to both console and OTLP-compatible backends simultaneously.

#### Metrics Exporter Options

The `OTEL_METRICS_EXPORTER` variable supports several values:

* **`none`**: Disable metrics collection entirely (no performance overhead)
* **`console`** (default): Export metrics to stdout/stderr in human-readable format (useful for development)
* **`otlphttp`**: Export metrics to an OTLP-compatible collector via HTTP(s)
* **`otlpgrpc`**: Export metrics to an OTLP-compatible collector via gRPC
* **Comma-separated**: `console,otlphttp`, `otlpgrpc,console` - Export to multiple destinations simultaneously

#### Metrics Collection

The server collects metrics at following levels:

**Request-Level Metrics:**

* `crypto_requests_total{rpc_method, profile, status}` - Total number of requests by operation type and status
* `crypto_request_duration_seconds{rpc_method, profile}` - Request duration histograms

**Operation-Specific Metrics:**

* `crypto_hash_operations_total{algorithm}` - Total hash operations by algorithm (SHA-256, SHA-384, SHA-512, SHA3, Shake)
* `crypto_sign_operations_total{profile}` - Total certificate signing operations
* `crypto_operations_errors_total{rpc_method, error_type}` - Error counters by operation and error type
* `crypto_operation_bytes_processed_total{rpc_method}` - Total bytes processed by operations

**System Metrics:**

* `crypto_memory_usage_bytes` - Current memory allocation in bytes

**Go Runtime Metrics:**
The server automatically collects comprehensive Go runtime metrics for monitoring application performance and resource usage:

* `go_goroutine_count` - Count of live goroutines
* `go_memory_used_bytes` - Memory used by the Go runtime
* `go_memory_allocated_bytes_total` - Memory allocated to the heap by the application
* `go_memory_allocations_total` - Count of allocations to the heap by the application
* `go_memory_gc_goal_bytes` - Heap size target for the end of the GC cycle
* `go_processor_limit` - The number of OS threads that can execute user-level Go code simultaneously
* `go_config_gogc_percent` - Heap size target percentage configured by the user

#### OTEL Metrics Setup Examples

**Disable metrics entirely:**

```bash
export OTEL_METRICS_EXPORTER="none"
```

**Console metrics only (default):**

```bash
export OTEL_METRICS_EXPORTER="console"
export OTEL_METRICS_INTERVAL="30s"
```

**Export to OTLP collector:**

```bash
export OTEL_METRICS_EXPORTER="otlphttp"
export OTEL_METRICS_INTERVAL="30s"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
```

**Export to both console and OTLP:**

```bash
export OTEL_METRICS_EXPORTER="otlphttp,console"
export OTEL_METRICS_INTERVAL="15s"
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
```
