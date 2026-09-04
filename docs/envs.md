| Variable | Required | Default | Description | Valid Values |
| -------- | -------- | ------- | ----------- | ------------ |
| `CRYPTO_BROKER_APP_ENV` | No | prod | Specifies the server runtime environment | `prod`, `dev` |
| `CRYPTO_BROKER_GRPC_MAX_CONCURRENT_STREAMS` | No | 1024 | Specifies how many concurrent connections server can accept | uint32 |
| `CRYPTO_BROKER_PROFILES_DIR` | Yes | - | Full OS path to directory containing profile files in YAML format | Any valid directory path |
| `CRYPTO_BROKER_KMS_DIR` | When using KMS | `configs/` in `.env.example` | Directory containing KMS connection configuration files and user-defined custom client implementations. | Any valid directory path |
| `CRYPTO_BROKER_LOG_LEVEL` | No | `info` | Log level for the server | `debug`, `info`, `warn`, `error` |
| `CRYPTO_BROKER_LOG_FORMAT` | No | `json` | Log output format | `json`, `text` |
| `CRYPTO_BROKER_LOG_OUTPUT` | No | `stdout` | Log output destination | `stdout`, `stderr` |
| `CRYPTO_BROKER_BENCHMARKING_SIGNCERTIFICATE_CA_CERT` | No | - | Full OS path to CA certificate file used in benchmark tests for signing certificates | Any valid file path |
| `CRYPTO_BROKER_BENCHMARKING_SIGNCERTIFICATE_PRIVATE_KEY` | No | - | Full OS path to CA private key file used in benchmark tests for signing certificates | Any valid file path |
| `CRYPTO_BROKER_BENCHMARKING_SIGNCERTIFICATE_CSR` | No | - | Full OS path to CSR file used in benchmark tests for signing certificates | Any valid file path |
| `OTEL_SERVICE_NAME` | No | `crypto-broker-server` | Service name for OpenTelemetry traces | Any string |
| `OTEL_SERVICE_VERSION` | No | `unknown service version` | Service version for OpenTelemetry traces | Any string |
| `OTEL_TRACES_EXPORTER` | No | `console` | OpenTelemetry trace exporter(s) to use | `otlphttp`, `otlpgrpc`, `console`, or comma-separated combinations like `console,otlphttp`; any unrecognized value disables tracing |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | - | OTLP endpoint for traces (gRPC format "host:port" or HTTP URL format `"https://host:port/path"`) | Valid endpoint URL (only used when OTLP exporter is enabled) |
| `OTEL_TRACES_SAMPLER` | No | `always_on` | Sampling strategy for traces | `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | No | - | Sampling ratio (0.0-1.0) when using ratio-based samplers | Float between 0.0 and 1.0 |
| `OTEL_EXPORTER_OTLP_HEADERS_AUTHORIZATION` | No | - | Authorization header for OTLP HTTP exporter (e.g., for Dynatrace: "Api-Token YOUR_API_TOKEN") | Valid authorization header string |
| `OTEL_LOGS_EXPORTER` | No | `console` | OpenTelemetry log exporter(s) to use | `console`, `otlp` (auto-detects HTTP/gRPC from endpoint URL format), `otlphttp`, `otlpgrpc`, or comma-separated combinations like `otlphttp,console` |
| `OTEL_METRICS_EXPORTER` | No | `console` | OpenTelemetry metrics exporter(s) to use | `none`, `console`, `otlphttp`, `otlpgrpc`, or comma-separated combinations like `otlphttp,console` |
| `OTEL_METRICS_INTERVAL` | No | `30s` | Metrics collection interval | Duration strings like `30s`, `1m`, `5m` |
| `CRYPTO_BROKER_PPROF_ADDR` | No | - | When set, enables `net/http/pprof` on this TCP address (e.g. for CPU profiles / PGO). Prefer loopback only. **Requires `CRYPTO_BROKER_APP_ENV=dev`** — has no effect in `prod` mode | e.g. `127.0.0.1:6060` |
