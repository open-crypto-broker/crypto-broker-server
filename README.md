# Crypto Broker Server

This repository contains the Crypto Broker server that allows the user to perform cryptographic operations. The server is not intended to be used alone, but in combination with any of the libraries provided.

## Usage

### Installation

The server does not need to be integrated into any existing code. Instead, it is meant to be deployed as a sidecar to a main application using the client library to communicate with the server. Client and server will establish a communication via a Unix Socket over a local shared drive (fixed to `/tmp`) and exchange data via gRPC as communication protocol.

### Usage

The server is not mean to be run locally in production. However, this can be done for the sake of easier testing. For that, please refer to the section below of [Testing](#testing).

At the moment, two methods of deployment are supported:

* CloudFoundry: Using the binaries provided in the [Releases](https://github.com/open-crypto-broker/crypto-broker-server/releases)
* Kubernetes: Using the Docker Image of the server

Documentation on how to deploy the server on these methods can be found on the [deployment repository](https://github.com/open-crypto-broker/crypto-broker-deployment)

### Environment Variables

The Crypto Broker Server supports several environment variables for configuration:

| Variable | Required | Default | Description | Valid Values |
| -------- | -------- | ------- | ----------- | ------------ |
| `CRYPTO_BROKER_PROFILES_DIR` | Yes | - | Full OS path to directory containing profile files in YAML format | Any valid directory path |
| `CRYPTO_BROKER_LOG_LEVEL` | No | `info` | Log level for the server | `debug`, `info`, `warn`, `error` |
| `CRYPTO_BROKER_LOG_FORMAT` | No | `json` | Log output format | `json`, `text` |
| `CRYPTO_BROKER_LOG_OUTPUT` | No | `stdout` | Log output destination | `stdout`, `stderr` |
| `CRYPTO_BROKER_BENCHMARKING_SIGNCERTIFICATE_CA_CERT` | No | - | Full OS path to CA certificate file used in benchmark tests for signing certificates | Any valid file path |
| `CRYPTO_BROKER_BENCHMARKING_SIGNCERTIFICATE_PRIVATE_KEY` | No | - | Full OS path to CA private key file used in benchmark tests for signing certificates | Any valid file path |
| `CRYPTO_BROKER_BENCHMARKING_SIGNCERTIFICATE_CSR` | No | - | Full OS path to CSR file used in benchmark tests for signing certificates | Any valid file path |
| `OTEL_SERVICE_NAME` | No | `crypto-broker-server` | Service name for OpenTelemetry traces | Any string |
| `OTEL_SERVICE_VERSION` | No | `unknown service version` | Service version for OpenTelemetry traces | Any string |
| `OTEL_TRACES_EXPORTER` | No | `console` | OpenTelemetry trace exporter(s) to use | `otlp`, `console`, or comma-separated list like `console,otlp` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | No | - | OTLP endpoint for traces (gRPC format "host:port" or HTTP URL format `"https://host:port/path"`) | Valid endpoint URL (only used when OTLP exporter is enabled) |
| `OTEL_TRACES_SAMPLER` | No | `always_on` | Sampling strategy for traces | `always_on`, `always_off`, `traceidratio`, `parentbased_always_on`, `parentbased_always_off`, `parentbased_traceidratio` |
| `OTEL_TRACES_SAMPLER_ARG` | No | - | Sampling ratio (0.0-1.0) when using ratio-based samplers | Float between 0.0 and 1.0 |
| `OTEL_EXPORTER_OTLP_HEADERS_AUTHORIZATION` | No | - | Authorization header for OTLP HTTP exporter (e.g., for Dynatrace: "Api-Token YOUR_API_TOKEN") | Valid authorization header string |
| `OTEL_LOGS_EXPORTER` | No | `console` | OpenTelemetry log exporter(s) to use | `console`, `otlphttp`, `otlpgrpc`, or comma-separated combinations like `otlphttp,console` |

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

Traces include error information and span status codes for failed operations.

### OpenTelemetry Logging

The Crypto Broker Server includes OpenTelemetry (OTEL) logging support for centralized log aggregation and correlation with traces. Logs are automatically structured and can be exported to both console and OTLP-compatible backends simultaneously.

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

## Development

This section covers how to contribute to the project and develop it further.

### Prerequisites

Note that you need to have a version of [Golang](https://go.dev/doc/install) > 1.24 installed on your local machine in order to run it locally from terminal. For building the Docker image, you need to have Docker/Docker Desktop or any other alternative (e.g. Podman) installed.

For running the commands using the `Taskfile` tool, you need to have Taskfile installed. Please check the documentation on [how to install Taskfile](https://taskfile.dev/installation/). If you don't have Taskfile support, you can directly use the commands specified in the Taskfile on your local terminal, provided you meet the requirements.

To contribute to this project please configure the custom githooks for this project:

```bash
git config core.hooksPath .githooks
```

This commit hook will make sure the code follows the standard formatting and keep everything consistent.

Additionally, please download all required tools for project development.
Please inspect the different tasks of [tools](./Taskfile.yaml) for more information which Go modules will be downloaded and installed.
Installation of the necessary tools is supported automatically for Linux and macOS.

```bash
task tools
```

### Building

#### Compiling the binary file

To build server binary in the `/bin` directory use

```shell
task build
```

This will also save a checksum of all the file `sources` in the Taskfile cache `.task`.
This means that, if no new changes are done, re-running the task will not build the binary again.

This repository uses a submodule for the proto files in `/protobuf` directory.

To reload the `/protobuf` files to the latest `main` commit and recompile them, run the following:

```shell
task proto
```

#### Building the Docker image

For building the image for local use, you can use the command:

```shell
task build-docker [TAG=opt]
```

The TAG argument is optional and will apply a custom image tag to the built images. If not specified, it defaults to `latest`. This will create a local image tagged as `server_app:TAG`, which will be saved in your local Docker repository. If you want to modify or append args to the build command, please refer to the one from the Taskfile.

Note that, by default, Taskfile will import a local `.env` file located in the directory. This is optional and  can be used to push images to private repositories or injecting variables in the system.

### Testing

The server is meant to be tested using the standard Golang Testing `go test`. If you want to additionally invoke the local pipeline for code formatting, you can run all of these commands with:

```shell
task ci
```

To run benchmarks, run

```shell
task run-benchmarks
```

More info on benchmarks can be found in [testing](https://pkg.go.dev/testing@go1.25.3#hdr-Benchmarks) pkg. For detailed description of bench output see [proposal](https://go.googlesource.com/proposal/+/master/design/14313-benchmark-format.md).

For some of benchmarks, you need to have the [deployment repository](https://github.com/open-crypto-broker/crypto-broker-deployment) in the same parent directory as this repository.

For running the server locally (e.g. for testing with the libraries' CLI), change directory to project root & run server with following command. This will first [compile the Go Code](#compiling-the-binary-file) if any of the Go files have been changed and then run the server with the default profiles dir:

```shell
task run
```

If you want to define your custom profiles dir, you can directly run the server with the following command:

```shell
CRYPTO_BROKER_PROFILES_DIR=<path-to-your-Profile.yaml> go run cmd/server/server.go
```

Both commands will keep the server running and listening on the unix socket. From another terminal in localhost, you can run the libraries' CLI in order to perform a local end2end test. For a more thorough end2end test, check the deployment repository.

#### Debugging with VS Code

To run & debug in `VSCode`:

1. Create `.vscode` secret directory in root of repository
1. Create `launch.json` file in it
1. Fill it with:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch Package",
            "type": "go",
            "request": "launch",
            "mode": "auto",
            "console": "integratedTerminal",
            "program": "${workspaceFolder}/cmd/server/server.go",
            "env": {
                "CRYPTO_BROKER_PROFILES_DIR": "${workspaceFolder}/profiles"
            },
            "args": ""
        }
    ]
}
```

Open `Run and Debug` tab from left side nav bar.
Click on `Start Debugging` icon.

Now you can place breakpoints in your code.

## Security / Disclosure

If you find any bug that may be a security problem, please follow our instructions at in our [security policy](./SECURITY.md) on how to report it. Please do not create GitHub issues for security-related doubts or problems.

## Code of Conduct

We as members, contributors, and leaders pledge to make participation in our community a harassment-free experience for everyone. By participating in this project, you agree to abide by its [Code of Conduct](https://github.com/open-crypto-broker/.github/blob/main/CODE_OF_CONDUCT.md) at all times.

## Licensing

Copyright 2025 SAP SE or an SAP affiliate company and Open Crypto Broker contributors. Please see our [LICENSE](./LICENSE) for copyright and license information. Detailed information including third-party components and their licensing/copyright information is available via the [REUSE](REUSE.toml) tool.
