// Package env stands for environment variables. Contains constants for environment variables used by the Crypto Broker.
package env

const (
	// PROFILES_DIRECTORY is environment variable that should contain full OS path
	// to directory that contains files with defined profiles in YAML format.
	PROFILES_DIRECTORY = "CRYPTO_BROKER_PROFILES_DIR"

	// LOG_LEVEL is environment variable that should contain log level.
	// Valid values are denoted in internal/clog package
	LOG_LEVEL = "CRYPTO_BROKER_LOG_LEVEL"

	// LOG_FORMAT is environment variable that should contain log format.
	// Valid values are denoted in internal/clog package
	LOG_FORMAT = "CRYPTO_BROKER_LOG_FORMAT"

	// LOG_OUTPUT is environment variable that should contain log output.
	// Valid values are denoted in internal/clog package
	LOG_OUTPUT = "CRYPTO_BROKER_LOG_OUTPUT"

	// BENCHMARK_SIGN_CERTIFICATE_CA_CERT is environment variable that should contain full OS path
	// to CA certificate file used in benchmark tests for signing certificates.
	BENCHMARK_SIGN_CERTIFICATE_CA_CERT = "CRYPTO_BROKER_BENCHMARKING_SIGNCERTIFICATE_CA_CERT"

	// BENCHMARK_SIGN_CERTIFICATE_PRIVATE_KEY is environment variable that should contain full OS path
	// to CA private key file used in benchmark tests for signing certificates.
	BENCHMARK_SIGN_CERTIFICATE_PRIVATE_KEY = "CRYPTO_BROKER_BENCHMARKING_SIGNCERTIFICATE_PRIVATE_KEY"

	// BENCHMARK_SIGN_CERTIFICATE_CSR is environment variable that should contain full OS path
	// to CSR file used in benchmark tests for signing certificates.
	BENCHMARK_SIGN_CERTIFICATE_CSR = "CRYPTO_BROKER_BENCHMARKING_SIGNCERTIFICATE_CSR"
)
