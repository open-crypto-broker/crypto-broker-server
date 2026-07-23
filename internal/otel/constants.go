package otel

const (
	StatusSuccess            = "success"
	StatusError              = "error"
	RPCMethodHashData        = "HashData"
	RPCMethodSignCertificate = "SignCertificate"
	RPCMethodEncryptData     = "EncryptData"
	RPCMethodDecryptData     = "DecryptData"
	RPCMethodBenchmark       = "Benchmark"
	RPCMethodFakeEndpoint    = "FakeEndpoint"
)

// default values for OTEL configurations
const (
	defaultServiceName    = "crypto-broker-server"
	defaultServiceVersion = "unknown service version"
	defaultTracesExporter = "console"
)

// keys representing OTEL exporters
const (
	keyExporterOTLPGRPC = "otlpgrpc"
	keyExporterConsole  = "console"
	keyExporterOTLPHTTP = "otlphttp"
	keyExporterNone     = "none"
)

// sampler names
const (
	samplerAlwaysOn                = "always_on"
	samplerAlways                  = "always"
	samplerAlwaysOff               = "always_off"
	samplerNever                   = "never"
	samplerTraceIDRatio            = "traceidratio"
	samplerRatio                   = "ratio"
	samplerParentBasedAlwaysOn     = "parentbased_always_on"
	samplerParentBasedAlwaysOff    = "parentbased_always_off"
	samplerParentBasedTraceIDRatio = "parentbased_traceidratio"
)

const (
	// BootstrapProbeNotConfigured indicates that the tracing bootstrap probe should not run.
	BootstrapProbeNotConfigured BootstrapProbeDecision = "not_configured"

	// BootstrapProbeSkippedDueToSampler indicates that the tracing bootstrap probe should not run due to the sampler.
	BootstrapProbeSkippedDueToSampler BootstrapProbeDecision = "skipped_due_to_sampler"

	// BootstrapProbeAttempted indicates that the tracing bootstrap probe should run.
	BootstrapProbeAttempted BootstrapProbeDecision = "attempted"
)
