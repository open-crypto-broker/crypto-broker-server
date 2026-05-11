package apivalidation

// Size limits are intentionally conservative; they bound memory usage and avoid
// expensive parsing work on obviously unreasonable input.
//
// These values are internal implementation details and can be tuned later.
const (
	// gRPC transport-level limits (bytes)
	MaxGrpcRecvMsgSize = 2 << 20 // 2 MiB
	MaxGrpcSendMsgSize = 1 << 20 // 1 MiB

	// Common fields
	MaxProfileLen = 64

	// Hash
	MaxHashInputBytes = 1 << 20 // 1 MiB

	// Sign (PEM strings)
	MaxCSRBytes          = 64 << 10 // 64 KiB
	MaxCAPrivateKeyBytes = 64 << 10 // 64 KiB
	MaxCACertBytes       = 64 << 10 // 64 KiB
	MaxSubjectLen        = 1024

	MaxCRLDistributionPoints   = 16
	MaxCRLDistributionPointLen = 2048

	// Metadata / trace propagation
	MaxMetadataIdLen        = 128
	MaxMetadataCreatedAtLen = 64

	MaxTraceIdLen       = 32
	MaxSpanIdLen        = 16
	MaxTraceFlagsLen    = 2
	MaxTraceStateLen    = 512
	MaxCorrelationIdLen = 128
)
