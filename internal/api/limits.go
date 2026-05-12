package api

// Size limits are intentionally conservative; they bound memory usage and avoid
// expensive parsing work on obviously unreasonable input.
//
// These values are internal implementation details and can be tuned later.
const (
	// gRPC transport-level limits (bytes)
	MaxGrpcRecvMsgSize = 2 << 20 // 2 MiB
	MaxGrpcSendMsgSize = 1 << 20 // 1 MiB

	// Common fields
	maxProfileLen = 64

	// Hash
	maxHashInputBytes = 1 << 20 // 1 MiB

	// Sign (PEM strings)
	maxCSRBytes          = 64 << 10 // 64 KiB
	maxCAPrivateKeyBytes = 64 << 10 // 64 KiB
	maxCACertBytes       = 64 << 10 // 64 KiB
	maxSubjectLen        = 1024

	maxCRLDistributionPoints   = 16
	maxCRLDistributionPointLen = 2048

	// Metadata / trace propagation
	maxMetadataIdLen        = 128
	maxMetadataCreatedAtLen = 64

	maxTraceIdLen       = 32
	maxSpanIdLen        = 16
	maxTraceFlagsLen    = 2
	maxTraceStateLen    = 512
	maxCorrelationIdLen = 128
)
