package api

import "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"

// Size limits are intentionally conservative; they bound memory usage and avoid
// expensive parsing work on obviously unreasonable input.
//
// These values are internal implementation details and can be tuned later.
const (
	KB = 1024
	MB = 1024 * KB

	// gRPC transport-level limits (bytes)
	MaxGrpcRecvMsgSize = protobuf.MessageSizeLimit_MESSAGE_SIZE_LIMIT_MAX_REQUEST_BYTES
	MaxGrpcSendMsgSize = protobuf.MessageSizeLimit_MESSAGE_SIZE_LIMIT_MAX_RESPONSE_BYTES

	// Hash Data
	maxHashInputBytes = 1 * MB

	// EncryptData / DecryptData
	maxEncryptionDataBytes  = 1 * MB
	maxEncryptionAADBytes   = 64 * KB
	maxEncryptionKeyBytes   = 32
	maxEncryptionNonceBytes = 32
	maxEncryptionTagBytes   = 32

	// SignCertificate (PEM strings)
	maxCSRBytes          = 64 * KB
	maxCAPrivateKeyBytes = 64 * KB
	maxCACertBytes       = 64 * KB
	maxSubjectLen        = 1024

	maxCRLDistributionPoints   = 16
	maxCRLDistributionPointLen = 2048

	// Metadata / trace propagation
	maxMetadataIdLen = 128

	maxTraceIdLen       = 32
	maxSpanIdLen        = 16
	maxTraceFlagsLen    = 2
	maxTraceStateLen    = 512
	maxCorrelationIdLen = 128
)
