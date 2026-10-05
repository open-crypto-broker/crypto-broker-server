package api

import "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"

const (
	KB = 1024
	MB = 1024 * KB

	// gRPC transport-level limits (bytes)
	MaxGrpcRecvMsgSize = protobuf.MessageSizeLimit_MESSAGE_SIZE_LIMIT_MAX_REQUEST_BYTES
	MaxGrpcSendMsgSize = protobuf.MessageSizeLimit_MESSAGE_SIZE_LIMIT_MAX_RESPONSE_BYTES

	// Hash Data
	maxHashInputBytes = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_HASH_DATA_INPUT_MAX_LEN)

	// EncryptData / DecryptData
	maxEncryptionDataBytes  = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_DATA_MAX_LEN)
	maxEncryptionAADBytes   = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_AAD_MAX_LEN)
	maxEncryptionKeyIDLen   = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_KEYSOURCE_KEY_ID_MAX_LEN)
	maxEncryptionKeyBytes   = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_KEYSOURCE_KEY_RAW_MAX_LEN)
	maxEncryptionNonceBytes = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_NONCE_MAX_LEN)
	maxEncryptionTagBytes   = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_ENCRYPT_DECRYPT_DATA_TAG_MAX_LEN)

	// SignCertificate (PEM strings)
	maxCSRBytes          = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CSR_MAX_LEN)
	maxCAPrivateKeyBytes = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CA_PRIVATE_KEY_MAX_LEN)
	maxCACertBytes       = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_CA_CERT_MAX_LEN)
	maxSubjectLen        = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_SUBJECT_MAX_LEN)

	maxCRLDistributionPoints   = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_DISTRIBUTION_POINTS_MAX)
	maxCRLDistributionPointLen = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_SIGN_CERTIFICATE_DISTRIBUTION_POINT_MAX_LEN)

	// SignData / VerifyData (PEM keys and raw signatures)
	maxSigningDataBytes = 1 * MB
	maxSigningKeyBytes  = 64 * KB
	maxSignatureBytes   = 128 * KB

	// Metadata / trace propagation
	maxMetadataIdLen = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_METADATA_ID_MAX_LEN)

	maxTraceIdLen       = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_ID_MAX_LEN)
	maxSpanIdLen        = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_SPAN_ID_MAX_LEN)
	maxTraceFlagsLen    = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_FLAGS_MAX_LEN)
	maxTraceStateLen    = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_STATE_MAX_LEN)
	maxCorrelationIdLen = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_TRACE_CORRELATION_ID_MAX_LEN)
)
