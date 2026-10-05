package profile

import (
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

const MaxNameLen = int(protobuf.PayloadLimits_PAYLOAD_LIMITS_PROFILE_MAX_LEN)

func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("required")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("too large (max %d)", MaxNameLen)
	}
	return nil
}
