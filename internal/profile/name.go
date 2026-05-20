package profile

import "fmt"

const MaxNameLen = 64

func ValidateName(name string) error {
	if name == "" {
		return fmt.Errorf("required")
	}
	if len(name) > MaxNameLen {
		return fmt.Errorf("too large (max %d)", MaxNameLen)
	}
	return nil
}
