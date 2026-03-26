package c10y_test

import (
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
)

func TestNewAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		want      c10y.Algorithm
	}{
		{
			name:      "NewAlgorithm() sha3-256 correctly normalizes algorithm",
			algorithm: "sha3-256",
			want:      c10y.SHA3_256,
		},
		{
			name:      "NewAlgorithm() sha3-384 correctly normalizes algorithm",
			algorithm: "SHA3-384",
			want:      c10y.SHA3_384,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := c10y.NewAlgorithm(tt.algorithm)

			if got != tt.want {
				t.Errorf("NewAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithm_IsSupported(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		operation c10y.Operation
		want      bool
	}{
		{
			name:      "Algorithm_IsSupported() returns true given algorithm: SHA3_256, operation: HashData",
			algorithm: c10y.SHA3_256.String(),
			operation: c10y.HashData,
			want:      true,
		},
		{
			name:      "Algorithm_IsSupported() returns false given algorithm: SHA3_256, operation: SignCertificateSigning",
			algorithm: c10y.SHA3_256.String(),
			operation: c10y.SignCertificateSigning,
			want:      false,
		},
		{
			name:      "Algorithm_IsSupported() returns false given algorithm: SHA3_256, operation: SignCertificateHashing",
			algorithm: c10y.SHA3_256.String(),
			operation: c10y.SignCertificateHashing,
			want:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg := c10y.NewAlgorithm(tt.algorithm)
			got := alg.IsSupported(tt.operation)
			if got != tt.want {
				t.Errorf("Algorithm_IsSupported() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithm_String(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		want      string
	}{
		{
			name:      "Algorithm_String() returns sha3-256 given algorithm: SHA3_256",
			algorithm: c10y.SHA3_256.String(),
			want:      "sha3-256",
		},
		{
			name:      "Algorithm_String() returns sha3-384 given algorithm: SHA3_384",
			algorithm: c10y.SHA3_384.String(),
			want:      "sha3-384",
		},
		{
			name:      "Algorithm_String() returns sha-256 given algorithm: SHA_256 uppercased",
			algorithm: "SHA-256",
			want:      "sha-256",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alg := c10y.NewAlgorithm(tt.algorithm)
			got := alg.String()
			if got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}
