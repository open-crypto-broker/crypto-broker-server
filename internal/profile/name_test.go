package profile

import (
	"strings"
	"testing"
)

func TestValidateName(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{
			name: "allows max length",
			in:   strings.Repeat("A", MaxNameLen),
		},
		{
			name:    "rejects empty",
			wantErr: true,
		},
		{
			name:    "rejects oversized",
			in:      strings.Repeat("A", MaxNameLen+1),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateName(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateName() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
