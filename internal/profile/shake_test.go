package profile

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadProfilesSHAKEOutputBounds(t *testing.T) {
	originalRoot, originalProfiles := profilesRootDir, profiles
	originalSettings, originalKMS := settingsConfiguration, kmsConfiguration
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	profilesRootDir = root
	t.Cleanup(func() {
		profilesRootDir, profiles = originalRoot, originalProfiles
		settingsConfiguration, kmsConfiguration = originalSettings, originalKMS
		_ = root.Close()
	})
	tests := []struct {
		name, algorithm, fields, wantErr string
		wantMin, wantMax                 int
	}{
		{name: "SHAKE128 defaults", algorithm: "shake-128", wantMin: 32, wantMax: 32},
		{name: "SHAKE256 defaults", algorithm: "SHAKE-256", wantMin: 64, wantMax: 64},
		{name: "minimum becomes default maximum", algorithm: "shake-128", fields: "MinOutputBytes: 96", wantMin: 96, wantMax: 96},
		{name: "maximum only", algorithm: "shake-256", fields: "MaxOutputBytes: 128", wantMin: 64, wantMax: 128},
		{name: "server maximum", algorithm: "shake-128", fields: "MinOutputBytes: 1024\nMaxOutputBytes: 1024", wantMin: 1024, wantMax: 1024},
		{name: "SHAKE128 security floor", algorithm: "shake-128", fields: "MinOutputBytes: 16", wantErr: "32 bytes required for 128-bit collision security"},
		{name: "SHAKE256 security floor", algorithm: "shake-256", fields: "MinOutputBytes: 32", wantErr: "64 bytes required for 256-bit collision security"},
		{name: "explicit zero minimum", algorithm: "shake-128", fields: "MinOutputBytes: 0", wantErr: "collision security"},
		{name: "negative minimum", algorithm: "shake-128", fields: "MinOutputBytes: -1", wantErr: "collision security"},
		{name: "explicit zero maximum", algorithm: "shake-256", fields: "MaxOutputBytes: 0", wantErr: "exceeds MaxOutputBytes 0"},
		{name: "negative maximum", algorithm: "shake-256", fields: "MaxOutputBytes: -1", wantErr: "exceeds MaxOutputBytes -1"},
		{name: "maximum too large", algorithm: "shake-128", fields: "MaxOutputBytes: 2048", wantErr: "server limit of 1024 bytes"},
		{name: "reversed range", algorithm: "shake-256", fields: "MinOutputBytes: 128\nMaxOutputBytes: 64", wantErr: "MinOutputBytes 128 exceeds MaxOutputBytes 64"},
		{name: "SHA2 minimum", algorithm: "sha-256", fields: "MinOutputBytes: 32", wantErr: "only allowed for SHAKE"},
		{name: "SHA3 maximum", algorithm: "sha3-512", fields: "MaxOutputBytes: 64", wantErr: "only allowed for SHAKE"},
		{name: "SHA explicit zero", algorithm: "sha-256", fields: "MinOutputBytes: 0", wantErr: "only allowed for SHAKE"},
		{name: "fixed hash unchanged", algorithm: "sha-256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fields := ""
			if tt.fields != "" {
				fields = "\n        " + strings.ReplaceAll(tt.fields, "\n", "\n        ")
			}
			content := fmt.Sprintf("Settings:\n  CryptoLibrary: native\nProfiles:\n  - Name: HashTest\n    API:\n      HashData:\n        HashAlg: %s%s\n", tt.algorithm, fields)
			if err := os.WriteFile(filepath.Join(root.Name(), "Profiles.yaml"), []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			err := LoadProfiles("Profiles.yaml")
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("LoadProfiles() = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			p, err := Retrieve("HashTest")
			if err != nil {
				t.Fatal(err)
			}
			if got := p.API.HashData; got.MinOutputBytes != tt.wantMin || got.MaxOutputBytes != tt.wantMax {
				t.Fatalf("resolved range = [%d, %d], want [%d, %d]", got.MinOutputBytes, got.MaxOutputBytes, tt.wantMin, tt.wantMax)
			}
		})
	}
}
