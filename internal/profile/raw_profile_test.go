package profile

import (
	"crypto/x509"
	"reflect"
	"strings"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
)

func TestRawProfileSettings_validate(t *testing.T) {
	tests := []struct {
		name    string
		in      rawProfileSettings
		wantErr bool
	}{
		{
			name: "validates known crypto library (case-insensitive)",
			in: rawProfileSettings{
				CryptoLibrary: "NATIVE",
			},
			wantErr: false,
		},
		{
			name: "rejects unknown crypto library",
			in: rawProfileSettings{
				CryptoLibrary: "unknown",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRawProfileAPI_validate_requiresAtLeastOneAPI(t *testing.T) {
	err := (rawProfileAPI{}).validate()
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestRawProfileAPIHashData_validate(t *testing.T) {
	tests := []struct {
		name    string
		in      rawProfileAPIHashData
		wantErr bool
	}{
		{
			name: "accepts supported algorithm (case-insensitive)",
			in: rawProfileAPIHashData{
				HashAlg: "SHA3-512",
			},
			wantErr: false,
		},
		{
			name: "rejects unsupported algorithm",
			in: rawProfileAPIHashData{
				HashAlg: "md5",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRawProfileAPISignCertificateValidity_validate(t *testing.T) {
	tests := []struct {
		name    string
		in      rawProfileAPISignCertificateValidity
		wantErr bool
	}{
		{
			name: "valid offsets",
			in: rawProfileAPISignCertificateValidity{
				NotBeforeOffset: "-1h",
				NotAfterOffset:  "24h",
			},
			wantErr: false,
		},
		{
			name: "rejects invalid duration string",
			in: rawProfileAPISignCertificateValidity{
				NotBeforeOffset: "abc",
				NotAfterOffset:  "1h",
			},
			wantErr: true,
		},
		{
			name: "rejects when after is earlier than before",
			in: rawProfileAPISignCertificateValidity{
				NotBeforeOffset: "2h",
				NotAfterOffset:  "1h",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRawProfileAPISignCertificateBasicConstraints_validate(t *testing.T) {
	pathLen := 0
	err := (rawProfileAPISignCertificateBasicConstraints{
		CA:                false,
		PathLenConstraint: &pathLen,
	}).validate()
	if err == nil {
		t.Fatalf("expected error when PathLenConstraint is set but CA=false")
	}
}

func TestRawProfileAPISignCertificateKeyConstraints_validate_negativeSizes(t *testing.T) {
	err := (rawProfileAPISignCertificateKeyConstraints{
		Subject: map[string]rawProfileAPISignCertificateKeyConstraintsLimits{
			"rsa": {MinKeySize: -1, MaxKeySize: 2048},
		},
	}).validate()
	if err == nil {
		t.Fatalf("expected error for negative minKeySize in Subject")
	}
}

func TestRawProfileAPISignCertificateKeyConstraints_validate_negativeSizesIssuer(t *testing.T) {
	err := (rawProfileAPISignCertificateKeyConstraints{
		Issuer: map[string]rawProfileAPISignCertificateKeyConstraintsLimits{
			"ecdsa": {MinKeySize: 256, MaxKeySize: -1},
		},
	}).validate()
	if err == nil {
		t.Fatalf("expected error for negative maxKeySize in Issuer")
	}
}

func TestRawProfileAPISignCertificate_validate_rejectsUnsupportedUsageOrAlgorithms(t *testing.T) {
	tests := []struct {
		name    string
		in      rawProfileAPISignCertificate
		wantErr bool
	}{
		{
			name: "rejects unsupported key usage",
			in: rawProfileAPISignCertificate{
				SignAlg: "ecdsa",
				HashAlg: "sha-512",
				Validity: rawProfileAPISignCertificateValidity{
					NotBeforeOffset: "-1h",
					NotAfterOffset:  "1h",
				},
				KeyConstraints: rawProfileAPISignCertificateKeyConstraints{},
				KeyUsage:       []string{"totallyNotAUsage"},
				BasicConstraints: rawProfileAPISignCertificateBasicConstraints{
					CA: false,
				},
			},
			wantErr: true,
		},
		{
			name: "rejects unsupported extended key usage",
			in: rawProfileAPISignCertificate{
				SignAlg: "ecdsa",
				HashAlg: "sha-512",
				Validity: rawProfileAPISignCertificateValidity{
					NotBeforeOffset: "-1h",
					NotAfterOffset:  "1h",
				},
				KeyConstraints:   rawProfileAPISignCertificateKeyConstraints{},
				ExtendedKeyUsage: []string{"totallyNotAnEKU"},
				BasicConstraints: rawProfileAPISignCertificateBasicConstraints{CA: false},
			},
			wantErr: true,
		},
		{
			name: "rejects unsupported signature/hash algorithm pair",
			in: rawProfileAPISignCertificate{
				SignAlg: "sha3-512",
				HashAlg: "ecdsa",
				Validity: rawProfileAPISignCertificateValidity{
					NotBeforeOffset: "-1h",
					NotAfterOffset:  "1h",
				},
				KeyConstraints:   rawProfileAPISignCertificateKeyConstraints{},
				BasicConstraints: rawProfileAPISignCertificateBasicConstraints{CA: false},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.in.validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRawProfileAPISignCertificate_validateSKIHashAlgorithm(t *testing.T) {
	validSignCertificate := rawProfileAPISignCertificate{
		SignAlg: "ecdsa",
		HashAlg: "sha-512",
		Validity: rawProfileAPISignCertificateValidity{
			NotBeforeOffset: "-1h",
			NotAfterOffset:  "1h",
		},
		BasicConstraints: rawProfileAPISignCertificateBasicConstraints{CA: false},
	}

	for _, algorithm := range []string{"sha-1", "sha-256", "sha-384", "sha-512", "sha3-256", "sha3-384", "sha3-512"} {
		t.Run("accepts "+algorithm, func(t *testing.T) {
			input := validSignCertificate
			input.SKIHashAlg = algorithm
			if err := input.validate(); err != nil {
				t.Fatalf("validate() error = %v", err)
			}
		})
	}

	t.Run("rejects unknown algorithm", func(t *testing.T) {
		input := validSignCertificate
		input.SKIHashAlg = "md5"
		err := input.validate()
		if err == nil || !strings.Contains(err.Error(), "unsupported SKI hash algorithm: md5") {
			t.Fatalf("validate() error = %v, want unsupported SKI hash algorithm error", err)
		}
	})
}

func TestRawProfile_mapToProfile_mapsSignCertificateFields(t *testing.T) {
	rp := rawProfile{
		Name: "MyProfile",
		Settings: rawProfileSettings{
			CryptoLibrary: "NATIVE",
		},
		API: rawProfileAPI{
			SignCertificate: rawProfileAPISignCertificate{
				SignAlg:    "ecdsa",
				HashAlg:    "sha-512",
				SKIHashAlg: "sha-256",
				Validity: rawProfileAPISignCertificateValidity{
					NotBeforeOffset: "-1h",
					NotAfterOffset:  "24h",
				},
				KeyConstraints: rawProfileAPISignCertificateKeyConstraints{
					Subject: map[string]rawProfileAPISignCertificateKeyConstraintsLimits{
						"rsa": {MinKeySize: 2048, MaxKeySize: 4096},
					},
					Issuer: map[string]rawProfileAPISignCertificateKeyConstraintsLimits{
						"ecdsa": {MinKeySize: 256, MaxKeySize: 521},
					},
				},
				KeyUsage:         []string{c10y.KeyUsageDigitalSignature, c10y.KeyUsageKeyCertSign},
				ExtendedKeyUsage: []string{c10y.ExtKeyUsageClientAuth},
				BasicConstraints: rawProfileAPISignCertificateBasicConstraints{
					CA:                false,
					PathLenConstraint: nil,
				},
			},
		},
	}

	got, err := rp.mapToProfile()
	if err != nil {
		t.Fatalf("mapToProfile() unexpected error: %v", err)
	}

	if got.Name != "MyProfile" {
		t.Fatalf("Name = %q, want %q", got.Name, "MyProfile")
	}
	if got.Settings.CryptoLibrary != "native" {
		t.Fatalf("CryptoLibrary = %q, want %q", got.Settings.CryptoLibrary, "native")
	}

	if got.API.SignCertificate.SignAlg != c10y.ECDSA || got.API.SignCertificate.HashAlg != c10y.SHA_512 {
		t.Fatalf("SignAlg/HashAlg = %q/%q, want %q/%q",
			got.API.SignCertificate.SignAlg, got.API.SignCertificate.HashAlg, c10y.ECDSA, c10y.SHA_512)
	}
	if got.API.SignCertificate.SignatureAlgorithm != x509.ECDSAWithSHA512 {
		t.Fatalf("SignatureAlgorithm = %v, want %v", got.API.SignCertificate.SignatureAlgorithm, x509.ECDSAWithSHA512)
	}
	if got.API.SignCertificate.SKIHashAlg != c10y.SHA_256 {
		t.Fatalf("SKIHashAlg = %q, want %q", got.API.SignCertificate.SKIHashAlg, c10y.SHA_256)
	}
	if got.API.SignCertificate.BasicConstraints.PathLenConstraint != -1 {
		t.Fatalf("PathLenConstraint = %d, want -1 when unset", got.API.SignCertificate.BasicConstraints.PathLenConstraint)
	}

	if !reflect.DeepEqual(got.API.SignCertificate.KeyUsage, []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageCertSign}) {
		t.Fatalf("KeyUsage = %#v, want %#v", got.API.SignCertificate.KeyUsage,
			[]x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageCertSign})
	}
	if !reflect.DeepEqual(got.API.SignCertificate.ExtendedKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		t.Fatalf("ExtendedKeyUsage = %#v, want %#v", got.API.SignCertificate.ExtendedKeyUsage,
			[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})
	}

	if got.API.SignCertificate.KeyConstraints.Subject[c10y.RSA].MinKeySize != 2048 ||
		got.API.SignCertificate.KeyConstraints.Subject[c10y.RSA].MaxKeySize != 4096 {
		t.Fatalf("Subject key constraints not mapped correctly: %#v", got.API.SignCertificate.KeyConstraints.Subject[c10y.RSA])
	}
	if got.API.SignCertificate.KeyConstraints.Issuer[c10y.ECDSA].MinKeySize != 256 ||
		got.API.SignCertificate.KeyConstraints.Issuer[c10y.ECDSA].MaxKeySize != 521 {
		t.Fatalf("Issuer key constraints not mapped correctly: %#v", got.API.SignCertificate.KeyConstraints.Issuer[c10y.ECDSA])
	}
}

func TestRawProfile_mapToProfile_defaultsSKIHashAlgorithmToSHA1(t *testing.T) {
	rp := rawProfile{
		Name:     "MyProfile",
		Settings: rawProfileSettings{CryptoLibrary: "native"},
		API: rawProfileAPI{SignCertificate: rawProfileAPISignCertificate{
			SignAlg: "ecdsa",
			HashAlg: "sha-512",
			Validity: rawProfileAPISignCertificateValidity{
				NotBeforeOffset: "-1h",
				NotAfterOffset:  "1h",
			},
			BasicConstraints: rawProfileAPISignCertificateBasicConstraints{CA: false},
		}},
	}

	got, err := rp.mapToProfile()
	if err != nil {
		t.Fatalf("mapToProfile() unexpected error: %v", err)
	}
	if got.API.SignCertificate.SKIHashAlg != c10y.SHA_1 {
		t.Fatalf("SKIHashAlg = %q, want %q", got.API.SignCertificate.SKIHashAlg, c10y.SHA_1)
	}
}
