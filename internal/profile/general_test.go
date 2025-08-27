package profile

import (
	"crypto/x509"
	"reflect"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
)

func TestLoadProfiles(t *testing.T) {
	type args struct {
		profilesFileName string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "LoadProfiles() returns error if provided not existing file path",
			args: args{
				profilesFileName: "abc.txt",
			},
			wantErr: true,
		},
		{
			name: "LoadProfiles() returns succeeds if provided valid path to file with YAML encoded profiles within expected dir",
			args: args{
				profilesFileName: "Profiles.yaml",
			},
			wantErr: false,
		},
		{
			name: "LoadProfiles() returns error if provided valid path to file outside of root dir",
			args: args{
				profilesFileName: "/usr/bin/cat",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := LoadProfiles(tt.args.profilesFileName); (err != nil) != tt.wantErr {
				t.Errorf("LoadProfiles() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRetrieve(t *testing.T) {
	if err := LoadProfiles("Profiles.yaml"); err != nil {
		t.Fatal("could not load profiles")
	}

	type args struct {
		name string
	}
	tests := []struct {
		name    string
		args    args
		want    Profile
		wantErr bool
	}{
		{
			name: "Retrieve of Default profile succeeds",
			args: args{
				name: "Default",
			},
			want: Profile{
				Name:     "Default",
				Settings: ProfileSettings{CryptoLibrary: "native"},
				API: ProfileAPI{
					HashData: ProfileAPIHashData{HashAlg: "sha3-512"},
					SignData: ProfileAPISignData{SignAlg: ""},
					SignCertificate: ProfileAPISignCertificate{
						SignatureAlgorithm: 12,
						SignAlg:            "ecdsa",
						HashAlg:            "sha-512",
						Validity:           ProfileAPISignCertificateValidity{NotBeforeOffset: -3600000000000, NotAfterOffset: 31536000000000000},
						KeyConstraints: ProfileAPISignCertificateKeyConstraints{
							Subject: map[c10y.Algorithm]c10y.BitSizeConstraints{
								c10y.RSA:   {MinKeySize: 2048, MaxKeySize: 4096},
								c10y.ECDSA: {MinKeySize: 256, MaxKeySize: 521},
							},
							Issuer: map[c10y.Algorithm]c10y.BitSizeConstraints{
								c10y.RSA:   {MinKeySize: 3072, MaxKeySize: 8192},
								c10y.ECDSA: {MinKeySize: 384, MaxKeySize: 521},
							},
						},
						KeyUsage:         []x509.KeyUsage{1, 4},
						ExtendedKeyUsage: []x509.ExtKeyUsage{2},
						BasicConstraints: ProfileAPISignCertificateBasicConstraints{
							CA:                false,
							PathLenConstraint: -1,
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Retrieve() returns error when asking for non-existing profile",
			args: args{
				name: "abc",
			},
			wantErr: true,
			want:    Profile{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Retrieve(tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("Retrieve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Retrieve() = %#v,\n want %#v", got, tt.want)
			}
		})
	}
}
