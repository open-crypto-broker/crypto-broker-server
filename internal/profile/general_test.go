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

func Test_convertRawProfilesData(t *testing.T) {
	tests := []struct {
		name        string
		rawProfiles []rawProfile
		want        map[string]Profile
		wantErr     bool
	}{
		{
			name: "convertRawProfilesData() succeeds if provided valid raw profiles",
			rawProfiles: []rawProfile{
				{
					Name: "Default",
					Settings: rawProfileSettings{
						CryptoLibrary: "native",
					},
					API: rawProfileAPI{
						HashData: rawProfileAPIHashData{
							HashAlg: "sha3-512",
						},
						SignData: rawProfileAPISignData{
							SignAlg: "ecdsa",
						},
					},
				},
			},
			want: map[string]Profile{
				"Default": {
					Name:     "Default",
					Settings: ProfileSettings{CryptoLibrary: "native"},
					API: ProfileAPI{
						SignCertificate: ProfileAPISignCertificate{
							SignAlg:            "",
							HashAlg:            "",
							SignatureAlgorithm: 0,
							Validity:           ProfileAPISignCertificateValidity{NotBeforeOffset: 0, NotAfterOffset: 0},
							KeyConstraints: ProfileAPISignCertificateKeyConstraints{
								Subject: map[c10y.Algorithm]c10y.BitSizeConstraints(nil),
								Issuer:  map[c10y.Algorithm]c10y.BitSizeConstraints(nil)},
							KeyUsage:         []x509.KeyUsage(nil),
							ExtendedKeyUsage: []x509.ExtKeyUsage(nil),
							BasicConstraints: ProfileAPISignCertificateBasicConstraints{CA: false, PathLenConstraint: 0}},
						HashData: ProfileAPIHashData{HashAlg: "sha3-512"},
						SignData: ProfileAPISignData{SignAlg: "ecdsa"},
					}},
			},
			wantErr: false,
		},
		{
			name: "convertRawProfilesData() returns error if there are duplicate profile names",
			rawProfiles: []rawProfile{
				{
					Name: "Default",
					Settings: rawProfileSettings{
						CryptoLibrary: "native",
					},
					API: rawProfileAPI{
						HashData: rawProfileAPIHashData{
							HashAlg: "sha3-512",
						},
						SignData: rawProfileAPISignData{
							SignAlg: "ecdsa",
						},
					},
				},
				{
					Name: "Default",
					Settings: rawProfileSettings{
						CryptoLibrary: "native",
					},
					API: rawProfileAPI{
						HashData: rawProfileAPIHashData{
							HashAlg: "sha3-256",
						},
						SignData: rawProfileAPISignData{
							SignAlg: "ecdsa",
						},
					},
				},
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := convertRawProfilesData(tt.rawProfiles)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("convertRawProfilesData() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("convertRawProfilesData() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("convertRawProfilesData() = %#v,\n want %#v", got, tt.want)
			}
		})
	}
}
