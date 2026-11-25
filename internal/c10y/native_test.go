package c10y

import (
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"reflect"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/cache"
)

// newTestLibraryNative builds a LibraryNative backed by a default in-memory cache.
func newTestLibraryNative() *LibraryNative {
	return NewLibraryNative(cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig))
}

func mustHex(s string) Hash {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mustHex: invalid hex string: " + err.Error())
	}
	return Hash(b)
}

func TestLibraryNative_computeSubjectKeyIdentifier(t *testing.T) {
	spkiDER, err := asn1.Marshal(struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}{
		Algorithm:        pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
		SubjectPublicKey: asn1.BitString{Bytes: []byte("subject-public-key"), BitLength: len("subject-public-key") * 8},
	})
	if err != nil {
		t.Fatalf("failed to marshal test SPKI: %v", err)
	}

	tests := []struct {
		name      string
		algorithm Algorithm
		want      Hash
		wantErr   bool
	}{
		{name: "sha-1", algorithm: SHA_1, want: mustHex("13972225ed3dbed5493964ea97b2384fa2ef5db9")},
		{name: "sha-256", algorithm: SHA_256, want: mustHex("5a926725ff7fa2013771f03e879e49b24342e265")},
		{name: "sha-384", algorithm: SHA_384, want: mustHex("29167ee5cfd41bf3a6ae982ab52ac26de125a4a6")},
		{name: "sha-512", algorithm: SHA_512, want: mustHex("328e06856cc544f71931934123bab0152cfb47c4")},
		{name: "sha3-256", algorithm: SHA3_256, want: mustHex("9ca4278434dd4705eaa2d08ab6461cf895b61db2")},
		{name: "sha3-384", algorithm: SHA3_384, want: mustHex("90f11e6d78a184b69215aeab6645f85394178673")},
		{name: "sha3-512", algorithm: SHA3_512, want: mustHex("49710e7f4bfc76870e343547b4bb747f80d22fde")},
		{name: "empty algorithm defaults to sha-1", algorithm: "", want: mustHex("13972225ed3dbed5493964ea97b2384fa2ef5db9")},
		{name: "unknown algorithm", algorithm: "md5", wantErr: true},
	}

	service := newTestLibraryNative()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := service.computeSubjectKeyIdentifier(spkiDER, tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Fatalf("computeSubjectKeyIdentifier() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && !reflect.DeepEqual(got, []byte(tt.want)) {
				t.Errorf("computeSubjectKeyIdentifier() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestLibraryNative_HashSHA3_256(t *testing.T) {
	type args struct {
		dataToHash []byte
	}
	tests := []struct {
		name    string
		service *LibraryNative
		args    args
		want    Hash
		wantErr bool
	}{
		{
			name:    "HashSHA3_256() correctly hashes with SHA3-256 hashing algorithm",
			service: newTestLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    mustHex("369183d3786773cef4e56c7b849e7ef5f742867510b676d6b38f8e38a222d8a2"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &LibraryNative{}
			got, err := service.HashSHA3_256(tt.args.dataToHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("LibraryNative.HashSHA3_256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LibraryNative.HashSHA3_256() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLibraryNative_HashSHA3_384(t *testing.T) {
	type args struct {
		dataToHash []byte
	}
	tests := []struct {
		name    string
		service *LibraryNative
		args    args
		want    Hash
		wantErr bool
	}{
		{
			name:    "HashSHA3_384() correctly hashes with SHA3-384 hashing algorithm",
			service: newTestLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    mustHex("ff3917192427ea1aa7f3ad47ac10152d179af30126c52835ee8dc7e6ea12aed91ad91b316e15c3b250469ef17a03e529"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &LibraryNative{}
			got, err := service.HashSHA3_384(tt.args.dataToHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("LibraryNative.HashSHA3_384() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LibraryNative.HashSHA3_384() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLibraryNative_HashSHA3_512(t *testing.T) {
	type args struct {
		dataToHash []byte
	}
	tests := []struct {
		name    string
		service *LibraryNative
		args    args
		want    Hash
		wantErr bool
	}{
		{
			name:    "HashSHA3_512() correctly hashes with SHA3-512 hashing algorithm",
			service: newTestLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    mustHex("e2e1c9e522efb2495a178434c8bb8f11000ca23f1fd679058b7d7e141f0cf3433f94fc427ec0b9bebb12f327a3240021053db6091196576d5e6d9bd8fac71c0c"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &LibraryNative{}
			got, err := service.HashSHA3_512(tt.args.dataToHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("LibraryNative.HashSHA3_512() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LibraryNative.HashSHA3_512() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLibraryNative_HashSHA_256(t *testing.T) {
	type args struct {
		dataToHash []byte
	}
	tests := []struct {
		name    string
		service *LibraryNative
		args    args
		want    Hash
		wantErr bool
	}{
		{
			name:    "HashSHA_256() correctly hashes with SHA-256 hashing algorithm",
			service: newTestLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    mustHex("64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &LibraryNative{}
			got, err := service.HashSHA_256(tt.args.dataToHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("LibraryNative.HashSHA_256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LibraryNative.HashSHA_256() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLibraryNative_HashSHA_384(t *testing.T) {
	type args struct {
		dataToHash []byte
	}
	tests := []struct {
		name    string
		service *LibraryNative
		args    args
		want    Hash
		wantErr bool
	}{
		{
			name:    "HashSHA_384() correctly hashes with SHA-384 hashing algorithm",
			service: newTestLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    mustHex("9203b0c4439fd1e6ae5878866337b7c532acd6d9260150c80318e8ab8c27ce330189f8df94fb890df1d298ff360627e1"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &LibraryNative{}
			got, err := service.HashSHA_384(tt.args.dataToHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("LibraryNative.HashSHA_384() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LibraryNative.HashSHA_384() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLibraryNative_HashSHA_512(t *testing.T) {
	type args struct {
		dataToHash []byte
	}
	tests := []struct {
		name    string
		service *LibraryNative
		args    args
		want    Hash
		wantErr bool
	}{
		{
			name:    "HashSHA_512() correctly hashes with SHA-512 hashing algorithm",
			service: newTestLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    mustHex("b7f783baed8297f0db917462184ff4f08e69c2d5e5f79a942600f9725f58ce1f29c18139bf80b06c0fff2bdd34738452ecf40c488c22a7e3d80cdf6f9c1c0d47"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &LibraryNative{}
			got, err := service.HashSHA_512(tt.args.dataToHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("LibraryNative.HashSHA_512() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LibraryNative.HashSHA_512() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLibraryNative_HashSHA_512_256(t *testing.T) {
	type args struct {
		dataToHash []byte
	}
	tests := []struct {
		name    string
		service *LibraryNative
		args    args
		want    Hash
		wantErr bool
	}{
		{
			name:    "HashSHA_512_256() correctly hashes with SHA512-256 hashing algorithm",
			service: newTestLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    mustHex("f7b55872d4aefe68143bd2ebd928b87f769e15362fcd5a1af8da184bbfcb5fa8"),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &LibraryNative{}
			got, err := service.HashSHA_512_256(tt.args.dataToHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("LibraryNative.HashSHA_512_256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("LibraryNative.HashSHA_512_256() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLibraryNative_ParseRSAPrivateKeyFromPKCS8DER(t *testing.T) {
	pkcs8DER := rsaTestKeyDER(t)
	parsedKey, err := ParsePrivateKeyFromPKCS8DER(pkcs8DER)
	if err != nil {
		t.Fatalf("could not parse PKCS#8 private key fixture: %v", err)
	}
	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("fixture key type = %T, want *rsa.PrivateKey", parsedKey)
	}

	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{name: "accepts PKCS#8 DER", key: pkcs8DER},
		{name: "rejects PEM", key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}), wantErr: true},
		{name: "rejects PKCS#1 DER", key: x509.MarshalPKCS1PrivateKey(rsaKey), wantErr: true},
		{name: "rejects empty input", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newTestLibraryNative().parseRSAPrivateKeyFromPKCS8DER(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseRSAPrivateKeyFromPKCS8DER() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLibraryNative_composeAttributeTypeAndValue(t *testing.T) {
	tests := []struct {
		name    string
		part    string
		want    []pkix.AttributeTypeAndValue
		wantErr bool
	}{
		{
			name:    "composeAttributeTypeAndValue() returns nil error & nil pkix.AttributeTypeAndValue if the part is empty",
			part:    "  ",
			want:    nil,
			wantErr: false,
		},
		{
			name:    "composeAttributeTypeAndValue() returns nil error & pkix.AttributeTypeAndValue if the part is valid",
			part:    "C=DE",
			want:    []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "DE"}},
			wantErr: false,
		},
		{
			name:    "composeAttributeTypeAndValue() returns nil error & pkix.AttributeTypeAndValue if the part is valid with spaces around =",
			part:    "C = DE",
			want:    []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 6}, Value: "DE"}},
			wantErr: false,
		},
		{
			name:    "composeAttributeTypeAndValue() returns nil error & pkix.AttributeTypeAndValue if the part is valid",
			part:    "O=SAP SE",
			want:    []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 10}, Value: "SAP SE"}},
			wantErr: false,
		},
		{
			name:    "composeAttributeTypeAndValue() returns nil error & pkix.AttributeTypeAndValue if the part is valid",
			part:    "OU=SAP Cloud Platform Certificate Service Test Clients",
			want:    []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 11}, Value: "SAP Cloud Platform Certificate Service Test Clients"}},
			wantErr: false,
		},
		{
			name:    "composeAttributeTypeAndValue() returns nil error & pkix.AttributeTypeAndValue if the part is valid",
			part:    "L=test",
			want:    []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 7}, Value: "test"}},
			wantErr: false,
		},
		{
			name:    "composeAttributeTypeAndValue() returns nil error & pkix.AttributeTypeAndValue if the part is valid",
			part:    "CN=test",
			want:    []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "test"}},
			wantErr: false,
		},
		{
			name:    "composeAttributeTypeAndValue() returns non-nil error & nil pkix.AttributeTypeAndValue if the part is invalid #1",
			part:    "ABC=def",
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := newTestLibraryNative()
			got, gotErr := service.composeAttributeTypeAndValue(tt.part)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("composeAttributeTypeAndValue() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("composeAttributeTypeAndValue() succeeded unexpectedly")
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("composeAttributeTypeAndValue() = %v, want %v", got, tt.want)
			}
		})
	}
}
