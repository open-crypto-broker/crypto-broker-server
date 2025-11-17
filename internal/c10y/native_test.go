package c10y

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
)

// BenchmarkLibraryNative_HashSHA3_256 to run benchmark:
// go test -benchmem -run=^$ -bench ^BenchmarkLibraryNative_HashSHA3_256$ github.com/open-crypto-broker/crypto-broker-server/internal/c10y
func BenchmarkLibraryNative_HashSHA3_256(b *testing.B) {
	service := NewLibraryNative()
	for b.Loop() {
		service.HashSHA3_256(bb)
	}
}

func BenchmarkLibraryNative_HashSHA3_384(b *testing.B) {
	service := NewLibraryNative()
	for b.Loop() {
		service.HashSHA3_384(bb)
	}
}

func BenchmarkLibraryNative_HashSHA3_512(b *testing.B) {
	service := NewLibraryNative()
	for b.Loop() {
		service.HashSHA3_512(bb)
	}
}

func BenchmarkLibraryNative_HashSHA_256(b *testing.B) {
	service := NewLibraryNative()
	for b.Loop() {
		service.HashSHA_256(bb)
	}
}

func BenchmarkLibraryNative_HashSHA_384(b *testing.B) {
	service := NewLibraryNative()
	for b.Loop() {
		service.HashSHA_384(bb)
	}
}

func BenchmarkLibraryNative_HashSHA_512(b *testing.B) {
	service := NewLibraryNative()
	for b.Loop() {
		service.HashSHA_512(bb)
	}
}

func BenchmarkLibraryNative_HashSHA_512_256(b *testing.B) {
	service := NewLibraryNative()
	for b.Loop() {
		service.HashSHA_512_256(bb)
	}
}

func BenchmarkLibraryNative_HashShake_128(b *testing.B) {
	service := NewLibraryNative()
	for b.Loop() {
		service.HashShake_128(16, bb)
	}
}

func BenchmarkLibraryNative_HashShake_256(b *testing.B) {
	service := NewLibraryNative()
	for b.Loop() {
		service.HashShake_256(32, bb)
	}
}

func BenchmarkLibraryNative_SignCertificate(b *testing.B) {
	notAfter, err := time.ParseDuration("8760h")
	if err != nil {
		b.Fatalf("could not parse duration, err: %s", err.Error())
	}
	notBefore, err := time.ParseDuration("-1h")
	if err != nil {
		b.Fatalf("could not parse duration, err: %s", err.Error())
	}

	service := NewLibraryNative()
	optsProfile := SignProfileOpts{
		BasicConstraints: SignProfileBasicConstraints{
			IsCA:              false,
			PathLenConstraint: -1,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		Validity: SignProfileValidity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		KeyUsage:         []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment},
		ExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	caCert, err := os.ReadFile(os.Getenv(env.BENCHMARK_SIGN_CERTIFICATE_CA_CERT))
	if err != nil {
		b.Fatalf("could not read CA cert, err: %s", err.Error())
	}
	caCertParsed, err := ParseX509Cert(caCert)
	if err != nil {
		b.Fatalf("could not parse CA cert, err: %s", err.Error())
	}

	caPrivateKey, err := os.ReadFile(os.Getenv(env.BENCHMARK_SIGN_CERTIFICATE_PRIVATE_KEY))
	if err != nil {
		b.Fatalf("could not read CA private key, err: %s", err.Error())
	}
	caPrivateKeyParsed, err := ParsePrivateKeyFromPEM(caPrivateKey)
	if err != nil {
		b.Fatalf("could not parse CA private key, err: %s", err.Error())
	}

	csrBytes, err := os.ReadFile(os.Getenv(env.BENCHMARK_SIGN_CERTIFICATE_CSR))
	if err != nil {
		b.Fatalf("could not read CSR, err: %s", err.Error())
	}

	block, _ := pem.Decode([]byte(csrBytes))
	if block == nil {
		b.Fatalf("could not decode CSR as PEM file")
	}

	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		b.Fatalf("could not parse CSR, err: %s", err.Error())
	}

	if err = csrParsed.CheckSignature(); err != nil {
		b.Fatalf("invalid certificate request signature, err: %s", err.Error())
	}

	optsAPI := SignAPIOpts{
		CSR:        csrParsed,
		CACert:     caCertParsed,
		PrivateKey: caPrivateKeyParsed,
		Subject:    "C=DE, O=SAP SE, OU=SAP Cloud Platform Certificate Service Test Clients, OU=Dev, OU=cf-us10-staging-certificate-service, L=test, CN=test",
		// CrlDistributionPoints: []string{"http://example.com/crl"},
	}

	for b.Loop() {
		_, err := service.SignCertificate(optsProfile, optsAPI)
		if err != nil {
			b.Fatalf("could not sign certificate, err: %s", err.Error())
		}
	}
}

func BenchmarkLibraryNative_SignCertificate_NIST_SECP521R1_RSA4096(b *testing.B) {
	notAfter, err := time.ParseDuration("8760h")
	if err != nil {
		b.Fatalf("could not parse duration, err: %s", err.Error())
	}
	notBefore, err := time.ParseDuration("-1h")
	if err != nil {
		b.Fatalf("could not parse duration, err: %s", err.Error())
	}

	service := NewLibraryNative()
	optsProfile := SignProfileOpts{
		BasicConstraints: SignProfileBasicConstraints{
			IsCA:              false,
			PathLenConstraint: -1,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA512,
		Validity: SignProfileValidity{
			NotBefore: notBefore,
			NotAfter:  notAfter,
		},
		KeyUsage:         []x509.KeyUsage{x509.KeyUsageDigitalSignature, x509.KeyUsageKeyEncipherment},
		ExtendedKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	caCert := []byte(`Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            73:2e:df:5b:b6:30:25:66:20:e5:80:b5:54:82:be:db:b9:72:f3:26
        Signature Algorithm: ecdsa-with-SHA512
        Issuer: C=DE, ST=Bavaria, O=Test-Organization, OU=Test-Organization-CA, CN=Test-Organization-Root-CA
        Validity
            Not Before: Jan  1 01:01:01 2023 GMT
            Not After : Jan  1 01:01:01 2033 GMT
        Subject: C=DE, ST=Bavaria, O=Test-Organization, OU=Test-Organization-CA, CN=Test-Organization-Root-CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (521 bit)
                pub:
                    04:01:11:95:d7:5b:41:94:4d:15:05:36:d6:56:fc:
                    8c:95:29:8d:a4:b6:50:6d:93:1f:70:85:74:5c:66:
                    0b:01:68:eb:a2:c8:ec:d1:7a:2a:00:1b:72:e9:41:
                    cf:8f:be:15:b0:fb:7d:c6:f4:0e:d8:f3:1e:b7:49:
                    fa:78:f8:39:46:91:63:00:f8:8e:3b:fc:67:b8:04:
                    89:0f:46:60:cf:21:3e:cc:af:01:72:5b:6c:cb:22:
                    52:8f:a5:72:c5:cd:59:ae:1a:ed:99:86:60:f1:2f:
                    24:34:5c:64:e6:90:10:b8:02:7d:2f:74:8c:03:d3:
                    e3:9c:9e:7c:b9:08:b2:01:16:ab:8e:5b:28
                ASN1 OID: secp521r1
                NIST CURVE: P-521
        X509v3 extensions:
            X509v3 Basic Constraints: critical
                CA:TRUE, pathlen:1
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier: 
                26:31:1C:05:F4:5A:BE:88:F4:52:32:6C:03:FA:FA:9D:B1:9C:F4:72
            X509v3 Authority Key Identifier: 
                26:31:1C:05:F4:5A:BE:88:F4:52:32:6C:03:FA:FA:9D:B1:9C:F4:72
    Signature Algorithm: ecdsa-with-SHA512
    Signature Value:
        30:81:88:02:42:01:48:22:62:b1:78:1f:a2:b7:fb:5b:ea:6a:
        cb:57:2a:37:e1:9e:fd:76:78:d3:99:ba:ff:80:c2:8d:10:d5:
        13:ea:60:78:59:c4:5e:71:e6:0c:a4:c3:47:25:86:0c:ba:c1:
        f9:aa:07:e2:a6:74:01:c4:9f:82:d3:a0:d5:f4:72:5d:68:02:
        42:01:f0:2b:ff:17:fe:d3:27:4b:49:9f:41:69:c2:d0:81:6c:
        d5:b3:95:4a:73:e9:32:63:db:0c:f9:7b:8b:7c:d1:dc:e2:0c:
        a5:e5:fc:75:55:9b:fa:6f:8a:05:d4:45:90:be:0f:31:3d:d3:
        3b:43:72:d8:47:e7:9c:87:9b:eb:0c:86:e1
-----BEGIN CERTIFICATE-----
MIIC7DCCAk2gAwIBAgIUcy7fW7YwJWYg5YC1VIK+27ly8yYwCgYIKoZIzj0EAwQw
fjELMAkGA1UEBhMCREUxEDAOBgNVBAgMB0JhdmFyaWExGjAYBgNVBAoMEVRlc3Qt
T3JnYW5pemF0aW9uMR0wGwYDVQQLDBRUZXN0LU9yZ2FuaXphdGlvbi1DQTEiMCAG
A1UEAwwZVGVzdC1Pcmdhbml6YXRpb24tUm9vdC1DQTAeFw0yMzAxMDEwMTAxMDFa
Fw0zMzAxMDEwMTAxMDFaMH4xCzAJBgNVBAYTAkRFMRAwDgYDVQQIDAdCYXZhcmlh
MRowGAYDVQQKDBFUZXN0LU9yZ2FuaXphdGlvbjEdMBsGA1UECwwUVGVzdC1Pcmdh
bml6YXRpb24tQ0ExIjAgBgNVBAMMGVRlc3QtT3JnYW5pemF0aW9uLVJvb3QtQ0Ew
gZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAERlddbQZRNFQU21lb8jJUpjaS2UG2T
H3CFdFxmCwFo66LI7NF6KgAbculBz4++FbD7fcb0DtjzHrdJ+nj4OUaRYwD4jjv8
Z7gEiQ9GYM8hPsyvAXJbbMsiUo+lcsXNWa4a7ZmGYPEvJDRcZOaQELgCfS90jAPT
45yefLkIsgEWq45bKKNmMGQwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8E
BAMCAYYwHQYDVR0OBBYEFCYxHAX0Wr6I9FIybAP6+p2xnPRyMB8GA1UdIwQYMBaA
FCYxHAX0Wr6I9FIybAP6+p2xnPRyMAoGCCqGSM49BAMEA4GMADCBiAJCAUgiYrF4
H6K3+1vqastXKjfhnv12eNOZuv+Awo0Q1RPqYHhZxF5x5gykw0clhgy6wfmqB+Km
dAHEn4LToNX0cl1oAkIB8Cv/F/7TJ0tJn0FpwtCBbNWzlUpz6TJj2wz5e4t80dzi
DKXl/HVVm/pvigXURZC+DzE90ztDcthH55yHm+sMhuE=
-----END CERTIFICATE-----
`)
	caCertParsed, err := ParseX509Cert(caCert)
	if err != nil {
		b.Fatalf("could not parse CA cert, err: %s", err.Error())
	}

	caPrivateKey := []byte(`-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAsaSvwGS0nfPXCBX7MY0nt2VYYkOrf1dygvH8oIxyDE9LyWJ7eDBx
T77tKXW71fO1Kq0WOcocNp89wg6PMsUFZxWgBwYFK4EEACOhgYkDgYYABAERlddb
QZRNFQU21lb8jJUpjaS2UG2TH3CFdFxmCwFo66LI7NF6KgAbculBz4++FbD7fcb0
DtjzHrdJ+nj4OUaRYwD4jjv8Z7gEiQ9GYM8hPsyvAXJbbMsiUo+lcsXNWa4a7ZmG
YPEvJDRcZOaQELgCfS90jAPT45yefLkIsgEWq45bKA==
-----END EC PRIVATE KEY-----
`)
	caPrivateKeyParsed, err := ParsePrivateKeyFromPEM(caPrivateKey)
	if err != nil {
		b.Fatalf("could not parse CA private key, err: %s", err.Error())
	}

	csrBytes := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIE6DCCAtACAQAwgaIxCzAJBgNVBAYTAkRFMREwDwYDVQQKDAhUZXN0IE9yZzEl
MCMGA1UECwwcVGVzdCBPcmcgQ2VydGlmaWNhdGUgU2VydmljZTEMMAoGA1UECwwD
RGV2MSEwHwYDVQQLDBhzdGFnaW5nLWNlcnRpZmljYXRlcy0xMDExDTALBgNVBAcM
BHRlc3QxGTAXBgNVBAMMEHRlc3QtY29tbW9uLW5hbWUwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDT14Pgmm/zX2+LBGqZeX+BvAOodbNg47DKESqP72xD
4SqzJOdfcLuRDVu9EVJGm7aSx5r+1m035ldk6Pw1/bnM64BgeyOTnBjxTd0l4lfe
o5robbrCwG5aax8GsE0DeJpHmqnR7Qa0Nl9M/qX+XN/7OLrJuHkHL5CgNIAOdOKz
oKErf8kI9YawIGhKYKDruDwRQxruOzFsBFHZZpFLaXXRKauJHswyiOOrmw5d4Tq9
qT/tUOuwrJY78Ei72JbYUEwJ+/m5wqvcya5/+qcCoC0uIJh7Mm5UOSDgohU1nkCb
Q/TewhuO5oBYVSH6gCg46GkufCtjNDgDb2mExnB5Y7kinvAQ4yuMXSArlND78bO/
Um4fb4YU7VfaXMgotMN6Twx4pbjAinuBqZBl6DkeYm1yeHcnT+Mb1Izx1DlpU/Nz
KV8kC/pcb9rNTITSr05zlmOg2YIghsbpqPJFaHko49vQkEIZz8FQON2H7umyqoU4
bm1q1mYJH9US1Dkvvg3X14pHC2zWULjoBtLKLHD9SgZF5rKvwEVtOE/RiPT6fFUk
4cSRqJB+hlPIvzuUZo7XuDCMb1drdT97dz6Wiu+GncNOKhkFfKfz1lW+C7cotEnZ
XOUTn9ZTzppCKTF2/T9pwkKxcW2KKwsiViKhIvEWzy7SXyhG4fGS5AFLzFgJTU0r
hQIDAQABoAAwDQYJKoZIhvcNAQEMBQADggIBAKCNmMm0SwfxgO3h0nnHLr/9FaV6
V5WfDGcRyyl00ttJc3YWL7TxlIi49KYY1t3pvll+BRYpyvqIt//zyJQ4tYVsNL+D
Ba6mTqM5eb+AOR43pDCRAgs93/uH/IQOKhxq03melKGLGEqTjZwvZDPkL9w9MGvn
qeZDZGNA1N4JPpAZ5RhkgX1Q8s5kW5EBxNb3T/GqnuiVA2UIPgEEHYPLbrpg1aeX
2AfzVz6RluLI1LXCHX5qnNLUnFPCBC4TkKqbRpoWvNXEUP9L1B7IqUM98IHJYfxk
NHxjUunqvAN3ND1/Z+Kc11AU+X8/5XWLDgOIBJT919jfPZbEiFHyO/3pROPRqtmQ
0tRbc6Y00ALkHjLg+8cX9hAIwH5eYWe6vUWYBtUm+v1+TQvNaTYrFB5PDnVLs94Q
DBdZ/zaHjoS8iPPJoXdEZSVHoUmV+47zlgBKZ+7rueuCIJEklA2x9CmotHSKAAeN
JLFlCR8pW4jVERN6wUotELx/7PvCp4BinWRFwA128Zm3rpZUC5ij3SBfg7Rya6om
9NoousKCD7Xpi+2mJLEHicd5JZyBaeBFkAPGd3DVHyThVf4/K31g6XqN096vDs6w
0IkLMPQPG61ewgo78o7/O9COR3edUnHoRaiPBqyM8J0rrVlRj9hoV9LJQbsBAhaW
6t4VX1s20PO1gvxx
-----END CERTIFICATE REQUEST-----
`)

	block, _ := pem.Decode([]byte(csrBytes))
	if block == nil {
		b.Fatalf("could not decode CSR as PEM file")
	}

	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		b.Fatalf("could not parse CSR, err: %s", err.Error())
	}

	if err = csrParsed.CheckSignature(); err != nil {
		b.Fatalf("invalid certificate request signature, err: %s", err.Error())
	}

	optsAPI := SignAPIOpts{
		CSR:        csrParsed,
		CACert:     caCertParsed,
		PrivateKey: caPrivateKeyParsed,
		Subject:    "C=DE, O=SAP SE, OU=SAP Cloud Platform Certificate Service Test Clients, OU=Dev, OU=cf-us10-staging-certificate-service, L=test, CN=test",
		// CrlDistributionPoints: []string{"http://example.com/crl"},
	}

	for b.Loop() {
		_, err := service.SignCertificate(optsProfile, optsAPI)
		if err != nil {
			b.Fatalf("could not sign certificate, err: %s", err.Error())
		}
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
			service: NewLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    Hash("369183d3786773cef4e56c7b849e7ef5f742867510b676d6b38f8e38a222d8a2"),
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
			if got != tt.want {
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
			service: NewLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    Hash("ff3917192427ea1aa7f3ad47ac10152d179af30126c52835ee8dc7e6ea12aed91ad91b316e15c3b250469ef17a03e529"),
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
			if got != tt.want {
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
			service: NewLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    Hash("e2e1c9e522efb2495a178434c8bb8f11000ca23f1fd679058b7d7e141f0cf3433f94fc427ec0b9bebb12f327a3240021053db6091196576d5e6d9bd8fac71c0c"),
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
			if got != tt.want {
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
			service: NewLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    Hash("64ec88ca00b268e5ba1a35678a1b5316d212f4f366b2477232534a8aeca37f3c"),
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
			if got != tt.want {
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
			service: NewLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    Hash("9203b0c4439fd1e6ae5878866337b7c532acd6d9260150c80318e8ab8c27ce330189f8df94fb890df1d298ff360627e1"),
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
			if got != tt.want {
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
			service: NewLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    Hash("b7f783baed8297f0db917462184ff4f08e69c2d5e5f79a942600f9725f58ce1f29c18139bf80b06c0fff2bdd34738452ecf40c488c22a7e3d80cdf6f9c1c0d47"),
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
			if got != tt.want {
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
			service: NewLibraryNative(),
			args: args{
				dataToHash: []byte("Hello world"),
			},
			want:    Hash("f7b55872d4aefe68143bd2ebd928b87f769e15362fcd5a1af8da184bbfcb5fa8"),
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
			if got != tt.want {
				t.Errorf("LibraryNative.HashSHA_512_256() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLibraryNative_ParseRSAPrivateKeyFromPEM(t *testing.T) {
	type args struct {
		key []byte
	}
	tests := []struct {
		name    string
		service *LibraryNative
		args    args
		wantErr bool
	}{
		{
			name:    "ParseRSAPrivateKeyFromPEM() returns error given empty key",
			service: NewLibraryNative(),
			args: args{
				key: []byte(``),
			},
			wantErr: true,
		},
		{
			name:    "ParseRSAPrivateKeyFromPEM() succeeds parsing RSA private key #1",
			service: NewLibraryNative(),
			args: args{
				key: []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAxM8/6O8EqHjFWPV6sWeauYM+xNUrvZWuFjc/RLyhWE9WXAD/
uqHg67P8zkfg1Nxk/A87FDI4vsULt9SbSnjZCbG9fI3BdqogWWXSxpvsiS1Hp5r7
7mtIgTIOYe/ReS4/Rn2VVj8w9SKbXgkzSpQhjScP2J2MnguDErpc7DT1L6uBadfp
c2E4QzX1/bTu4E18af/zcBVJ4KAj+MnaQrZH76Qrnx5q6NqyCN1VTUm0ZVm13VuI
xNDY8qozyoPxddbs9mX4HRpgz99d6Ere+E95XT8Kahu2h3FJPkiWUDmi3kYh7OSx
200OA8ybLXxJGdIzYGe3gcnVAtPbXjPUOWx5rQIDAQABAoIBAA7xlNVRMmK/naFH
xzb2bYdahNPM3KzHhosFsa/v1rYHro0yPwV8lyeugfdm+i/13O3neVseORrOVKAM
hg7dWc8XoavccG0ozwE0VXdiwLVMLKp4S44ETWJ2wSRq+wlr6CTbeKrIBfKgqKvQ
oDljqAYf8JJIQprmUUYekNtKmVD/xW8xbC9x0tfTLcZ3azsQWGBQgVN0DKo2hDtm
9wh6yDO6E1TxNqcsoSyKJBF/G1xZFr2oPVkYiyzffDkuXc4SwIG/Cew4Tf5sRvfe
lGNvxE3QYiF7X3Jq1qgXRd1jVDFOLWhzXy6cEpmbM1mC3M3KFUhqGcKgXqlpAqMW
osZTNO0CgYEA/XYlvzxgWog/n/QedzOvWaUHxyOXkIwdJxM54rA9SGLQGY8nsOvt
XIn8F3wDVjITMQyVG3R9OwLGVTEI22nCqdiDP20IgJPjZO41Nh16cxsPM/3QGe2Q
ual8UVfAoqLZuNZRSYRnM26S4Ivm9uCjtFEspNb+zO+KSP6aj2d+3FMCgYEAxsfa
CSnIFklMfvb0aT6xCNvTzKeUpujejrS7JelSNGDesjBTTpT+b9jnCKRipkBMe1o5
/hU+G/yIOx/38YzWbSxLAccTFty5q72EHnpAdwl4M+pkRy65MQI0SG9SKTi9Vna0
7WhgQuNz2o1YIHFQVUK6WU4Cvec0qYIdTdMskf8CgYEAkX9iGc5Z7X5rL7IeTwU/
crF2ro0y80pLbePuhb/v3f7DQPjZqwk0H7wiF4UcET37oFt9uN39CYQFQGA+ml2y
3ncomJ9Jky3SCl1n9GGlqi/tYUYhUND8FGhDshoyvenIHAADd7Vm3LJr5DTLaAr6
ToeOni3A5PnZIx/sr8eUnnsCgYEAjDPJhU0C4zUvzx0/pjuhgi4KZP6NymvVDbJL
jaHTaT4p1GRhXbuY+ipySZYoPjp7t0UcQimZdQPY0lrp9mTvmHD1NnvC6w0jqA4z
cYuojE0Riwx3Tf2WgQqc9boOqSRr5uAzHH/R5VuoCy5GShuiHYDDDtoG9QpuCmDL
amjXtuECgYEAxkdsOAtmCihgDucHTht1zNImBNB/31+iZ1R3q78PkUwLWC5GGU/x
3nMsr2pvQgb1cC9Wdi8vAHz4bxDsPNzKJ1Tlyrxp1o4J8sJM64n3gY+HaGk3HRbQ
kLCBYOHSXIZVDr/GFND1zYDbMky/HNWFo0RxhEZL7ihtvugnHhGuOno=
-----END RSA PRIVATE KEY-----
`),
			},
			wantErr: false,
		},
		{
			name:    "ParseRSAPrivateKeyFromPEM() succeeds parsing RSA private key #2",
			service: NewLibraryNative(),
			args: args{
				key: []byte(`-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDEzz/o7wSoeMVY
9XqxZ5q5gz7E1Su9la4WNz9EvKFYT1ZcAP+6oeDrs/zOR+DU3GT8DzsUMji+xQu3
1JtKeNkJsb18jcF2qiBZZdLGm+yJLUenmvvua0iBMg5h79F5Lj9GfZVWPzD1Ipte
CTNKlCGNJw/YnYyeC4MSulzsNPUvq4Fp1+lzYThDNfX9tO7gTXxp//NwFUngoCP4
ydpCtkfvpCufHmro2rII3VVNSbRlWbXdW4jE0NjyqjPKg/F11uz2ZfgdGmDP313o
St74T3ldPwpqG7aHcUk+SJZQOaLeRiHs5LHbTQ4DzJstfEkZ0jNgZ7eBydUC09te
M9Q5bHmtAgMBAAECggEADvGU1VEyYr+doUfHNvZth1qE08zcrMeGiwWxr+/Wtgeu
jTI/BXyXJ66B92b6L/Xc7ed5Wx45Gs5UoAyGDt1Zzxehq9xwbSjPATRVd2LAtUws
qnhLjgRNYnbBJGr7CWvoJNt4qsgF8qCoq9CgOWOoBh/wkkhCmuZRRh6Q20qZUP/F
bzFsL3HS19MtxndrOxBYYFCBU3QMqjaEO2b3CHrIM7oTVPE2pyyhLIokEX8bXFkW
vag9WRiLLN98OS5dzhLAgb8J7DhN/mxG996UY2/ETdBiIXtfcmrWqBdF3WNUMU4t
aHNfLpwSmZszWYLczcoVSGoZwqBeqWkCoxaixlM07QKBgQD9diW/PGBaiD+f9B53
M69ZpQfHI5eQjB0nEznisD1IYtAZjyew6+1cifwXfANWMhMxDJUbdH07AsZVMQjb
acKp2IM/bQiAk+Nk7jU2HXpzGw8z/dAZ7ZC5qXxRV8Ciotm41lFJhGczbpLgi+b2
4KO0USyk1v7M74pI/pqPZ37cUwKBgQDGx9oJKcgWSUx+9vRpPrEI29PMp5Sm6N6O
tLsl6VI0YN6yMFNOlP5v2OcIpGKmQEx7Wjn+FT4b/Ig7H/fxjNZtLEsBxxMW3Lmr
vYQeekB3CXgz6mRHLrkxAjRIb1IpOL1WdrTtaGBC43PajVggcVBVQrpZTgK95zSp
gh1N0yyR/wKBgQCRf2IZzlntfmsvsh5PBT9ysXaujTLzSktt4+6Fv+/d/sNA+Nmr
CTQfvCIXhRwRPfugW3243f0JhAVAYD6aXbLedyiYn0mTLdIKXWf0YaWqL+1hRiFQ
0PwUaEOyGjK96cgcAAN3tWbcsmvkNMtoCvpOh46eLcDk+dkjH+yvx5SeewKBgQCM
M8mFTQLjNS/PHT+mO6GCLgpk/o3Ka9UNskuNodNpPinUZGFdu5j6KnJJlig+Onu3
RRxCKZl1A9jSWun2ZO+YcPU2e8LrDSOoDjNxi6iMTRGLDHdN/ZaBCpz1ug6pJGvm
4DMcf9HlW6gLLkZKG6IdgMMO2gb1Cm4KYMtqaNe24QKBgQDGR2w4C2YKKGAO5wdO
G3XM0iYE0H/fX6JnVHervw+RTAtYLkYZT/Hecyyvam9CBvVwL1Z2Ly8AfPhvEOw8
3MonVOXKvGnWjgnywkzrifeBj4doaTcdFtCQsIFg4dJchlUOv8YU0PXNgNsyTL8c
1YWjRHGERkvuKG2+6CceEa46eg==
-----END PRIVATE KEY-----
`),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := &LibraryNative{}
			_, err := service.ParseRSAPrivateKeyFromPEM(tt.args.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("LibraryNative.ParseRSAPrivateKeyFromPEM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestLibraryNative_composeAttributeTypeAndValue(t *testing.T) {
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
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
			service := NewLibraryNative()
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
