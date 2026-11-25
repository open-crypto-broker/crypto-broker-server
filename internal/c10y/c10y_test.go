package c10y

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"reflect"
	"strings"
	"testing"
)

func rsaTestKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := base64.StdEncoding.DecodeString(`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
Wy2RCtRVfbDOyQfcULDyBBdGOrjRzMzzCg==`)
	if err != nil {
		t.Fatalf("could not decode PKCS#8 private key fixture: %v", err)
	}
	return key
}

func TestParseX509Cert(t *testing.T) {
	type args struct {
		rawCert []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ParseX509Cert returns error given empty rawCert bytes",
			args: args{
				rawCert: []byte(""),
			},
			wantErr: true,
		},
		{
			name: "ParseX509Cert returns error given non-certificate bytes",
			args: args{
				rawCert: []byte("not a certificate"),
			},
			wantErr: true,
		},
		{
			name: "ParseX509Cert succeeds given valid certificate bytes",
			args: args{
				rawCert: []byte(`-----BEGIN CERTIFICATE-----
MIICjTCCAjMCFFZylIOCFbBNCArZuYH9Am7mx/HgMAoGCCqGSM49BAMCMDQxCzAJ
BgNVBAYTAkRFMRMwEQYDVQQKDApNeSBUZXN0IENBMRAwDgYDVQQDDAdUZXN0IENB
MB4XDTI1MDYyNzA3NTY0OVoXDTM1MDYyNTA3NTY0OVowgZIxCzAJBgNVBAYTAkRF
MQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJlcmxpbjEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRIwEAYDVQQLDAlBY2NlbnR1cmUxKjAoBgkq
hkiG9w0BCQEWG2RhbmllbC5iZWNrZXJAYWNjZW50dXJlLmNvbTCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAMTPP+jvBKh4xVj1erFnmrmDPsTVK72VrhY3
P0S8oVhPVlwA/7qh4Ouz/M5H4NTcZPwPOxQyOL7FC7fUm0p42QmxvXyNwXaqIFll
0sab7IktR6ea++5rSIEyDmHv0XkuP0Z9lVY/MPUim14JM0qUIY0nD9idjJ4LgxK6
XOw09S+rgWnX6XNhOEM19f207uBNfGn/83AVSeCgI/jJ2kK2R++kK58eaujasgjd
VU1JtGVZtd1biMTQ2PKqM8qD8XXW7PZl+B0aYM/fXehK3vhPeV0/CmobtodxST5I
llA5ot5GIezksdtNDgPMmy18SRnSM2Bnt4HJ1QLT214z1Dlsea0CAwEAATAKBggq
hkjOPQQDAgNIADBFAiEAm5qRf3sYRW6v44M4aEvQ6LNFODegDslLB8di10QHlYEC
IFJg2YEcgTg/KojYGjPBFjR0hlVnCuRYSHr6R7DLtv9J
-----END CERTIFICATE-----`),
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseX509Cert(tt.args.rawCert)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseX509Cert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestParsePrivateKeyFromPKCS8DER(t *testing.T) {
	pkcs8DER := rsaTestKeyDER(t)
	parsedKey, err := x509.ParsePKCS8PrivateKey(pkcs8DER)
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
		{
			name: "accepts PKCS#8 DER",
			key:  pkcs8DER,
		},
		{
			name:    "rejects PEM",
			key:     pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}),
			wantErr: true,
		},
		{
			name:    "rejects PKCS#1 DER",
			key:     x509.MarshalPKCS1PrivateKey(rsaKey),
			wantErr: true,
		},
		{
			name:    "rejects trailing data",
			key:     append(append([]byte(nil), pkcs8DER...), 0),
			wantErr: true,
		},
		{
			name:    "rejects empty input",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParsePrivateKeyFromPKCS8DER(tt.key)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParsePrivateKeyFromPKCS8DER() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if _, ok := key.(*rsa.PrivateKey); !ok {
					t.Fatalf("parsed key type = %T, want *rsa.PrivateKey", key)
				}
			}
		})
	}
}

func TestMLDSADERKeys(t *testing.T) {
	for _, algorithm := range []Algorithm{MLDSA44, MLDSA65, MLDSA87} {
		t.Run(string(algorithm), func(t *testing.T) {
			original, err := mldsa.GenerateKey(MLDSAParameters(algorithm))
			if err != nil {
				t.Fatal(err)
			}
			privateDER, err := x509.MarshalPKCS8PrivateKey(original)
			if err != nil {
				t.Fatal(err)
			}
			publicDER, err := x509.MarshalPKIXPublicKey(original.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			privateKey, err := ParseMLDSAPrivateKey(privateDER, algorithm)
			if err != nil || !original.Equal(privateKey) {
				t.Fatalf("parse PKCS#8 private key: %v", err)
			}
			publicKey, err := ParseMLDSAPublicKey(publicDER, algorithm)
			if err != nil || !original.PublicKey().Equal(publicKey) {
				t.Fatalf("parse SPKI public key: %v", err)
			}
			other := MLDSA44
			if algorithm == other {
				other = MLDSA65
			}
			for _, test := range []struct {
				name  string
				check func() error
			}{
				{"private PEM", func() error {
					_, err := ParseMLDSAPrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), algorithm)
					return err
				}},
				{"raw seed", func() error { _, err := ParseMLDSAPrivateKey(original.Bytes(), algorithm); return err }},
				{"private trailing data", func() error {
					_, err := ParseMLDSAPrivateKey(append(append([]byte(nil), privateDER...), 0), algorithm)
					return err
				}},
				{"private wrong algorithm", func() error { _, err := ParseMLDSAPrivateKey(privateDER, other); return err }},
				{"public PEM", func() error {
					_, err := ParseMLDSAPublicKey(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}), algorithm)
					return err
				}},
				{"raw public key", func() error { _, err := ParseMLDSAPublicKey(original.PublicKey().Bytes(), algorithm); return err }},
				{"public trailing data", func() error {
					_, err := ParseMLDSAPublicKey(append(append([]byte(nil), publicDER...), 0), algorithm)
					return err
				}},
				{"public wrong algorithm", func() error { _, err := ParseMLDSAPublicKey(publicDER, other); return err }},
			} {
				t.Run(test.name, func(t *testing.T) {
					if err := test.check(); err == nil {
						t.Fatal("expected invalid key to be rejected")
					}
				})
			}
		})
	}
}

func TestParsePublicKeyFromDERRejectsLegacyFormats(t *testing.T) {
	privateKey, err := x509.ParsePKCS8PrivateKey(rsaTestKeyDER(t))
	if err != nil {
		t.Fatal(err)
	}
	publicKey := &privateKey.(*rsa.PrivateKey).PublicKey
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKeyFromDER(der); err != nil {
		t.Fatalf("SPKI DER rejected: %v", err)
	}
	for _, input := range [][]byte{
		x509.MarshalPKCS1PublicKey(publicKey),
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		append(append([]byte(nil), der...), 0),
	} {
		if _, err := ParsePublicKeyFromDER(input); err == nil {
			t.Fatal("accepted a non-SPKI DER public key")
		}
	}
}

func TestMapStringToKeyUsage(t *testing.T) {
	type args struct {
		in string
	}
	tests := []struct {
		name    string
		args    args
		want    x509.KeyUsage
		wantErr bool
	}{
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageDigitalSignature to x509.KeyUsageDigitalSignature",
			args: args{
				in: KeyUsageDigitalSignature,
			},
			want:    x509.KeyUsageDigitalSignature,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageContentCommitment to x509.KeyUsageContentCommitment",
			args: args{
				in: KeyUsageContentCommitment,
			},
			want:    x509.KeyUsageContentCommitment,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageCRLSign to x509.KeyUsageCRLSign",
			args: args{
				in: KeyUsageCRLSign,
			},
			want:    x509.KeyUsageCRLSign,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageKeyCertSign to x509.KeyUsageKeyCertSign",
			args: args{
				in: KeyUsageKeyCertSign,
			},
			want:    x509.KeyUsageCertSign,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageDataEncipherment to x509.KeyUsageDataEncipherment",
			args: args{
				in: KeyUsageDataEncipherment,
			},
			want:    x509.KeyUsageDataEncipherment,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageDecipherOnly to x509.KeyUsageDecipherOnly",
			args: args{
				in: KeyUsageDecipherOnly,
			},
			want:    x509.KeyUsageDecipherOnly,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageEncipherOnly to x509.KeyUsageEncipherOnly",
			args: args{
				in: KeyUsageEncipherOnly,
			},
			want:    x509.KeyUsageEncipherOnly,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageKeyAgreement to x509.KeyUsageKeyAgreement",
			args: args{
				in: KeyUsageKeyAgreement,
			},
			want:    x509.KeyUsageKeyAgreement,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() successfully maps KeyUsageKeyEncipherment to x509.KeyUsageKeyEncipherment",
			args: args{
				in: KeyUsageKeyEncipherment,
			},
			want:    x509.KeyUsageKeyEncipherment,
			wantErr: false,
		},
		{
			name: "MapStringToKeyUsage() fails to map unknown phrase",
			args: args{
				in: "abc",
			},
			want:    x509.KeyUsage(0),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MapStringToKeyUsage(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapStringToKeyUsage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapStringToKeyUsage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMapExtKeyUsage(t *testing.T) {
	type args struct {
		in string
	}
	tests := []struct {
		name    string
		args    args
		want    x509.ExtKeyUsage
		wantErr bool
	}{
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageServerAuth to x509.ExtKeyUsageServerAuth",
			args: args{
				in: ExtKeyUsageServerAuth,
			},
			want:    x509.ExtKeyUsageServerAuth,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageClientAuth to x509.ExtKeyUsageClientAuth",
			args: args{
				in: ExtKeyUsageClientAuth,
			},
			want:    x509.ExtKeyUsageClientAuth,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageCodeSigning to x509.ExtKeyUsageCodeSigning",
			args: args{
				in: ExtKeyUsageCodeSigning,
			},
			want:    x509.ExtKeyUsageCodeSigning,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageEmailProtection to x509.ExtKeyUsageEmailProtection",
			args: args{
				in: ExtKeyUsageEmailProtection,
			},
			want:    x509.ExtKeyUsageEmailProtection,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageTimeStamping to x509.ExtKeyUsageTimeStamping",
			args: args{
				in: ExtKeyUsageTimeStamping,
			},
			want:    x509.ExtKeyUsageTimeStamping,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() successfully maps ExtKeyUsageOCSPSigning to x509.ExtKeyUsageOCSPSigning",
			args: args{
				in: ExtKeyUsageOCSPSigning,
			},
			want:    x509.ExtKeyUsageOCSPSigning,
			wantErr: false,
		},
		{
			name: "MapExtKeyUsage() fails to map unknown phrase",
			args: args{
				in: "abc",
			},
			want:    x509.ExtKeyUsage(0),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := MapExtKeyUsage(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("MapExtKeyUsage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("MapExtKeyUsage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestComposeSignatureAlgorithm(t *testing.T) {
	type args struct {
		signAlg Algorithm
		hashAlg Algorithm
	}
	tests := []struct {
		name    string
		args    args
		want    x509.SignatureAlgorithm
		wantErr bool
	}{
		{
			name: "ComposeSignatureAlgorithm() returns x509.ECDSAWithSHA256 given signAlg: ECDSA, hashAlg: SHA_256",
			args: args{
				signAlg: ECDSA,
				hashAlg: SHA_256,
			},
			want:    x509.ECDSAWithSHA256,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.ECDSAWithSHA384 given signAlg: ECDSA, hashAlg: SHA_384",
			args: args{
				signAlg: ECDSA,
				hashAlg: SHA_384,
			},
			want:    x509.ECDSAWithSHA384,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.ECDSAWithSHA512 given signAlg: ECDSA, hashAlg: SHA_512",
			args: args{
				signAlg: ECDSA,
				hashAlg: SHA_512,
			},
			want:    x509.ECDSAWithSHA512,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns error given unsupported hashing algorithm with ECDSA",
			args: args{
				signAlg: ECDSA,
				hashAlg: RSA,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.SHA256WithRSA given signAlg: RSA, hashAlg: SHA_256",
			args: args{
				signAlg: RSA,
				hashAlg: SHA_256,
			},
			want:    x509.SHA256WithRSA,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.SHA384WithRSA given signAlg: RSA, hashAlg: SHA_384",
			args: args{
				signAlg: RSA,
				hashAlg: SHA_384,
			},
			want:    x509.SHA384WithRSA,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns x509.SHA512WithRSA given signAlg: RSA, hashAlg: SHA_512",
			args: args{
				signAlg: RSA,
				hashAlg: SHA_512,
			},
			want:    x509.SHA512WithRSA,
			wantErr: false,
		},
		{
			name: "ComposeSignatureAlgorithm() returns error given unsupported hashing algorithm with RSA",
			args: args{
				signAlg: RSA,
				hashAlg: ECDSA,
			},
			want:    0,
			wantErr: true,
		},
		{
			name: "ComposeSignatureAlgorithm() returns error given unsupported pair of algorithms",
			args: args{
				signAlg: SHA3_512,
				hashAlg: ECDSA,
			},
			want:    0,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ComposeSignatureAlgorithm(tt.args.signAlg, tt.args.hashAlg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ComposeSignatureAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ComposeSignatureAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidatePublicKey(t *testing.T) {
	csr := []byte(`-----BEGIN CERTIFICATE REQUEST-----
MIIC2DCCAcACAQAwgZIxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzAN
BgNVBAcMBkJlcmxpbjEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRk
MRIwEAYDVQQLDAlBY2NlbnR1cmUxKjAoBgkqhkiG9w0BCQEWG2RhbmllbC5iZWNr
ZXJAYWNjZW50dXJlLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AMTPP+jvBKh4xVj1erFnmrmDPsTVK72VrhY3P0S8oVhPVlwA/7qh4Ouz/M5H4NTc
ZPwPOxQyOL7FC7fUm0p42QmxvXyNwXaqIFll0sab7IktR6ea++5rSIEyDmHv0Xku
P0Z9lVY/MPUim14JM0qUIY0nD9idjJ4LgxK6XOw09S+rgWnX6XNhOEM19f207uBN
fGn/83AVSeCgI/jJ2kK2R++kK58eaujasgjdVU1JtGVZtd1biMTQ2PKqM8qD8XXW
7PZl+B0aYM/fXehK3vhPeV0/CmobtodxST5IllA5ot5GIezksdtNDgPMmy18SRnS
M2Bnt4HJ1QLT214z1Dlsea0CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBKTYgW
LO8NA++5HRaCzeokHNw4ZffvN7v4ThaXY5m5pit0miROSEDscREaOqXlG1DZoF7r
sxx7UYL0CM4KGnTr8D3zOCykoNH8t73nWIKyUouPX7nbTve0udSwtJzbjkAqIsfu
/bQqDevPFLYVCv0AxfKiL6N4yiGUCY/rOtJnhXksyHRZrJO0Lf07LQaNMKlbHXeb
giZOJd5zqkWcdIhngALBmuua+8hlriv0778AwRGa1afK14/w88mNAPY948KXwj75
bWcqqXICM6paRxVqB6dUfFNzqSzDRRGj5dQbe24x88Jjv5E1SKRwv4Lb0q1JgfC1
AcGJkRMFqt3M96ox
-----END CERTIFICATE REQUEST-----`)
	block, _ := pem.Decode(csr)
	if block == nil {
		t.Error("could not decode CSR as PEM file")

		return
	}

	csrParsed, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Errorf("could not parse CSR, err: %s", err)

		return
	}

	type args struct {
		pubKey           any
		constraintsByAlg map[Algorithm]BitSizeConstraints
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ValidatePublicKey() returns no error if public key match constraints",
			args: args{
				pubKey: csrParsed.PublicKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					RSA: {
						MinKeySize: 2048,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ValidatePublicKey() returns error if public key doesn't match constraints",
			args: args{
				pubKey: csrParsed.PublicKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					RSA: {
						MinKeySize: 4096,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ValidatePublicKey() returns error if missing constraints for that algorithm",
			args: args{
				pubKey: csrParsed.PublicKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					ECDSA: {
						MinKeySize: 2048,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePublicKey(tt.args.pubKey, tt.args.constraintsByAlg); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePrivateKey(t *testing.T) {
	pk := rsaTestKeyDER(t)
	caPrivateKey, err := ParsePrivateKeyFromPKCS8DER(pk)
	if err != nil {
		t.Fatalf("could not parse DER private key fixture: %v", err)
	}

	type args struct {
		privKey          any
		constraintsByAlg map[Algorithm]BitSizeConstraints
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "ValidatePrivateKey() returns no error if private key match constraints",
			args: args{
				privKey: caPrivateKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					RSA: {
						MinKeySize: 2048,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ValidatePrivateKey() returns error if private key doesn't match constraints",
			args: args{
				privKey: caPrivateKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					RSA: {
						MinKeySize: 4096,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: true,
		},
		{
			name: "ValidatePrivateKey() returns error if missing constraints for that algorithm",
			args: args{
				privKey: caPrivateKey,
				constraintsByAlg: map[Algorithm]BitSizeConstraints{
					ECDSA: {
						MinKeySize: 2048,
						MaxKeySize: 4096,
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidatePrivateKey(tt.args.privKey, tt.args.constraintsByAlg); (err != nil) != tt.wantErr {
				t.Errorf("ValidatePrivateKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMapKeyUsageToExtension(t *testing.T) {
	tests := []struct {
		name       string
		usage      x509.KeyUsage
		wantBytes  []byte
		wantBitLen int
		wantErr    bool
	}{
		{
			name:       "MapKeyUsageToExtension() encodes digitalSignature correctly",
			usage:      x509.KeyUsageDigitalSignature,
			wantBytes:  []byte{0x80},
			wantBitLen: 1,
			wantErr:    false,
		},
		{
			name:       "MapKeyUsageToExtension() encodes decipherOnly (9th bit) correctly",
			usage:      x509.KeyUsageDecipherOnly,
			wantBytes:  []byte{0x00, 0x80},
			wantBitLen: 9,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ext, err := MapKeyUsageToExtension(tt.usage)
			if (err != nil) != tt.wantErr {
				t.Fatalf("MapKeyUsageToExtension() error = %v, wantErr %v", err, tt.wantErr)
			}

			if err != nil {
				return
			}

			if !ext.Critical {
				t.Fatalf("expected extension to be critical")
			}

			wantOID := asn1.ObjectIdentifier{2, 5, 29, 15}
			if !ext.Id.Equal(wantOID) {
				t.Fatalf("expected OID %v, got %v", wantOID, ext.Id)
			}

			var bitStr asn1.BitString
			rest, err := asn1.Unmarshal(ext.Value, &bitStr)
			if err != nil {
				t.Fatalf("failed to unmarshal extension value as bit string: %v", err)
			}
			if len(rest) != 0 {
				t.Fatalf("unexpected trailing bytes after ASN.1 unmarshal: %x", rest)
			}

			if !reflect.DeepEqual(bitStr.Bytes, tt.wantBytes) {
				t.Fatalf("bit string bytes = %x, want %x", bitStr.Bytes, tt.wantBytes)
			}
			if bitStr.BitLength != tt.wantBitLen {
				t.Fatalf("bit string bit length = %d, want %d", bitStr.BitLength, tt.wantBitLen)
			}
		})
	}
}

func TestValidatePublicKey_UnsupportedType(t *testing.T) {
	err := ValidatePublicKey("not-a-key", map[Algorithm]BitSizeConstraints{
		RSA: {MinKeySize: 2048, MaxKeySize: 4096},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported-type error, got: %v", err)
	}
}

func TestValidatePrivateKey_ECDSA_UnsupportedType(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}

	if err = ValidatePrivateKey(ecdsaKey, map[Algorithm]BitSizeConstraints{
		ECDSA: {MinKeySize: 256, MaxKeySize: 384},
	}); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	err = ValidatePrivateKey("not-a-key", map[Algorithm]BitSizeConstraints{
		ECDSA: {MinKeySize: 256, MaxKeySize: 384},
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("expected unsupported-type error, got: %v", err)
	}
}
