package procedure

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	protobuf "github.com/open-crypto-broker/crypto-broker-server/internal/gen/cryptobroker/v1"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestSignVerifyData_MLDSADERKeys(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	p := profile.Profile{Name: "MLDSA"}
	p.API.SignData.SignAlg = c10y.MLDSA65
	format := protobuf.SignatureFormat_SIGNATURE_FORMAT_RAW
	input := []byte("document contents")
	signed, err := NewSignData(newTestLibraryNative()).executeMLDSA(&protobuf.SignDataRequest{
		KeySource: signKeySource(privateDER), Input: input,
	}, p, format)
	if err != nil {
		t.Fatalf("sign ML-DSA DER: %v", err)
	}
	verified, err := NewVerifyData(newTestLibraryNative()).executeMLDSA(&protobuf.VerifyDataRequest{
		KeySource: signKeySource(publicDER), Input: input, Signature: signed.GetSignature(),
	}, p, format)
	if err != nil || !verified.GetValid() {
		t.Fatalf("verify ML-DSA DER: valid=%t, err=%v", verified.GetValid(), err)
	}
}

func TestSignVerifyData_Execute(t *testing.T) {
	loadDefaultProfiles(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal ECDSA private key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal ECDSA public key: %v", err)
	}

	input := []byte("document contents")
	metadata := &protobuf.Metadata{Id: "sign-request"}
	signed, err := NewSignData(newTestLibraryNative()).Execute(&protobuf.SignDataRequest{
		Profile:   "Default",
		KeySource: signKeySource(privateKeyDER),
		Input:     input,
		Metadata:  metadata,
	})
	if err != nil {
		t.Fatalf("SignData.Execute() error: %v", err)
	}
	if len(signed.GetSignature()) == 0 {
		t.Fatal("SignData.Execute() returned an empty signature")
	}
	if signed.GetDescriptor_().GetOperation() != "SignData" || signed.GetDescriptor_().GetAlgorithm() != "ecdsa-with-sha-512" {
		t.Fatalf("unexpected descriptor: %#v", signed.GetDescriptor_())
	}
	if signed.GetMetadata() != metadata {
		t.Fatal("response metadata was not propagated")
	}

	verified, err := NewVerifyData(newTestLibraryNative()).Execute(&protobuf.VerifyDataRequest{
		Profile:   "Default",
		KeySource: signKeySource(publicKeyDER),
		Input:     input,
		Signature: signed.GetSignature(),
		Metadata:  metadata,
	})
	if err != nil {
		t.Fatalf("VerifyData.Execute() error: %v", err)
	}
	if !verified.GetValid() || verified.GetMetadata() != metadata {
		t.Fatalf("unexpected verification response: %#v", verified)
	}

	tamperedSignature := append([]byte(nil), signed.GetSignature()...)
	tamperedSignature[0] ^= 1
	verified, err = NewVerifyData(newTestLibraryNative()).Execute(&protobuf.VerifyDataRequest{
		Profile:   "Default",
		KeySource: signKeySource(publicKeyDER),
		Input:     input,
		Signature: tamperedSignature,
	})
	if err != nil {
		t.Fatalf("VerifyData.Execute() tampered signature error: %v", err)
	}
	if verified.GetValid() {
		t.Fatal("VerifyData.Execute() accepted a tampered signature")
	}
}

func TestSignVerifyData_ExecuteWithDERKeys(t *testing.T) {
	loadDefaultProfiles(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal ECDSA private key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal ECDSA public key: %v", err)
	}

	input := []byte("document contents")
	signed, err := NewSignData(newTestLibraryNative()).Execute(&protobuf.SignDataRequest{
		Profile:   "Default",
		KeySource: signKeySource(privateKeyDER),
		Input:     input,
	})
	if err != nil {
		t.Fatalf("SignData.Execute() with DER private key error: %v", err)
	}

	verified, err := NewVerifyData(newTestLibraryNative()).Execute(&protobuf.VerifyDataRequest{
		Profile:   "Default",
		KeySource: signKeySource(publicKeyDER),
		Input:     input,
		Signature: signed.GetSignature(),
	})
	if err != nil {
		t.Fatalf("VerifyData.Execute() with DER public key error: %v", err)
	}
	if !verified.GetValid() {
		t.Fatal("VerifyData.Execute() with DER keys returned invalid")
	}
}

func TestSignData_RejectsPEMEncodedProtoKey(t *testing.T) {
	loadDefaultProfiles(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal ECDSA private key: %v", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})

	_, err = NewSignData(newTestLibraryNative()).Execute(&protobuf.SignDataRequest{
		Profile:   "Default",
		KeySource: signKeySource(privateKeyPEM),
		Input:     []byte("document contents"),
	})
	if err == nil {
		t.Fatal("SignData.Execute() accepted a PEM-encoded proto key")
	}
}

func TestSignData_ExecuteRejectsKeyOutsideProfileConstraints(t *testing.T) {
	loadDefaultProfiles(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal ECDSA private key: %v", err)
	}

	_, err = NewSignData(newTestLibraryNative()).Execute(&protobuf.SignDataRequest{
		Profile:   "Default",
		KeySource: signKeySource(privateKeyDER),
		Input:     []byte("document contents"),
	})
	if err == nil {
		t.Fatal("SignData.Execute() accepted an ECDSA P-256 key below the profile minimum")
	}
}

func TestSignVerifyData_Formats(t *testing.T) {
	loadDefaultProfiles(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal ECDSA private key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal ECDSA public key: %v", err)
	}
	for _, format := range []protobuf.SignatureFormat{
		protobuf.SignatureFormat_SIGNATURE_FORMAT_RAW,
		protobuf.SignatureFormat_SIGNATURE_FORMAT_DER,
		protobuf.SignatureFormat_SIGNATURE_FORMAT_PEM,
	} {
		t.Run(format.String(), func(t *testing.T) {
			signed, err := NewSignData(newTestLibraryNative()).Execute(&protobuf.SignDataRequest{
				Profile:         "Default",
				KeySource:       signKeySource(privateKeyDER),
				Input:           []byte("document contents"),
				SignatureFormat: format,
			})
			if err != nil {
				t.Fatalf("SignData.Execute() error: %v", err)
			}
			if format == protobuf.SignatureFormat_SIGNATURE_FORMAT_RAW && len(signed.GetSignature()) != 132 {
				t.Fatalf("RAW P-521 signature length = %d, want 132", len(signed.GetSignature()))
			}
			if format == protobuf.SignatureFormat_SIGNATURE_FORMAT_PEM && !bytes.HasPrefix(signed.GetSignature(), []byte("-----BEGIN SIGNATURE-----")) {
				t.Fatalf("PEM signature does not have a SIGNATURE block: %q", signed.GetSignature())
			}

			verified, err := NewVerifyData(newTestLibraryNative()).Execute(&protobuf.VerifyDataRequest{
				Profile:         "Default",
				KeySource:       signKeySource(publicKeyDER),
				Input:           []byte("document contents"),
				Signature:       signed.GetSignature(),
				SignatureFormat: format,
			})
			if err != nil {
				t.Fatalf("VerifyData.Execute() error: %v", err)
			}
			if !verified.GetValid() {
				t.Fatal("VerifyData.Execute() returned invalid")
			}
		})
	}
}

func TestSignatureFormatWasSet(t *testing.T) {
	for _, format := range []protobuf.SignatureFormat{
		protobuf.SignatureFormat_SIGNATURE_FORMAT_UNSPECIFIED,
		protobuf.SignatureFormat_SIGNATURE_FORMAT_RAW,
		protobuf.SignatureFormat_SIGNATURE_FORMAT_DER,
		protobuf.SignatureFormat_SIGNATURE_FORMAT_PEM,
		protobuf.SignatureFormat_SIGNATURE_FORMAT_CMS,
		protobuf.SignatureFormat(99),
	} {
		t.Run(format.String(), func(t *testing.T) {
			requests := map[string]protoreflect.ProtoMessage{
				"SignData":   &protobuf.SignDataRequest{SignatureFormat: format},
				"VerifyData": &protobuf.VerifyDataRequest{SignatureFormat: format},
			}
			for name, request := range requests {
				t.Run(name, func(t *testing.T) {
					want := format != protobuf.SignatureFormat_SIGNATURE_FORMAT_UNSPECIFIED
					if got := signatureFormatWasSet(request); got != want {
						t.Fatalf("signatureFormatWasSet() = %t, want %t", got, want)
					}
				})
			}
		})
	}
}

func TestEffectiveSignatureFormat(t *testing.T) {
	format, err := effectiveSignatureFormat(protobuf.SignatureFormat_SIGNATURE_FORMAT_RAW, false, profile.SignatureFormatPEM)
	if err != nil {
		t.Fatalf("effectiveSignatureFormat() error: %v", err)
	}
	if format != protobuf.SignatureFormat_SIGNATURE_FORMAT_PEM {
		t.Fatalf("effectiveSignatureFormat() = %s, want SIGNATURE_PEM", format)
	}

	if _, err = decodeSignature(protobuf.SignatureFormat_SIGNATURE_FORMAT_PEM, &ecdsa.PublicKey{}, []byte("not pem")); err == nil {
		t.Fatal("decodeSignature() accepted malformed PEM")
	}
}

func TestDecodeSignature_RejectsCustomMLDSAHeaders(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}

	signature := []byte("test signature data")

	pemBlockWithHeaders := &pem.Block{
		Type:    signaturePEMBlockType,
		Headers: map[string]string{"MLDSAVariant": "ml-dsa-65", "CustomHeader": "value"},
		Bytes:   signature,
	}
	pemWithHeaders := pem.EncodeToMemory(pemBlockWithHeaders)

	_, err = decodeSignature(protobuf.SignatureFormat_SIGNATURE_FORMAT_PEM, &privateKey.PublicKey, pemWithHeaders)
	if err == nil {
		t.Fatal("decodeSignature() accepted PEM block with custom headers")
	}

	pemBlockWithoutHeaders := &pem.Block{
		Type:  signaturePEMBlockType,
		Bytes: signature,
	}
	pemWithoutHeaders := pem.EncodeToMemory(pemBlockWithoutHeaders)

	decoded, err := decodeSignature(protobuf.SignatureFormat_SIGNATURE_FORMAT_PEM, &privateKey.PublicKey, pemWithoutHeaders)
	if err != nil {
		t.Fatalf("decodeSignature() rejected valid PEM block without headers: %v", err)
	}
	if !bytes.Equal(decoded, signature) {
		t.Fatalf("decodeSignature() returned incorrect decoded signature")
	}
}

func signKeySource(rawKey []byte) *protobuf.SignKeySource {
	return &protobuf.SignKeySource{Source: &protobuf.SignKeySource_Single{
		Single: &protobuf.KeySource{Source: &protobuf.KeySource_RawKey{RawKey: rawKey}},
	}}
}
