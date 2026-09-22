package procedure

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

func TestSignVerifyData_Execute(t *testing.T) {
	loadDefaultProfiles(t)

	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
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
		KeySource: signKeySource(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privateKeyDER})),
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
		KeySource: signKeySource(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})),
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
		KeySource: signKeySource(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})),
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

func signKeySource(rawKey []byte) *protobuf.SignKeySource {
	return &protobuf.SignKeySource{Source: &protobuf.SignKeySource_Single{
		Single: &protobuf.KeySource{Source: &protobuf.KeySource_RawKey{RawKey: rawKey}},
	}}
}
