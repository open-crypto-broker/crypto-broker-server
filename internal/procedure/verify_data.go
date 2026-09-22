package procedure

import (
	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

// VerifyData verifies arbitrary input using the legacy algorithm selected by the profile.
type VerifyData struct {
	cryptographicEngineNative *c10y.LibraryNative
}

func NewVerifyData(cryptographicEngineNative *c10y.LibraryNative) *VerifyData {
	return &VerifyData{cryptographicEngineNative: cryptographicEngineNative}
}

func (procedure *VerifyData) Execute(req *protobuf.VerifyDataRequest) (*protobuf.VerifyDataResponse, error) {
	reqProfile, err := profile.Retrieve(req.GetProfile())
	if err != nil {
		return nil, ArgumentError("could not retrieve profile, err: %w", err)
	}
	if formatErr := validateRawSignatureFormat(req.GetSignatureFormat()); formatErr != nil {
		return nil, formatErr
	}

	key, err := singleRawSigningKey(req.GetKeySource())
	if err != nil {
		return nil, err
	}
	publicKey, err := c10y.ParsePublicKeyFromPEM(key)
	if err != nil {
		return nil, ArgumentError("could not parse PEM public key: %w", err)
	}
	engine, err := signingEngine(procedure.cryptographicEngineNative, reqProfile)
	if err != nil {
		return nil, err
	}
	valid, err := engine.VerifyData(c10y.VerifyDataInput{
		PublicKey: publicKey,
		Data:      req.GetInput(),
		Signature: req.GetSignature(),
		SignAlg:   reqProfile.API.SignData.SignAlg,
		HashAlg:   reqProfile.API.SignData.HashAlg,
	})
	if err != nil {
		return nil, ArgumentError("could not verify data: %w", err)
	}

	return &protobuf.VerifyDataResponse{Valid: valid, Metadata: req.GetMetadata()}, nil
}
