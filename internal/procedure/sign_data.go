package procedure

import (
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

// SignData signs arbitrary input using the legacy algorithm selected by the profile.
type SignData struct {
	cryptographicEngineNative *c10y.LibraryNative
}

func NewSignData(cryptographicEngineNative *c10y.LibraryNative) *SignData {
	return &SignData{cryptographicEngineNative: cryptographicEngineNative}
}

func (procedure *SignData) Execute(req *protobuf.SignDataRequest) (*protobuf.SignDataResponse, error) {
	reqProfile, err := profile.Retrieve(req.GetProfile())
	if err != nil {
		return nil, ArgumentError("could not retrieve profile, err: %w", err)
	}
	if formatErr := validateRawSignatureFormat(req.GetSignatureFormat()); formatErr != nil {
		return nil, formatErr
	}

	privateKey, err := signingPrivateKey(req.GetKeySource())
	if err != nil {
		return nil, err
	}
	engine, err := signingEngine(procedure.cryptographicEngineNative, reqProfile)
	if err != nil {
		return nil, err
	}
	signature, err := engine.SignData(c10y.SignDataInput{
		PrivateKey: privateKey,
		Data:       req.GetInput(),
		SignAlg:    reqProfile.API.SignData.SignAlg,
		HashAlg:    reqProfile.API.SignData.HashAlg,
	})
	if err != nil {
		return nil, ArgumentError("could not sign data: %w", err)
	}

	return &protobuf.SignDataResponse{
		Signature: signature,
		Metadata:  req.GetMetadata(),
		Descriptor_: &protobuf.CryptoDescriptor{
			Profile:   reqProfile.Name,
			Operation: "SignData",
			Algorithm: fmt.Sprintf("%s-with-%s", reqProfile.API.SignData.SignAlg.String(), reqProfile.API.SignData.HashAlg.String()),
		},
	}, nil
}

func signingEngine(engine *c10y.LibraryNative, p profile.Profile) (*c10y.LibraryNative, error) {
	if p.Settings.CryptoLibrary != c10y.LibNative {
		return nil, ArgumentError("unknown '%s' cryptographic engine, available values: %v", p.Settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
	}
	if !p.API.SignData.SignAlg.IsSupported(c10y.SignDataSigning) || !p.API.SignData.HashAlg.IsSupported(c10y.SignDataHashing) {
		return nil, ArgumentError("profile does not contain a supported SignData configuration")
	}
	return engine, nil
}

func signingPrivateKey(keySource *protobuf.SignKeySource) (any, error) {
	key, err := singleRawSigningKey(keySource)
	if err != nil {
		return nil, err
	}
	privateKey, err := c10y.ParsePrivateKeyFromPEM(key)
	if err != nil {
		return nil, ArgumentError("could not parse PEM private key: %w", err)
	}
	return privateKey, nil
}

func singleRawSigningKey(keySource *protobuf.SignKeySource) ([]byte, error) {
	if keySource == nil || keySource.GetSingle() == nil {
		return nil, ArgumentError("keySource.single is required")
	}
	single := keySource.GetSingle()
	if len(single.GetRawKey()) > 0 {
		return single.GetRawKey(), nil
	}
	if single.GetKeyId() != "" {
		return nil, ArgumentError("keySource.single.keyId is not supported without a KMS implementation")
	}
	return nil, ArgumentError("keySource.single.rawKey is required")
}

func validateRawSignatureFormat(format protobuf.SignatureFormat) error {
	if format != protobuf.SignatureFormat_SIGNATURE_RAW {
		return ArgumentError("signatureFormat %s is not currently supported", format.String())
	}
	return nil
}
