package procedure

import (
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	protobuf "github.com/open-crypto-broker/crypto-broker-server/internal/gen/cryptobroker/v1"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
)

// HashData defines the procedure for hashing data
type HashData struct {
	cryptographicEngineNative *c10y.LibraryNative
}

func NewHashData(cryptographicEngineNative *c10y.LibraryNative) *HashData {
	return &HashData{cryptographicEngineNative: cryptographicEngineNative}
}

// Execute executes the hash data procedure
func (procedure *HashData) Execute(req *protobuf.HashDataRequest) (*protobuf.HashDataResponse, error) {
	reqProfile, err := profile.Retrieve(req.GetProfile())
	if err != nil {
		return nil, ArgumentError("could not retrieve profile, err: %w", err)
	}

	hashConfig := reqProfile.API.HashData
	outputBytes := hashConfig.MinOutputBytes
	if req.OutputBytes != nil {
		if !hashConfig.HashAlg.IsSHAKE() {
			return nil, ArgumentError("output_bytes is only allowed for SHAKE, not %s", hashConfig.HashAlg)
		}
		requested := req.GetOutputBytes()
		if requested < uint32(hashConfig.MinOutputBytes) || requested > uint32(hashConfig.MaxOutputBytes) {
			return nil, ArgumentError("output_bytes %d is outside the allowed range [%d, %d] bytes",
				requested, hashConfig.MinOutputBytes, hashConfig.MaxOutputBytes)
		}
		outputBytes = int(requested)
	}

	hashedBytes, err := procedure.hashData(req.GetInput(), reqProfile, outputBytes)
	if err != nil {
		return nil, fmt.Errorf("error while hashing data: %w", err)
	}

	algorithm := hashConfig.HashAlg.String()
	if hashConfig.HashAlg.IsSHAKE() {
		algorithm = fmt.Sprintf("%s/%d", algorithm, outputBytes*8)
	}
	resp := &protobuf.HashDataResponse{
		Metadata: req.GetMetadata(),
		Descriptor_: &protobuf.CryptoDescriptor{
			Profile:   reqProfile.Name,
			Operation: "HashData",
			Algorithm: algorithm,
		},
	}

	switch req.GetOutputFormat() {
	case protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_RAW:
		resp.HashValue = &protobuf.HashDataResponse_HashValueRaw{
			HashValueRaw: []byte(hashedBytes),
		}
	case protobuf.HashOutputFormat_HASH_OUTPUT_FORMAT_HEX:
		resp.HashValue = &protobuf.HashDataResponse_HashValueHex{
			HashValueHex: hashedBytes.ToHEX(),
		}
	default:
		resp.HashValue = &protobuf.HashDataResponse_HashValueHex{
			HashValueHex: hashedBytes.ToHEX(),
		}
	}

	return resp, nil
}

// hashData hashes provided data according to profile rules
func (procedure *HashData) hashData(data []byte, p profile.Profile, outputBytes int) (c10y.Hash, error) {

	// hasher defines abstraction over hashing library/engine.
	type hasher interface {
		HashSHA3_256(dataToHash []byte) (c10y.Hash, error)
		HashSHA3_384(dataToHash []byte) (c10y.Hash, error)
		HashSHA3_512(dataToHash []byte) (c10y.Hash, error)
		HashSHA_256(dataToHash []byte) (c10y.Hash, error)
		HashSHA_384(dataToHash []byte) (c10y.Hash, error)
		HashSHA_512(dataToHash []byte) (c10y.Hash, error)
		HashSHA_512_256(dataToHash []byte) (c10y.Hash, error)
		HashShake_128(size int, dataToHash []byte) (c10y.Hash, error)
		HashShake_256(size int, dataToHash []byte) (c10y.Hash, error)
	}

	settings := profile.Settings()
	var h hasher
	switch settings.CryptoLibrary {
	case c10y.LibNative:
		h = procedure.cryptographicEngineNative
	default:
		return nil, ArgumentError("unknown '%s' cryptographic engine, available values: %v",
			settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
	}

	var (
		hash c10y.Hash
		err  error
	)
	switch p.API.HashData.HashAlg {
	case c10y.SHA3_256:
		hash, err = h.HashSHA3_256(data)
	case c10y.SHA3_384:
		hash, err = h.HashSHA3_384(data)
	case c10y.SHA3_512:
		hash, err = h.HashSHA3_512(data)
	case c10y.SHA_256:
		hash, err = h.HashSHA_256(data)
	case c10y.SHA_384:
		hash, err = h.HashSHA_384(data)
	case c10y.SHA_512:
		hash, err = h.HashSHA_512(data)
	case c10y.SHA_512_256:
		hash, err = h.HashSHA_512_256(data)
	case c10y.SHAKE_128:
		hash, err = h.HashShake_128(outputBytes, data)
	case c10y.SHAKE_256:
		hash, err = h.HashShake_256(outputBytes, data)
	default:
		return nil, ArgumentError("unknown '%s' algorithm value, available values: %v", p.API.HashData.HashAlg, c10y.HashDataAlgorithmsSupported)
	}

	if err != nil {
		return nil, fmt.Errorf("could not hash provided bytes, err: %w", err)
	}

	return hash, nil
}
