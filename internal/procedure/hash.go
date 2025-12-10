package procedure

import (
	"fmt"

	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
	"github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
)

// Hash defines the procedure for hashing data
type Hash struct {
	cryptographicEngineNative *c10y.LibraryNative
}

func NewHash(cryptographicEngineNative *c10y.LibraryNative) *Hash {
	return &Hash{cryptographicEngineNative: cryptographicEngineNative}
}

// Execute executes the hash procedure
func (procedure *Hash) Execute(req *protobuf.HashRequest) (*protobuf.HashResponse, error) {
	reqProfile, err := profile.Retrieve(req.Profile)
	if err != nil {
		return nil, fmt.Errorf("could not retrieve profile, err: %w", err)
	}

	hashedBytes, err := procedure.hash(req.Input, reqProfile)
	if err != nil {
		return nil, fmt.Errorf("error while hashing data: %s", err.Error())
	}

	return &protobuf.HashResponse{
		HashValue:     string(hashedBytes),
		HashAlgorithm: reqProfile.API.HashData.HashAlg.String(),
		Metadata:      req.Metadata,
	}, nil
}

// hash hashes provided data according to profile rules
func (procedure *Hash) hash(data []byte, p profile.Profile) (c10y.Hash, error) {

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

	var h hasher
	switch p.Settings.CryptoLibrary {
	case c10y.LibNative:
		h = procedure.cryptographicEngineNative
	default:
		return "", fmt.Errorf("unknown '%s' cryptographic engine, available values: %v",
			p.Settings.CryptoLibrary, c10y.SupportedCryptographicLibraries)
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
		hash, err = h.HashShake_128(16, data)
	case c10y.SHAKE_256:
		hash, err = h.HashShake_256(32, data)
	default:
		return "", fmt.Errorf("unknown '%s' algorithm value, available values: %v", p.API.HashData.HashAlg, c10y.HashDataAlgorithmsSupported)
	}

	if err != nil {
		return "", fmt.Errorf("could not hash provided bytes, err: %s", err)
	}

	return hash, nil
}
