package di

import (
	"log"
	"os"

	"github.com/open-crypto-broker/crypto-broker-server/internal/api"
	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
)

// Container is struct that contains everything required for server to run
type Container struct {
	Server *api.CryptoBrokerServer
	Logger *log.Logger
}

// NewContainer returns new dependency injection container which exposes the GRPC endpoints.
// It panics in case of error.
func NewContainer(profiles string) *Container {
	logger := log.New(os.Stdout, "GRPC CRYPTO BROKER: ", log.Ldate|log.Lmicroseconds)
	c10yNative := c10y.NewLibraryNative()
	if err := profile.LoadProfiles(profiles); err != nil {
		panic(err)
	}

	return &Container{Server: api.NewCryptoBrokerServer(c10yNative, logger), Logger: logger}
}
