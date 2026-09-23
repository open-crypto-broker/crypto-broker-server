//go:build dev

package main

import (
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
	"google.golang.org/grpc"
)

func TestDevServiceRegistration(t *testing.T) {
	for _, appEnv := range []string{"", "prod", "dev"} {
		t.Run("APP_ENV="+appEnv, func(t *testing.T) {
			t.Setenv(env.APP_ENV, appEnv)
			server := grpc.NewServer()
			t.Cleanup(server.Stop)
			registerDevService(server)

			_, registered := server.GetServiceInfo()["CryptoBroker.CryptoGrpcDev"]
			if registered != (appEnv == "dev") {
				t.Fatalf("dev service registered = %v for APP_ENV=%q", registered, appEnv)
			}
		})
	}
}
