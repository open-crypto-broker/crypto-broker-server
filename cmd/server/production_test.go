//go:build !dev

package main

import (
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
	"google.golang.org/grpc"
)

func TestProductionExcludesDevService(t *testing.T) {
	t.Setenv(env.APP_ENV, "dev")
	server := grpc.NewServer()
	t.Cleanup(server.Stop)
	registerDevService(server)
	if _, registered := server.GetServiceInfo()["CryptoBroker.CryptoGrpcDev"]; registered {
		t.Fatal("production build registered the dev service")
	}
}
