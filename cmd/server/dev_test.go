//go:build dev

package main

import (
	"testing"

	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
	"google.golang.org/grpc"
)

func TestDevServiceRegistration(t *testing.T) {
	t.Setenv(env.APP_ENV, "prod")
	server := grpc.NewServer()
	t.Cleanup(server.Stop)
	registerDevService(server)

	if _, registered := server.GetServiceInfo()["CryptoBroker.CryptoGrpcDev"]; !registered {
		t.Fatal("dev build did not register the dev service")
	}
}
