//go:build dev

package main

import (
	"os"

	"github.com/open-crypto-broker/crypto-broker-server/internal/api"
	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	pb "github.com/open-crypto-broker/crypto-broker-server/internal/protobuf"
	"google.golang.org/grpc"
)

func registerDevService(server *grpc.Server) {
	if os.Getenv(env.APP_ENV) == devENV {
		dev := api.NewCryptoBrokerDevServer(procedure.NewBenchmark(), procedure.NewFakeEndpoint())
		pb.RegisterCryptoGrpcDevServer(server, dev)
	}
}
