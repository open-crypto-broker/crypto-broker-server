//go:build dev

package main

import (
	"github.com/open-crypto-broker/crypto-broker-server/internal/api"
	pb "github.com/open-crypto-broker/crypto-broker-server/internal/gen/cryptobroker/v1"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"google.golang.org/grpc"
)

func registerDevService(server *grpc.Server) {
	dev := api.NewCryptoBrokerDevServer(procedure.NewBenchmark(), procedure.NewFakeEndpoint())
	pb.RegisterCryptoDevServiceServer(server, dev)
}
