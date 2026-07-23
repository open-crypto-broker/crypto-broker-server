package di

import (
	"context"
	"crypto/x509"

	"github.com/open-crypto-broker/crypto-broker-server/internal/api"
	"github.com/open-crypto-broker/crypto-broker-server/internal/c10y"
	"github.com/open-crypto-broker/crypto-broker-server/internal/cache"
	"github.com/open-crypto-broker/crypto-broker-server/internal/otel"
	"github.com/open-crypto-broker/crypto-broker-server/internal/procedure"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
)

// Container is struct that contains everything required for server to run
type Container struct {
	Server         *api.CryptoBrokerServer
	TracerProvider *otel.TracerProvider
	MeterProvider  *otel.MeterProvider
}

// NewContainer returns new dependency injection container which exposes the GRPC endpoints.
// It panics in case of error.
func NewContainer(ctx context.Context, profiles string) *Container {
	return NewContainerWithTracing(ctx, profiles, true)
}

// NewContainerWithTracing returns new dependency injection container which exposes the GRPC endpoints.
// tracingEnabled controls whether OpenTelemetry tracing is initialized.
// It panics in case of error.
func NewContainerWithTracing(ctx context.Context, profiles string, tracingEnabled bool) *Container {
	subjectDERCache, err := cache.NewRistretto[[]byte](cache.RistrettoConfig{
		NumCounters: 40_000, // ~10x of ~4000 distinct subjects
		MaxCost:     4_000,
		BufferItems: 64,
	})
	if err != nil {
		panic(err)
	}

	caCertCache, err := cache.NewRistretto[*x509.Certificate](cache.RistrettoConfig{
		NumCounters: 10_000, // ~10x of ~1000 CA certs
		MaxCost:     1_000,
		BufferItems: 64,
	})
	if err != nil {
		panic(err)
	}

	c10yNative := c10y.NewLibraryNative(subjectDERCache)
	if err = profile.LoadProfiles(profiles); err != nil {
		panic(err)
	}

	var tracerProvider *otel.TracerProvider
	if tracingEnabled {
		tracerProvider, err = otel.NewTracerProvider(ctx)
		if err != nil {
			panic(err)
		}
	}

	// Initialize metrics provider
	meterProvider, err := otel.NewMeterProvider(ctx)
	if err != nil {
		panic(err)
	}

	procedureHash := procedure.NewHashData(c10yNative)
	procedureSign := procedure.NewSignCertificate(c10yNative, caCertCache)
	procedureEncrypt := procedure.NewEncryptData(c10yNative)
	procedureDecrypt := procedure.NewDecryptData(c10yNative)

	// Check if metrics are enabled (not nil)
	metricsEnabled := meterProvider != nil

	return &Container{
		Server:         api.NewCryptoBrokerServer(c10yNative, procedureHash, procedureSign, procedureEncrypt, procedureDecrypt, metricsEnabled),
		TracerProvider: tracerProvider,
		MeterProvider:  meterProvider,
	}
}
