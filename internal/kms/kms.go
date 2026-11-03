// Package kms manages the globally configured key-management service client.
package kms

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/cache"
	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
	openbao "github.com/open-crypto-broker/crypto-broker-server/internal/kms/client"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
)

type Client interface {
	Health(context.Context) error
	GetKey(keyID string) ([]byte, error)
	GetCertificate(keyID string) ([]byte, error)
}

var (
	client Client
	mux    sync.RWMutex

	keys = cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig)
	// Certificate entries are byte-costed and can be larger than the default
	// cache's entire budget (1,000 bytes).
	certificates = cache.MustNewRistretto[[]byte](cache.RistrettoConfig{
		NumCounters: 10_000,
		MaxCost:     4 * 1024 * 1024,
		BufferItems: 64,
	})
)

const (
	cacheTTL             = 60 * time.Minute
	startupHealthTimeout = 5 * time.Second
)

// Connect initializes the configured KMS client and verifies the connection.
func Connect() error {
	configuration := profile.KMS()
	if !configuration.Configured() {
		return fmt.Errorf("KMS is not configured")
	}

	directory := os.Getenv(env.KMS_DIRECTORY)
	if directory == "" {
		return fmt.Errorf("%s is not configured", env.KMS_DIRECTORY)
	}

	root, err := os.OpenRoot(directory)
	if err != nil {
		return fmt.Errorf("open KMS configuration directory: %w", err)
	}
	defer root.Close()

	configFile, err := root.Open(configuration.Config)
	if err != nil {
		return fmt.Errorf("open KMS configuration: %w", err)
	}
	defer configFile.Close()

	var kmsClient Client

	switch configuration.Client {
	case "openbao":
		kmsClient, err = openbao.Connect(configFile)
	default:
		return fmt.Errorf("unsupported KMS adapter %q", configuration.Client)
	}

	if err != nil {
		return fmt.Errorf("connect KMS adapter: %w", err)
	}

	healthCtx, cancel := context.WithTimeout(context.Background(), startupHealthTimeout)
	defer cancel()
	if err = kmsClient.Health(healthCtx); err != nil {
		return fmt.Errorf("check KMS health: %w", err)
	}

	mux.Lock()
	client = kmsClient
	mux.Unlock()

	return nil
}

// GetKey retrieves keyID using the globally configured KMS client.
func GetKey(keyID string) ([]byte, error) {
	configuration := profile.KMS()

	if configuration.Cache {
		key, ok := keys.Get(keyID)
		if ok {
			return bytes.Clone(key), nil
		}
	}

	mux.RLock()
	kmsClient := client
	mux.RUnlock()

	if kmsClient == nil {
		if err := Connect(); err != nil {
			return nil, err
		}

		mux.RLock()
		kmsClient = client
		mux.RUnlock()
		if kmsClient == nil {
			return nil, fmt.Errorf("KMS client was not loaded")
		}
	}

	key, err := kmsClient.GetKey(keyID)
	if err != nil {
		return nil, err
	}

	if configuration.Cache {
		keys.SetWithTTL(keyID, bytes.Clone(key), int64(max(1, len(key))), cacheTTL)
		keys.Wait()
	}

	return key, nil
}

// GetCertificate retrieves a PEM certificate using the globally configured KMS client.
func GetCertificate(keyID string) ([]byte, error) {
	cacheEnabled := profile.KMS().Cache
	if cacheEnabled {
		certificate, ok := certificates.Get(keyID)
		if ok {
			return bytes.Clone(certificate), nil
		}
	}

	mux.RLock()
	kmsClient := client
	mux.RUnlock()

	if kmsClient == nil {
		if err := Connect(); err != nil {
			return nil, err
		}

		mux.RLock()
		kmsClient = client
		mux.RUnlock()
		if kmsClient == nil {
			return nil, fmt.Errorf("KMS client was not loaded")
		}
	}

	certificate, err := kmsClient.GetCertificate(keyID)
	if err != nil {
		return nil, err
	}

	if cacheEnabled {
		certificates.SetWithTTL(keyID, bytes.Clone(certificate), int64(max(1, len(certificate))), cacheTTL)
		certificates.Wait()
	}

	return certificate, nil
}
