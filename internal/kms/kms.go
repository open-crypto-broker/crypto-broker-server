// Package kms manages the key-management service clients configured for profiles.
package kms

import (
	"bytes"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/open-crypto-broker/crypto-broker-server/internal/cache"
	"github.com/open-crypto-broker/crypto-broker-server/internal/env"
	"github.com/open-crypto-broker/crypto-broker-server/internal/kms/client"
	"github.com/open-crypto-broker/crypto-broker-server/internal/profile"
)

type Client interface {
	GetKey(keyID string) ([]byte, error)
}

var (
	clients = make(map[string]Client)
	mux     sync.RWMutex

	keys = cache.MustNewRistretto[[]byte](cache.DefaultRistrettoConfig)
)

const cacheTTL = 60 * time.Minute

func Load(profileName string) error {
	p, err := profile.Retrieve(profileName)
	if err != nil {
		return fmt.Errorf("retrieve profile %q: %w", profileName, err)
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

	configFile, err := root.Open(p.KMS.Config)
	if err != nil {
		return fmt.Errorf("open KMS configuration for profile %q: %w", profileName, err)
	}
	defer configFile.Close()

	var kmsClient Client

	switch p.KMS.Client {
	case "openbao":
		kmsClient, err = client.Connect(configFile)
	default:
		return fmt.Errorf("unsupported KMS adapter %q for profile %q", p.KMS.Client, profileName)
	}

	if err != nil {
		return fmt.Errorf("load KMS adapter for profile %q: %w", profileName, err)
	}

	mux.Lock()
	clients[profileName] = kmsClient
	mux.Unlock()

	return nil
}

// GetKey retrieves keyID using the KMS client registered for profileName.
func GetKey(profileName, keyID string) ([]byte, error) {
	cacheKey := profileName + keyID

	p, err := profile.Retrieve(profileName)
	if err != nil {
		return nil, fmt.Errorf("retrieve profile %q: %w", profileName, err)
	}

	if p.KMS.Cache {
		key, ok := keys.Get(cacheKey)
		if ok {
			return bytes.Clone(key), nil
		}
	}

	mux.RLock()
	kmsClient, ok := clients[profileName]
	mux.RUnlock()

	if !ok {
		err = Load(profileName)
		if err != nil {
			return nil, err
		}

		mux.RLock()
		kmsClient, ok = clients[profileName]
		mux.RUnlock()
		if !ok {
			return nil, fmt.Errorf("KMS client was not registered for profile %q", profileName)
		}
	}

	key, err := kmsClient.GetKey(keyID)
	if err != nil {
		return nil, err
	}

	if p.KMS.Cache {
		keys.SetWithTTL(cacheKey, bytes.Clone(key), int64(max(1, len(key))), cacheTTL)
		keys.Wait()
	}

	return key, nil
}
