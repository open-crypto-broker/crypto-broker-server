// Package client contains clients for external key-management services.
package client

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/openbao/openbao/api/v2"
)

type OpenBao struct {
	client *api.Client
}

type openBaoConfig struct {
	Address   string `yaml:"address"`
	Token     string `yaml:"token"`
	Namespace string `yaml:"namespace"`
}

func Connect(configFile string) (*OpenBao, error) {
	config := api.DefaultConfig()
	if config.Error != nil {
		return nil, fmt.Errorf("create default OpenBao configuration: %w", config.Error)
	}

	var fileConfig openBaoConfig

	if configFile != "" {
		contents, err := os.ReadFile(configFile)
		if err != nil {
			return nil, fmt.Errorf("read OpenBao configuration file: %w", err)
		}

		err = yaml.Unmarshal(contents, &fileConfig)
		if err != nil {
			return nil, fmt.Errorf("parse OpenBao configuration file: %w", err)
		}

		if fileConfig.Address != "" {
			config.Address = fileConfig.Address
		}
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create OpenBao client: %w", err)
	}

	client.SetToken(fileConfig.Token)
	client.SetNamespace(fileConfig.Namespace)

	return &OpenBao{client: client}, nil
}

func (c *OpenBao) GetKey(keyID string) ([]byte, error) {
	secret, err := c.client.Logical().Read(keyID)
	if err != nil {
		return nil, fmt.Errorf("read OpenBao key %q: %w", keyID, err)
	}

	if secret == nil {
		return nil, fmt.Errorf("OpenBao key %q was not found", keyID)
	}

	data, ok := secret.Data["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenBao key %q does not contain KV v2 data", keyID)
	}

	key, ok := data["key"].(string)
	if !ok {
		return nil, fmt.Errorf("OpenBao key %q does not contain a string key field", keyID)
	}

	return []byte(key), nil
}
