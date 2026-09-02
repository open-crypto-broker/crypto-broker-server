// Package client contains clients for external key-management services.
package client

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/goccy/go-yaml"
	"github.com/openbao/openbao/api/v2"
)

type OpenBao struct {
	client *api.Client
	config openBaoConfig
}

type openBaoConfig struct {
	Address   string `yaml:"address"`
	Token     string `yaml:"token"`
	Mount     string `yaml:"mount"`
}

func Connect(configFile io.Reader) (*OpenBao, error) {
	config := api.DefaultConfig()
	if config.Error != nil {
		return nil, fmt.Errorf("create default OpenBao configuration: %w", config.Error)
	}

	contents, err := io.ReadAll(configFile)
	if err != nil {
		return nil, fmt.Errorf("read OpenBao configuration file: %w", err)
	}

	var fileConfig openBaoConfig
	err = yaml.Unmarshal(contents, &fileConfig)
	if err != nil {
		return nil, fmt.Errorf("parse OpenBao configuration file: %w", err)
	}

	if fileConfig.Address != "" {
		config.Address = fileConfig.Address
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create OpenBao client: %w", err)
	}

	client.SetToken(fileConfig.Token)
	return &OpenBao{client: client, config: fileConfig}, nil
}

func (o *OpenBao) GetKey(keyID string) ([]byte, error) {
	keyID = o.config.Mount + "/data/" + keyID
	secret, err := o.client.Logical().Read(keyID)
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

	decodedKey, err := hex.DecodeString(key)
	if err != nil {
		return nil, fmt.Errorf("decode OpenBao key %q: %w", keyID, err)
	}

	return decodedKey, nil
}
