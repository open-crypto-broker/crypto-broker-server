// Package client contains clients for external key-management services.
package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/openbao/openbao/api/v2"
)

type OpenBao struct {
	client *api.Client
	config openBaoConfig
}

type openBaoConfig struct {
	Address string `yaml:"address"`
	Token   string `yaml:"token"`
	Mount   string `yaml:"mount"`
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

	var conf openBaoConfig
	err = yaml.Unmarshal(contents, &conf)
	if err != nil {
		return nil, fmt.Errorf("parse OpenBao configuration file: %w", err)
	}

	conf.Address = strings.TrimSpace(conf.Address)
	conf.Token = strings.TrimSpace(conf.Token)
	conf.Mount = strings.Trim(strings.TrimSpace(conf.Mount), "/")

	if conf.Address == "" {
		return nil, fmt.Errorf("OpenBao address is required")
	}

	if conf.Token == "" {
		return nil, fmt.Errorf("OpenBao token is required")
	}

	if conf.Mount == "" {
		return nil, fmt.Errorf("OpenBao mount is required")
	}

	config.Address = conf.Address

	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("create OpenBao client: %w", err)
	}

	client.SetToken(conf.Token)
	return &OpenBao{client: client, config: conf}, nil
}

// Health verifies that OpenBao is reachable, initialized, unsealed, and that
// the configured token is accepted.
func (o *OpenBao) Health(ctx context.Context) error {
	health, err := o.client.Sys().HealthWithContext(ctx)
	if err != nil {
		return fmt.Errorf("query OpenBao health: %w", err)
	}

	if health == nil || !health.Initialized {
		return fmt.Errorf("OpenBao is not initialized")
	}

	if health.Sealed {
		return fmt.Errorf("OpenBao is sealed")
	}

	token, err := o.client.Auth().Token().LookupSelfWithContext(ctx)
	if err != nil {
		return fmt.Errorf("validate OpenBao token: %w", err)
	}

	if token == nil {
		return fmt.Errorf("validate OpenBao token: empty response")
	}

	return nil
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

func (o *OpenBao) GetCertificate(keyID string) ([]byte, error) {
	keyID = o.config.Mount + "/data/" + keyID
	secret, err := o.client.Logical().Read(keyID)
	if err != nil {
		return nil, fmt.Errorf("read OpenBao certificate %q: %w", keyID, err)
	}

	if secret == nil {
		return nil, fmt.Errorf("OpenBao certificate %q was not found", keyID)
	}

	data, ok := secret.Data["data"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("OpenBao certificate %q does not contain KV v2 data", keyID)
	}

	certificate, ok := data["certificate"].(string)
	if !ok {
		return nil, fmt.Errorf("OpenBao certificate %q does not contain a string certificate field", keyID)
	}

	return []byte(certificate), nil
}
