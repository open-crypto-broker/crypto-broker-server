package client

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

func TestOpenBaoClientGetKey(t *testing.T) {
	decodedKey, _ := hex.DecodeString("67e1befda6538f162a308bb37b922441bed6e27039a26a48ad8e11c568c4cda0")

	tests := []struct {
		name     string
		response string
		want     []byte
	}{
		{
			name:     "KV v2 secret",
			response: `{"data":{"data":{"key":"67e1befda6538f162a308bb37b922441bed6e27039a26a48ad8e11c568c4cda0"}}}`,
			want:     decodedKey,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/keys2/data/secret_1" {
					t.Errorf("request path = %q, want %q", r.URL.Path, "/v1/keys2/data/secret_1")
				}

				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.response))
			}))

			defer server.Close()
			config := api.DefaultConfig()

			if config.Error != nil {
				t.Fatalf("DefaultConfig() error = %v", config.Error)
			}

			config.Address = server.URL
			baoClient, err := api.NewClient(config)

			if err != nil {
				t.Fatalf("NewClient() error = %v", err)
			}

			client := &OpenBao{client: baoClient, config: openBaoConfig{Mount: "keys2"}}
			key, err := client.GetKey("secret_1")

			if err != nil {
				t.Fatalf("GetKey() error = %v", err)
			}

			if !bytes.Equal(key, test.want) {
				t.Errorf("GetKey() = %q, want %q", key, test.want)
			}
		})
	}
}

func TestOpenBaoClientGetCertificate(t *testing.T) {
	const pem = "-----BEGIN CERTIFICATE-----\nPEM content\n-----END CERTIFICATE-----\n"
	tests := []struct {
		name     string
		status   int
		response string
		wantErr  string
	}{
		{name: "private key and PEM certificate", status: http.StatusOK, response: `{"data":{"data":{"key":"4142","ca_cert":"-----BEGIN CERTIFICATE-----\nPEM content\n-----END CERTIFICATE-----\n"}}}`},
		{name: "not found", status: http.StatusNotFound, response: `{}`, wantErr: "was not found"},
		{name: "permission denied", status: http.StatusForbidden, response: `{"errors":["permission denied"]}`, wantErr: "permission denied"},
		{name: "not KV v2", status: http.StatusOK, response: `{"data":{"ca_cert":"pem"}}`, wantErr: "KV v2 data"},
		{name: "missing key", status: http.StatusOK, response: `{"data":{"data":{"ca_cert":"pem"}}}`, wantErr: "string key field"},
		{name: "invalid key", status: http.StatusOK, response: `{"data":{"data":{"key":"invalid","ca_cert":"pem"}}}`, wantErr: "decode"},
		{name: "missing certificate", status: http.StatusOK, response: `{"data":{"data":{"key":"ab"}}}`, wantErr: "string ca_cert field"},
		{name: "non-string certificate", status: http.StatusOK, response: `{"data":{"data":{"key":"ab","ca_cert":123}}}`, wantErr: "string ca_cert field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requestCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requestCount++
				if r.Method != http.MethodGet || r.URL.Path != "/v1/keys2/data/ca" {
					t.Errorf("request = %s %s, want GET /v1/keys2/data/ca", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.response))
			}))
			defer server.Close()
			client, err := Connect(strings.NewReader("address: " + server.URL + "\ntoken: dev-token\nmount: keys2\n"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.GetCertificate("ca")
			if requestCount != 1 {
				t.Fatalf("GetCertificate() requests = %d, want 1", requestCount)
			}
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("GetCertificate() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil || !bytes.Equal(got.PrivateKey, []byte("AB")) || string(got.CACert) != pem {
				t.Fatalf("GetCertificate() = %#v, %v, want private key and original PEM", got, err)
			}
		})
	}
}

func TestOpenBaoConnectRequiresConfiguration(t *testing.T) {
	tests := []struct {
		name   string
		config string
		field  string
	}{
		{name: "address", config: "token: token\nmount: keys\n", field: "address"},
		{name: "token", config: "address: http://127.0.0.1:8200\nmount: keys\n", field: "token"},
		{name: "mount", config: "address: http://127.0.0.1:8200\ntoken: token\n", field: "mount"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Connect(strings.NewReader(test.config))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), test.field) {
				t.Fatalf("Connect() error = %v, want missing %s", err, test.field)
			}
		})
	}
}
