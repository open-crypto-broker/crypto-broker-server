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
		{name: "PEM certificate", status: http.StatusOK, response: `{"data":{"data":{"certificate":"-----BEGIN CERTIFICATE-----\nPEM content\n-----END CERTIFICATE-----\n"}}}`},
		{name: "not found", status: http.StatusNotFound, response: `{}`, wantErr: "was not found"},
		{name: "permission denied", status: http.StatusForbidden, response: `{"errors":["permission denied"]}`, wantErr: "permission denied"},
		{name: "not KV v2", status: http.StatusOK, response: `{"data":{"certificate":"pem"}}`, wantErr: "KV v2 data"},
		{name: "missing certificate", status: http.StatusOK, response: `{"data":{"data":{"key":"ab"}}}`, wantErr: "string certificate field"},
		{name: "non-string certificate", status: http.StatusOK, response: `{"data":{"data":{"certificate":123}}}`, wantErr: "string certificate field"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/keys2/data/ca" {
					t.Errorf("request = %s %s, want GET /v1/keys2/data/ca", r.Method, r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.response))
			}))
			defer server.Close()
			client, err := Connect(strings.NewReader("address: " + server.URL + "\nmount: keys2\n"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := client.GetCertificate("ca")
			if test.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErr) {
					t.Fatalf("GetCertificate() error = %v, want %q", err, test.wantErr)
				}
				return
			}
			if err != nil || string(got) != pem {
				t.Fatalf("GetCertificate() = %q, %v, want original PEM", got, err)
			}
		})
	}
}
