package client

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
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
