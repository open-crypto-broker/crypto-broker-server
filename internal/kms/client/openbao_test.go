package client

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbao/openbao/api/v2"
)

func TestOpenBaoClientGetKey(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name:     "KV v2 secret",
			response: `{"data":{"data":{"key":"nested-key"}}}`,
			want:     "nested-key",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/secret/example" {
					t.Errorf("request path = %q, want %q", r.URL.Path, "/v1/secret/example")
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
			
			client := &OpenBao{client: baoClient}
			key, err := client.GetKey("secret/example")
			
			if err != nil {
				t.Fatalf("GetKey() error = %v", err)
			}
			
			if string(key) != test.want {
				t.Errorf("GetKey() = %q, want %q", key, test.want)
			}
		})
	}
}
