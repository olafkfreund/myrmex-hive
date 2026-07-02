package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestResolveSecretVaultKV2(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if r.URL.Path != "/v1/secret/data/x" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		resp := map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"field": "s3cr3t",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	got := resolveSecret("vault:secret/data/x#field")
	if got != "s3cr3t" {
		t.Fatalf("resolveSecret() = %q, want %q", got, "s3cr3t")
	}
}

func TestResolveSecretVaultKV1(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/secret/x" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		resp := map[string]any{
			"data": map[string]any{
				"field": "  v1-secret  ",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	got := resolveSecret("vault:secret/x#field")
	if got != "v1-secret" {
		t.Fatalf("resolveSecret() = %q, want %q (trimmed)", got, "v1-secret")
	}
}

func TestResolveSecretVaultMissingToken(t *testing.T) {
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:0")
	t.Setenv("VAULT_TOKEN", "")

	got := resolveSecret("vault:secret/data/x#field")
	if got != "" {
		t.Fatalf("resolveSecret() = %q, want empty string when VAULT_TOKEN is unset", got)
	}
}

func TestResolveSecretVaultNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	got := resolveSecret("vault:secret/data/x#field")
	if got != "" {
		t.Fatalf("resolveSecret() = %q, want empty string on non-200 response", got)
	}
}

func TestResolveSecretVaultMissingField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"data": map[string]any{
				"data": map[string]any{
					"other_field": "value",
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("VAULT_ADDR", srv.URL)
	t.Setenv("VAULT_TOKEN", "test-token")

	got := resolveSecret("vault:secret/data/x#field")
	if got != "" {
		t.Fatalf("resolveSecret() = %q, want empty string when field is missing", got)
	}
}
