package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"
)

// agenixNameRe validates agenix secret names ("agenix:<name>") so the derived
// path /run/agenix/<name> cannot be used for directory traversal.
var agenixNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

type AllowedCommand struct {
	Name      string `json:"name"`
	ArgsRegex string `json:"args_regex"`
}

type AgentConfig struct {
	GatewayAddr     string           `json:"gateway_addr"`
	GatewayAddrs    []string         `json:"gateway_addrs,omitempty"`
	PrivateKeyPath  string           `json:"private_key_path"`
	AgentID         string           `json:"agent_id"`
	AllowedCommands []AllowedCommand `json:"allowed_commands"`
	// GatewayHostKey pins the gateway's SSH host key. When set, it must be an
	// OpenSSH authorized_keys-formatted public key line and the agent will only
	// connect to a gateway presenting exactly this host key.
	GatewayHostKey string `json:"gateway_host_key,omitempty"`
	// KnownHostKeyPath is the path used to persist a trust-on-first-use (TOFU)
	// learned gateway host key. Defaults to PrivateKeyPath+".gateway_hostkey".
	KnownHostKeyPath string `json:"known_host_key_path,omitempty"`
}

// Validate checks the AgentConfig for missing/inconsistent required fields
// and normalizes GatewayAddrs so callers can rely on it being populated
// whenever GatewayAddr and/or GatewayAddrs was set. It returns an aggregated
// error listing every problem found, or nil if the config is usable.
func (c *AgentConfig) Validate() error {
	var errs []error

	if c.GatewayAddr == "" && len(c.GatewayAddrs) == 0 {
		errs = append(errs, fmt.Errorf("at least one of gateway_addr or gateway_addrs must be set"))
	}

	// Normalize: ensure GatewayAddrs reflects both fields so callers only
	// need to consult GatewayAddrs.
	if len(c.GatewayAddrs) == 0 && c.GatewayAddr != "" {
		c.GatewayAddrs = []string{c.GatewayAddr}
	} else if c.GatewayAddr != "" {
		found := false
		for _, a := range c.GatewayAddrs {
			if a == c.GatewayAddr {
				found = true
				break
			}
		}
		if !found {
			c.GatewayAddrs = append([]string{c.GatewayAddr}, c.GatewayAddrs...)
		}
	}

	if c.AgentID == "" {
		errs = append(errs, fmt.Errorf("agent_id must be set"))
	}
	if c.PrivateKeyPath == "" {
		errs = append(errs, fmt.Errorf("private_key_path must be set"))
	}

	return errors.Join(errs...)
}

type UpstreamServer struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

type ExternalMcpServerConfig struct {
	Name      string            `json:"name"`
	Transport string            `json:"transport"` // "stdio" or "sse"
	Command   string            `json:"command,omitempty"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	URL       string            `json:"url,omitempty"`
	AuthToken string            `json:"auth_token,omitempty"`
}

// TokenScope restricts a bearer token to a role plus an optional subset of
// agents (by ID or tag) and tools it may invoke. A token with no Agents/Tags
// entries is unrestricted with respect to agents; likewise for Tools. This is
// the fine-grained authorization layer on top of the coarser path-based RBAC
// in rolePermissions (cmd/gateway/main.go).
type TokenScope struct {
	Token  string   `json:"token"`
	Role   string   `json:"role"`
	Agents []string `json:"agents,omitempty"`
	Tags   []string `json:"tags,omitempty"`
	Tools  []string `json:"tools,omitempty"`
}

type GatewayConfig struct {
	ListenAddr         string                    `json:"listen_addr"`
	HTTPAddr           string                    `json:"http_addr"`
	HostKeyPath        string                    `json:"host_key_path"`
	AuthorizedKeysPath string                    `json:"authorized_keys_path"`
	OllamaURL          string                    `json:"ollama_url"`
	OllamaModel        string                    `json:"ollama_model"`
	UpstreamServers    []UpstreamServer          `json:"upstream_servers,omitempty"`
	ExternalMcpServers []ExternalMcpServerConfig `json:"external_mcp_servers,omitempty"`
	TLSCertPath        string                    `json:"tls_cert_path,omitempty"`
	TLSKeyPath         string                    `json:"tls_key_path,omitempty"`
	AuthToken          string                    `json:"auth_token,omitempty"`
	AntigravityToken   string                    `json:"antigravity_token,omitempty"`
	Tokens             map[string]string         `json:"tokens,omitempty"`
	// ScopedTokens are bearer tokens restricted to a role plus an optional
	// subset of agents/tags/tools. They are checked before Tokens/AuthToken
	// during authentication; existing Tokens/AuthToken entries remain
	// unrestricted for backward compatibility.
	ScopedTokens []TokenScope `json:"scoped_tokens,omitempty"`
	// AgentTags maps an agent ID to the set of tags it belongs to, used to
	// evaluate TokenScope.Tags.
	AgentTags    map[string][]string `json:"agent_tags,omitempty"`
	AuditLogPath string              `json:"audit_log_path,omitempty"`
	// AllowedOrigins is the CORS allowlist of browser origins permitted to make
	// cross-origin requests to the gateway HTTP API. Empty means same-origin only.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	// RiskTiers maps an unprefixed tool name (e.g. "run_command",
	// "service_control", "get_metrics") to a risk tier: "read", "mutate", or
	// "destructive". Tools not listed default to "read". Used together with
	// RequireApprovalTiers and RateLimitPerMinute to gate risky calls.
	RiskTiers map[string]string `json:"risk_tiers,omitempty"`
	// RequireApprovalTiers lists the risk tiers that must be approved by an
	// admin (via the gateway's /api/approvals endpoint) before executing.
	// Empty/unset means no calls require approval, preserving backward
	// compatibility.
	RequireApprovalTiers []string `json:"require_approval_tiers,omitempty"`
	// RateLimitPerMinute caps the number of tool calls allowed per minute for
	// a given (token, agent, tool) combination. 0 (the default) disables rate
	// limiting entirely.
	RateLimitPerMinute int `json:"rate_limit_per_minute,omitempty"`
	// MetricsPollSeconds, when > 0, enables periodic background polling of
	// each connected agent's get_metrics tool. 0 (the default) disables
	// polling entirely, preserving backward compatibility: no config change
	// means no new goroutines, network calls, or memory growth.
	MetricsPollSeconds int `json:"metrics_poll_seconds,omitempty"`
	// MetricsHistorySize caps the number of metrics samples retained in
	// memory per agent (a ring buffer). Only meaningful when
	// MetricsPollSeconds > 0; defaults to 60 when unset/<=0 while polling is
	// enabled.
	MetricsHistorySize int `json:"metrics_history_size,omitempty"`
	// AlertThresholds configures fleet-wide threshold alerting evaluated
	// against each polled metrics sample. Nil (the default) disables
	// alerting entirely.
	AlertThresholds *AlertThresholds `json:"alert_thresholds,omitempty"`
	// EnrollmentTokenTTLSeconds bounds how long a join token minted by
	// POST /api/enroll/token remains redeemable via POST /api/enroll before
	// it expires. A value <= 0 (including unset) defaults to 900 (15
	// minutes) at the point the gateway issues a token.
	EnrollmentTokenTTLSeconds int `json:"enrollment_token_ttl_seconds,omitempty"`
}

// AlertThresholds defines the percentage thresholds that trigger a threshold
// alert when breached by a polled get_metrics sample. A field <= 0 means
// that dimension is not alerted on.
type AlertThresholds struct {
	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float64 `json:"mem_percent"`
	DiskPercent float64 `json:"disk_percent"`
}

// Validate checks the GatewayConfig for missing/inconsistent required fields
// and returns an aggregated error listing every problem found, or nil if the
// config is usable.
func (c *GatewayConfig) Validate() error {
	var errs []error

	if c.ListenAddr == "" {
		errs = append(errs, fmt.Errorf("listen_addr must be set"))
	}

	// Mirrors the runtime fail-closed rule: a signed audit log requires a
	// host key to sign with, so catch the misconfiguration at load time
	// rather than at first audit-log write.
	if c.AuditLogPath != "" && c.HostKeyPath == "" {
		errs = append(errs, fmt.Errorf("host_key_path must be set when audit_log_path is set"))
	}

	for i, st := range c.ScopedTokens {
		if st.Token == "" {
			errs = append(errs, fmt.Errorf("scoped_tokens[%d]: token must not be empty", i))
		}
		if st.Role == "" {
			errs = append(errs, fmt.Errorf("scoped_tokens[%d]: role must not be empty", i))
		}
	}

	return errors.Join(errs...)
}

// resolveSecret resolves indirect secret references so secret-bearing config
// values need not be written inline in the JSON config. Supported forms:
//
//   - "env:NAME"          -> the value of environment variable NAME
//   - "file:/path/to/f"   -> the trimmed contents of that file
//   - "agenix:<name>"     -> the trimmed contents of /run/agenix/<name>; a
//     convenience form over "file:/run/agenix/<name>" for agenix-managed
//     secrets. <name> must match ^[A-Za-z0-9._-]+$ (no path traversal).
//   - "${NAME}"           -> the value of environment variable NAME (whole-string form)
//   - "vault:<path>#field" -> the named field read from HashiCorp Vault's KV
//     secret engine at <path> (e.g. "vault:secret/data/myrmex#auth_token"),
//     using VAULT_ADDR (default "http://127.0.0.1:8200") and VAULT_TOKEN from
//     the environment. Supports both KV v2 (.data.data.<field>) and KV v1
//     (.data.<field>) response shapes.
//   - anything else       -> returned unchanged, preserving backward compatibility
//
// agenix and sops-nix both decrypt secrets to files at runtime (e.g. under
// /run/agenix or /run/secrets), so their secrets are consumed via the "file:"
// form (or the "agenix:" convenience form) — no in-process decryption is done
// here.
//
// File read errors and Vault errors are logged to stderr and resolve to ""
// rather than panicking.
func resolveSecret(s string) string {
	switch {
	case strings.HasPrefix(s, "env:"):
		return strings.TrimSpace(os.Getenv(strings.TrimPrefix(s, "env:")))
	case strings.HasPrefix(s, "file:"):
		data, err := os.ReadFile(strings.TrimPrefix(s, "file:"))
		if err != nil {
			log.Printf("resolveSecret: failed to read secret file %q: %v", strings.TrimPrefix(s, "file:"), err)
			return ""
		}
		return strings.TrimSpace(string(data))
	case strings.HasPrefix(s, "agenix:"):
		name := strings.TrimPrefix(s, "agenix:")
		if !agenixNameRe.MatchString(name) {
			log.Printf("resolveSecret: invalid agenix secret name %q: must match %s", name, agenixNameRe.String())
			return ""
		}
		// Sugar over "file:/run/agenix/<name>"; agenix decrypts secrets to
		// this path at runtime.
		return resolveSecret("file:/run/agenix/" + name)
	case strings.HasPrefix(s, "vault:"):
		val, err := resolveVault(strings.TrimPrefix(s, "vault:"))
		if err != nil {
			log.Printf("resolveSecret: failed to resolve vault secret %q: %v", s, err)
			return ""
		}
		return strings.TrimSpace(val)
	case strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}"):
		return strings.TrimSpace(os.Getenv(s[2 : len(s)-1]))
	default:
		return s
	}
}

// resolveVault reads a secret from HashiCorp Vault's HTTP KV API. ref is of
// the form "<mountAndPath>#<field>", e.g. "secret/data/myrmex#auth_token".
// It reads VAULT_ADDR (default "http://127.0.0.1:8200") and VAULT_TOKEN from
// the environment, and supports both KV v2 (.data.data.<field>) and KV v1
// (.data.<field>) response shapes, trying v2 first.
func resolveVault(ref string) (string, error) {
	pathAndField := strings.SplitN(ref, "#", 2)
	if len(pathAndField) != 2 || pathAndField[0] == "" || pathAndField[1] == "" {
		return "", fmt.Errorf("invalid vault reference %q: expected \"<path>#<field>\"", ref)
	}
	path, field := pathAndField[0], pathAndField[1]

	token := os.Getenv("VAULT_TOKEN")
	if token == "" {
		return "", fmt.Errorf("VAULT_TOKEN is not set")
	}

	addr := os.Getenv("VAULT_ADDR")
	if addr == "" {
		addr = "http://127.0.0.1:8200"
	}

	url := strings.TrimRight(addr, "/") + "/v1/" + strings.TrimLeft(path, "/")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("building vault request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("vault request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("vault returned status %d for %q", resp.StatusCode, url)
	}

	// Decode generically so both KV v1 ({"data": {field: ...}}) and KV v2
	// ({"data": {"data": {field: ...}}}) response shapes can be inspected
	// from a single parse.
	var body struct {
		Data map[string]any `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decoding vault response: %w", err)
	}

	// KV v2 shape: data.data.<field>
	if inner, ok := body.Data["data"].(map[string]any); ok {
		if v, ok := inner[field]; ok {
			s, ok := v.(string)
			if !ok {
				return "", fmt.Errorf("vault field %q is not a string", field)
			}
			return s, nil
		}
	}

	// KV v1 shape: data.<field>
	if v, ok := body.Data[field]; ok {
		s, ok := v.(string)
		if !ok {
			return "", fmt.Errorf("vault field %q is not a string", field)
		}
		return s, nil
	}

	return "", fmt.Errorf("field %q not found in vault response for %q", field, url)
}

func LoadAgentConfig(path string) (*AgentConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg AgentConfig
	dec := json.NewDecoder(file)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func LoadGatewayConfig(path string) (*GatewayConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg GatewayConfig
	dec := json.NewDecoder(file)
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}

	// Resolve secret indirection so operators can reference an env var or a
	// file instead of embedding the secret value directly in the JSON config.
	cfg.AuthToken = resolveSecret(cfg.AuthToken)
	cfg.AntigravityToken = resolveSecret(cfg.AntigravityToken)
	if cfg.Tokens != nil {
		resolvedTokens := make(map[string]string, len(cfg.Tokens))
		for token, role := range cfg.Tokens {
			resolvedTokens[resolveSecret(token)] = role
		}
		cfg.Tokens = resolvedTokens
	}
	for i := range cfg.ScopedTokens {
		cfg.ScopedTokens[i].Token = resolveSecret(cfg.ScopedTokens[i].Token)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
