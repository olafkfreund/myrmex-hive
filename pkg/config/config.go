package config

import (
	"encoding/json"
	"log"
	"os"
	"strings"
)

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
}

// resolveSecret resolves indirect secret references so secret-bearing config
// values need not be written inline in the JSON config. Supported forms:
//
//   - "env:NAME"        -> the value of environment variable NAME
//   - "file:/path/to/f" -> the trimmed contents of that file
//   - "${NAME}"         -> the value of environment variable NAME (whole-string form)
//   - anything else     -> returned unchanged, preserving backward compatibility
//
// File read errors are logged to stderr and resolve to "" rather than panicking.
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
	case strings.HasPrefix(s, "${") && strings.HasSuffix(s, "}"):
		return strings.TrimSpace(os.Getenv(s[2 : len(s)-1]))
	default:
		return s
	}
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

	return &cfg, nil
}
