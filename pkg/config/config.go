package config

import (
	"encoding/json"
	"os"
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
	AuditLogPath       string                    `json:"audit_log_path,omitempty"`
	// AllowedOrigins is the CORS allowlist of browser origins permitted to make
	// cross-origin requests to the gateway HTTP API. Empty means same-origin only.
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
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

	return &cfg, nil
}
