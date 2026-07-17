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
	ListenAddr         string `json:"listen_addr"`
	HTTPAddr           string `json:"http_addr"`
	HostKeyPath        string `json:"host_key_path"`
	AuthorizedKeysPath string `json:"authorized_keys_path"`
	OllamaURL          string `json:"ollama_url"`
	OllamaModel        string `json:"ollama_model"`
	// LLMProvider selects the LLM backend used for gateway__ask_gemma,
	// gateway__humanize_syslog, and the /api/chat Ollama fallback path. See
	// llm.EngineConfig.Provider for accepted values (""/"ollama", "openai",
	// "vllm", "llamacpp", "openai-compatible", "disabled"). Empty preserves
	// the historical default: enabled (as Ollama) only when OllamaURL is set,
	// disabled otherwise.
	LLMProvider string `json:"llm_provider,omitempty"`
	// LLMAPIKey is the bearer token sent to OpenAI-compatible LLM backends
	// (OpenAI, vLLM, llama.cpp's server). Unused by the Ollama provider.
	// Resolved via resolveSecret like other secret fields (env:/file:/agenix:/vault:).
	LLMAPIKey string `json:"llm_api_key,omitempty"`
	// MaxOrchestrationSteps bounds how many tool-call iterations the
	// gateway__ask_gemma structured orchestration loop may take before it
	// must stop and summarize whatever was accomplished so far. A value <= 0
	// (including unset) defaults to 3 at the point the gateway uses it.
	MaxOrchestrationSteps int                       `json:"max_orchestration_steps,omitempty"`
	UpstreamServers       []UpstreamServer          `json:"upstream_servers,omitempty"`
	ExternalMcpServers    []ExternalMcpServerConfig `json:"external_mcp_servers,omitempty"`
	TLSCertPath           string                    `json:"tls_cert_path,omitempty"`
	TLSKeyPath            string                    `json:"tls_key_path,omitempty"`
	AuthToken             string                    `json:"auth_token,omitempty"`
	AntigravityToken      string                    `json:"antigravity_token,omitempty"`
	Tokens                map[string]string         `json:"tokens,omitempty"`
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
	// AlertWebhookURL receives a POST with a JSON alert body on every
	// threshold breach and recovery (issue #100). Empty (the default) means
	// no webhook delivery: alerts stay in-portal/log/audit as before.
	AlertWebhookURL string `json:"alert_webhook_url,omitempty"`
	// AlertmanagerURL is the BASE url of a Prometheus Alertmanager (e.g.
	// "http://alertmanager:9093"); alerts are POSTed to its /api/v2/alerts.
	// Empty (the default) means no Alertmanager delivery. May be set
	// alongside AlertWebhookURL; both targets receive every alert.
	AlertmanagerURL string `json:"alertmanager_url,omitempty"`
	// AlertDeliveryRetries is how many times a failed alert delivery is
	// retried, with exponential backoff, before it is dropped and logged. A
	// value < 0 disables retrying; 0 (unset) defaults to 3 at the point of
	// use.
	AlertDeliveryRetries int `json:"alert_delivery_retries,omitempty"`
	// AlertWebhookHeaders are extra headers sent with every AlertWebhookURL
	// delivery, e.g. {"authorization": "Bearer env:PAGERDUTY_TOKEN"} (issue
	// #127). Most on-call systems require a token, and without this the only
	// way to authenticate was to smuggle a secret into the URL - where it then
	// lands in the config, logs and error messages.
	//
	// Values resolve via resolveSecret, so "env:"/"file:"/"agenix:"/"vault:"
	// work as they do for llm_api_key. Header names are not secrets and are
	// left as-is. Empty (the default) sends no extra headers.
	AlertWebhookHeaders map[string]string `json:"alert_webhook_headers,omitempty"`
	// AlertmanagerHeaders are extra headers sent with every AlertmanagerURL
	// delivery, for an Alertmanager behind an authenticating proxy. Same
	// secret-indirection rules as AlertWebhookHeaders.
	AlertmanagerHeaders map[string]string `json:"alertmanager_headers,omitempty"`
	// EnrollmentTokenTTLSeconds bounds how long a join token minted by
	// POST /api/enroll/token remains redeemable via POST /api/enroll before
	// it expires. A value <= 0 (including unset) defaults to 900 (15
	// minutes) at the point the gateway issues a token.
	EnrollmentTokenTTLSeconds int `json:"enrollment_token_ttl_seconds,omitempty"`
	// ScheduledTasks configures recurring LLM orchestration runs (issue #6):
	// every IntervalSeconds, the gateway runs Prompt as an ask_gemma-style
	// orchestration against AgentID and routes the resulting summary through
	// notifyAlert (the same webhook/Alertmanager delivery threshold alerts
	// use). Empty/unset (the default) starts no scheduler goroutines.
	ScheduledTasks []ScheduledTask `json:"scheduled_tasks,omitempty"`

	// --- Operator authentication: mTLS (#59) ---
	//
	// ClientCACertPath is the path to a PEM-encoded CA bundle used to verify
	// operator client certificates presented over TLS. When set, the HTTP
	// server accepts (but does not require) a client certificate and, if one
	// is presented and verifies against this pool, requireAuth resolves a
	// role from it (see MTLSRole/MTLSCNRoles) without requiring a bearer
	// token. Leaving this unset preserves today's bearer-token-only behavior
	// byte-for-byte.
	ClientCACertPath string `json:"client_ca_cert_path,omitempty"`
	// MTLSRole is the role granted to a request bearing a client certificate
	// that verifies against ClientCACertPath, when its CommonName has no
	// entry in MTLSCNRoles. Defaults to "operator" when empty. Only
	// consulted when ClientCACertPath is set.
	MTLSRole string `json:"mtls_role,omitempty"`
	// MTLSCNRoles maps a verified client certificate's CommonName to a role,
	// overriding MTLSRole for that CommonName. Only consulted when
	// ClientCACertPath is set.
	MTLSCNRoles map[string]string `json:"mtls_cn_roles,omitempty"`

	// --- Operator authentication: OIDC/SSO via a trusted authenticating
	// proxy (#55) ---
	//
	// These fields let a reverse proxy (e.g. oauth2-proxy, Pomerium) perform
	// OIDC/SSO login and forward the authenticated identity to the gateway
	// in a header, alongside a shared secret proving the request actually
	// came through the proxy (and not directly from an untrusted client
	// spoofing the identity header). Both TrustedProxySecret and a non-empty
	// identity header are required for this auth method to grant a role;
	// leaving TrustedProxySecret unset preserves today's behavior.
	//
	// TrustedProxyIdentityHeader is the header name the proxy sets to the
	// authenticated user's identity (e.g. "X-Auth-Request-Email").
	TrustedProxyIdentityHeader string `json:"trusted_proxy_identity_header,omitempty"`
	// TrustedProxySecretHeader is the header name the proxy sets to the
	// shared secret (e.g. "X-Proxy-Secret").
	TrustedProxySecretHeader string `json:"trusted_proxy_secret_header,omitempty"`
	// TrustedProxySecret is the shared secret the proxy must send in
	// TrustedProxySecretHeader. Resolved via resolveSecret like other secret
	// fields (env:/file:/agenix:/vault:). Empty (the default) disables this
	// auth method entirely.
	TrustedProxySecret string `json:"trusted_proxy_secret,omitempty"`
	// TrustedProxyRole is the role granted to requests authenticated via the
	// trusted proxy. Defaults to "operator" when empty.
	TrustedProxyRole string `json:"trusted_proxy_role,omitempty"`

	// --- Durability: persistent state + graceful restart recovery (#44/#50) ---
	//
	// StatePath, when set, enables durable persistence of the fleet inventory
	// and audit-log index to a JSON file at this path (see pkg/store), so an
	// operator sees the last-known fleet immediately after a Gateway restart
	// instead of an empty list while agents reconnect. Empty (the default)
	// disables persistence entirely: behavior is identical to the
	// pre-persistence gateway (pure in-memory state, lost on restart). This
	// delivers single-gateway durability/recovery only; it is not a shared
	// backend and does not provide multi-gateway clustering (see #47/#56/#63).
	StatePath string `json:"state_path,omitempty"`
	// StateSaveSeconds sets how often (in seconds) the gateway snapshots its
	// state to StatePath in the background, in addition to the always-on
	// snapshot taken on graceful shutdown (SIGINT/SIGTERM). Only meaningful
	// when StatePath is set; a value <= 0 (including unset) defaults to 30
	// once persistence is active.
	StateSaveSeconds int `json:"state_save_seconds,omitempty"`

	// --- HA: symmetric peer mesh clustering (#47/#56/#63) ---
	//
	// Multiple gateway instances can share their agent registries and
	// forward tool calls to whichever peer holds the target agent. Agents
	// are unaffected: each still connects to exactly one gateway (its home)
	// via the existing GatewayAddrs failover; clustering only changes how
	// operator-facing API calls are routed once they reach a gateway. Empty
	// PeerGateways (the default) disables clustering entirely: no peer-sync
	// goroutine starts, the /internal/* endpoints 404, and behavior is
	// byte-for-byte identical to a standalone gateway.
	//
	// GatewayID identifies this gateway instance within the cluster (surfaced
	// in /api/fleet responses so operators can see which gateway holds each
	// agent). Empty (the default) is resolved at runtime to the OS hostname,
	// falling back to ListenAddr if the hostname cannot be determined.
	GatewayID string `json:"gateway_id,omitempty"`
	// PeerGateways lists the base HTTPS URLs of the other gateway instances
	// in this gateway's cluster (e.g. "https://gw-b:8080").
	PeerGateways []string `json:"peer_gateways,omitempty"`
	// ClusterSecret is the shared bearer token peer gateways present to each
	// other's /internal/* endpoints. Resolved via resolveSecret like other
	// secret fields (env:/file:/agenix:/vault:). Required whenever
	// PeerGateways is non-empty (see Validate).
	ClusterSecret string `json:"cluster_secret,omitempty"`
	// PeerSyncSeconds sets how often (in seconds) this gateway polls each
	// peer's /internal/agents to refresh its view of which agents are
	// connected elsewhere in the cluster. A value <= 0 (including unset)
	// defaults to 10 once clustering is active.
	PeerSyncSeconds int `json:"peer_sync_seconds,omitempty"`
	// PeerInsecureSkipVerify disables TLS certificate verification when this
	// gateway calls its peers' /internal/* endpoints. Gateways use
	// self-signed certificates by default (see startHTTPServer), so this is
	// commonly needed in test/dev clusters unless peers share a common CA.
	// Defaults to false (verify).
	PeerInsecureSkipVerify bool `json:"peer_insecure_skip_verify,omitempty"`
	// TracingEnabled turns on OpenTelemetry tracing of tool calls, Gemma
	// orchestration, upstream proxying and peer forwarding (issue #98).
	// Defaults to false: with nothing configured no tracer provider is
	// installed, spans become no-ops, and no exporter goroutines or network
	// calls exist.
	TracingEnabled bool `json:"tracing_enabled,omitempty"`
	// OTLPEndpoint is the OTLP/HTTP collector endpoint, host:port WITHOUT a
	// scheme or path (e.g. "otel-collector:4318"); the exporter appends
	// /v1/traces. Empty with TracingEnabled defaults to "localhost:4318".
	OTLPEndpoint string `json:"otlp_endpoint,omitempty"`
	// OTLPInsecure sends OTLP over plain HTTP instead of HTTPS. Collectors
	// commonly listen on plaintext 4318 inside a trusted network.
	OTLPInsecure bool `json:"otlp_insecure,omitempty"`
	// OTLPHeaders are extra headers sent to the collector, e.g. an auth token
	// for a hosted backend. Values are resolved via resolveSecret, so
	// "env:OTLP_TOKEN" / "file:/run/secrets/x" / "agenix:name" / "vault:path"
	// work as they do for llm_api_key.
	OTLPHeaders map[string]string `json:"otlp_headers,omitempty"`
	// TraceSampleRatio is the head-sampling ratio, 0.0-1.0. 0 (unset) means
	// 1.0 (sample everything) when tracing is enabled - a gateway's tool-call
	// rate is low enough that full sampling is the useful default. Set lower
	// for a busy fleet.
	TraceSampleRatio float64 `json:"trace_sample_ratio,omitempty"`
	// TraceServiceName is the service.name resource attribute reported to the
	// collector. Empty defaults to "myrmex-gateway".
	TraceServiceName string `json:"trace_service_name,omitempty"`
	// OIDCIssuer enables native OIDC/JWKS bearer-token validation (#114).
	// The issuer URL, e.g. "https://accounts.google.com" or
	// "https://login.microsoftonline.com/<tenant>/v2.0" — the gateway fetches
	// <issuer>/.well-known/openid-configuration to discover the JWKS endpoint,
	// and go-oidc caches and rotates the keys.
	//
	// Empty (the default) disables OIDC entirely: no discovery, no network
	// calls, and bearer tokens resolve exactly as before.
	//
	// This does NOT replace static tokens. A bearer that fails OIDC validation
	// still falls through to scoped_tokens/tokens/auth_token, so existing
	// deployments are unaffected.
	OIDCIssuer string `json:"oidc_issuer,omitempty"`
	// OIDCAudience is the expected `aud` claim — normally your client ID.
	// REQUIRED when OIDCIssuer is set: without it any token the issuer minted
	// for ANY audience would be accepted here, which is a confused-deputy
	// waiting to happen. Validate() enforces this.
	OIDCAudience string `json:"oidc_audience,omitempty"`
	// OIDCRoleClaim is the JWT claim carrying the caller's groups/roles.
	// Defaults to "groups". The claim may be a string or an array of strings.
	OIDCRoleClaim string `json:"oidc_role_claim,omitempty"`
	// OIDCRoleMap maps a value from OIDCRoleClaim to a gateway role, e.g.
	// {"myrmex-admins": "admin", "sre-oncall": "operator"}. REQUIRED when
	// OIDCIssuer is set: with no mapping every validated token would resolve
	// no role and be denied, so an empty map is a misconfiguration, not a
	// default. Validate() enforces this.
	//
	// A caller matching several entries gets the most privileged
	// (admin > operator > read-only), matching how group membership is
	// normally additive.
	OIDCRoleMap map[string]string `json:"oidc_role_map,omitempty"`
	// MetricsEnabled exposes a Prometheus exposition endpoint at /metrics on
	// the gateway's HTTP server (issue #97). Defaults to false: with nothing
	// configured the route is not registered at all and behavior is unchanged.
	//
	// The endpoint sits behind requireAuth like every other API path, so a
	// scraper must present a bearer token (Prometheus scrape_config supports
	// this via `authorization:`). The per-agent resource gauges additionally
	// require MetricsPollSeconds > 0, which is what populates the samples they
	// read.
	MetricsEnabled bool `json:"metrics_enabled,omitempty"`
}

// AlertThresholds defines the percentage thresholds that trigger a threshold
// alert when breached by a polled get_metrics sample. A field <= 0 means
// that dimension is not alerted on.
type AlertThresholds struct {
	CPUPercent  float64 `json:"cpu_percent"`
	MemPercent  float64 `json:"mem_percent"`
	DiskPercent float64 `json:"disk_percent"`
}

// ScheduledTask is one recurring orchestration job (see GatewayConfig.ScheduledTasks).
type ScheduledTask struct {
	Name            string `json:"name"`
	AgentID         string `json:"agent_id"`
	Prompt          string `json:"prompt"`
	IntervalSeconds int    `json:"interval_seconds"`
}

// Validate checks the GatewayConfig for missing/inconsistent required fields
// and returns an aggregated error listing every problem found, or nil if the
// config is usable.
func (c *GatewayConfig) Validate() error {
	var errs []error

	if c.ListenAddr == "" {
		errs = append(errs, fmt.Errorf("listen_addr must be set"))
	}

	// OIDC (#114) fails closed on misconfiguration rather than degrading into
	// something permissive.
	if c.OIDCIssuer != "" {
		if c.OIDCAudience == "" {
			// Without an audience check, ANY token the issuer minted — for any
			// application — would authenticate here. On a shared IdP that is a
			// confused deputy, not an inconvenience.
			errs = append(errs, fmt.Errorf("oidc_audience must be set when oidc_issuer is: without it any token from that issuer, for any audience, would be accepted"))
		}
		if len(c.OIDCRoleMap) == 0 {
			// Every validated token would map to no role and be denied. That is
			// a config mistake, and silently authenticating nobody is a
			// confusing way to discover it.
			errs = append(errs, fmt.Errorf("oidc_role_map must be set when oidc_issuer is: with no mapping every validated token resolves no role and is denied"))
		}
		for claim, role := range c.OIDCRoleMap {
			switch role {
			case "admin", "operator", "read-only":
			default:
				errs = append(errs, fmt.Errorf("oidc_role_map[%q] = %q is not a gateway role (admin, operator, read-only)", claim, role))
			}
		}
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

	// Fail closed: without a ClusterSecret the /internal/* peer endpoints
	// are disabled entirely (see requireClusterSecret), which would make a
	// configured peer mesh silently non-functional rather than insecure —
	// but that's still a misconfiguration worth catching at load time.
	if len(c.PeerGateways) > 0 && c.ClusterSecret == "" {
		errs = append(errs, fmt.Errorf("cluster_secret must be set when peer_gateways is non-empty"))
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
	cfg.LLMAPIKey = resolveSecret(cfg.LLMAPIKey)
	cfg.TrustedProxySecret = resolveSecret(cfg.TrustedProxySecret)
	cfg.ClusterSecret = resolveSecret(cfg.ClusterSecret)
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
	// OTLP header VALUES only: a hosted tracing backend's auth token belongs
	// in an env/file/agenix/vault reference, not inline in the config. Header
	// names are not secrets and are left as-is.
	for _, headers := range []map[string]string{cfg.AlertWebhookHeaders, cfg.AlertmanagerHeaders} {
		for name, value := range headers {
			headers[name] = resolveSecret(value)
		}
	}
	if cfg.OTLPHeaders != nil {
		resolvedHeaders := make(map[string]string, len(cfg.OTLPHeaders))
		for name, value := range cfg.OTLPHeaders {
			resolvedHeaders[name] = resolveSecret(value)
		}
		cfg.OTLPHeaders = resolvedHeaders
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}
