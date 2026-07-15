package main

import (
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// secretFields are GatewayConfig fields whose value is (or contains) secret
// material and MUST NOT be returned by GET /api/config.
var secretFields = map[string]bool{
	"AuthToken":           true,
	"AntigravityToken":    true,
	"LLMAPIKey":           true,
	"TrustedProxySecret":  true,
	"ClusterSecret":       true,
	"Tokens":              true, // the map KEYS are the tokens
	"ScopedTokens":        true, // .Token within each entry
	"OTLPHeaders":         true, // values commonly carry an auth token
	"AlertWebhookHeaders": true, // values carry the on-call system's token
	"AlertmanagerHeaders": true, // ditto, for an authenticating proxy
	"TLSKeyPath":          true, // points at private key material
}

// nonSecretFields are GatewayConfig fields that are safe to return. Listed
// explicitly so a NEW field cannot be silently assumed safe.
var nonSecretFields = map[string]bool{
	"ListenAddr": true, "HTTPAddr": true, "HostKeyPath": true,
	"AuthorizedKeysPath": true, "OllamaURL": true, "OllamaModel": true,
	"LLMProvider": true, "MaxOrchestrationSteps": true, "UpstreamServers": true,
	"ExternalMcpServers": true, "TLSCertPath": true, "AgentTags": true,
	"AuditLogPath": true, "AllowedOrigins": true, "RiskTiers": true,
	"RequireApprovalTiers": true, "RateLimitPerMinute": true,
	"MetricsPollSeconds": true, "MetricsHistorySize": true,
	"AlertThresholds": true, "AlertWebhookURL": true, "AlertmanagerURL": true,
	"AlertDeliveryRetries": true, "EnrollmentTokenTTLSeconds": true,
	"ClientCACertPath": true, "MTLSRole": true, "MTLSCNRoles": true,
	"TrustedProxyIdentityHeader": true, "TrustedProxySecretHeader": true,
	"TrustedProxyRole": true, "StatePath": true, "StateSaveSeconds": true,
	"GatewayID": true, "PeerGateways": true, "PeerSyncSeconds": true,
	"PeerInsecureSkipVerify": true, "TracingEnabled": true,
	"OTLPEndpoint": true, "OTLPInsecure": true, "TraceSampleRatio": true,
	"TraceServiceName": true, "MetricsEnabled": true,
}

// This is the guard for #131. Redaction was a hand-maintained list of four
// fields and drifted five times as secrets were added, leaking llm_api_key,
// cluster_secret, trusted_proxy_secret, scoped_tokens and otlp_headers over the
// API. Every NEW GatewayConfig field must be classified here, so adding a
// secret without redacting it fails the build instead of shipping.
func TestGatewayConfigFieldsAreClassified(t *testing.T) {
	typ := reflect.TypeOf(config.GatewayConfig{})
	var unclassified []string

	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !secretFields[name] && !nonSecretFields[name] {
			unclassified = append(unclassified, name)
		}
	}

	sort.Strings(unclassified)
	if len(unclassified) > 0 {
		t.Errorf("GatewayConfig has unclassified field(s): %v\n\n"+
			"A new config field must be added to secretFields or nonSecretFields in "+
			"redact_test.go. If it holds a token/key/password, add it to secretFields "+
			"AND redact it in redactConfigSecrets (cmd/gateway/redact.go) - that is the "+
			"drift that caused #131.", unclassified)
	}
}

// Every field classified secret must actually be scrubbed by
// redactConfigSecrets. Serializing to JSON is the real test: it is exactly what
// handleApiConfig returns, and it catches a nested field (ScopedTokens[].Token)
// that a top-level check would miss.
func TestRedactConfigSecretsRemovesEverySecret(t *testing.T) {
	cfg := &config.GatewayConfig{
		AuthToken:          "SENTINEL-AUTH",
		AntigravityToken:   "SENTINEL-ANTIGRAVITY",
		LLMAPIKey:          "SENTINEL-LLM",
		TrustedProxySecret: "SENTINEL-PROXY",
		ClusterSecret:      "SENTINEL-CLUSTER",
		TLSKeyPath:         "SENTINEL-TLSKEY",
		Tokens:             map[string]string{"SENTINEL-TOKENKEY": "admin"},
		ScopedTokens: []config.TokenScope{
			{Token: "SENTINEL-SCOPED", Role: "operator", Agents: []string{"web-1"}},
		},
		OTLPHeaders: map[string]string{"authorization": "SENTINEL-OTLP"},
	}
	redactConfigSecrets(cfg)

	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	body := string(out)

	for _, sentinel := range []string{
		"SENTINEL-AUTH", "SENTINEL-ANTIGRAVITY", "SENTINEL-LLM",
		"SENTINEL-PROXY", "SENTINEL-CLUSTER", "SENTINEL-TLSKEY",
		"SENTINEL-TOKENKEY", "SENTINEL-SCOPED", "SENTINEL-OTLP",
	} {
		if strings.Contains(body, sentinel) {
			t.Errorf("%s leaked into the /api/config response:\n%s", sentinel, body)
		}
	}
}

// Redaction must not destroy the non-secret structure operators need to debug
// an authz decision or confirm that auth is configured at all.
func TestRedactConfigSecretsKeepsUsefulShape(t *testing.T) {
	cfg := &config.GatewayConfig{
		ListenAddr:    ":2222",
		ClusterSecret: "SENTINEL-CLUSTER",
		ScopedTokens: []config.TokenScope{
			{Token: "SENTINEL-SCOPED", Role: "operator", Agents: []string{"web-1"}, Tools: []string{"get_metrics"}},
		},
		OTLPHeaders: map[string]string{"authorization": "SENTINEL-OTLP"},
	}
	redactConfigSecrets(cfg)

	if cfg.ListenAddr != ":2222" {
		t.Errorf("non-secret field mangled: ListenAddr = %q", cfg.ListenAddr)
	}
	// A set secret reads as [redacted], not "" - operators must be able to tell
	// "configured but hidden" from "not configured".
	if cfg.ClusterSecret != redactedPlaceholder {
		t.Errorf("set secret should read %q, got %q", redactedPlaceholder, cfg.ClusterSecret)
	}
	if len(cfg.ScopedTokens) != 1 || cfg.ScopedTokens[0].Role != "operator" ||
		len(cfg.ScopedTokens[0].Agents) != 1 || cfg.ScopedTokens[0].Agents[0] != "web-1" {
		t.Errorf("scoped-token shape lost: %+v", cfg.ScopedTokens)
	}
	if _, ok := cfg.OTLPHeaders["authorization"]; !ok {
		t.Error("OTLP header NAME should survive redaction (only the value is secret)")
	}
}

// An unset secret must stay "" rather than becoming "[redacted]", or every
// response would claim secrets are configured when they are not.
func TestRedactConfigSecretsLeavesUnsetSecretsEmpty(t *testing.T) {
	cfg := &config.GatewayConfig{ListenAddr: ":2222"}
	redactConfigSecrets(cfg)

	if cfg.AuthToken != "" || cfg.ClusterSecret != "" || cfg.LLMAPIKey != "" {
		t.Errorf("unset secrets should stay empty, got auth=%q cluster=%q llm=%q",
			cfg.AuthToken, cfg.ClusterSecret, cfg.LLMAPIKey)
	}
}

// redactConfigSecrets must not mutate the live config through the shared maps
// and slices a shallow copy carries.
func TestRedactConfigSecretsDoesNotMutateOriginal(t *testing.T) {
	live := &config.GatewayConfig{
		ScopedTokens: []config.TokenScope{{Token: "SENTINEL-SCOPED", Role: "operator"}},
		OTLPHeaders:  map[string]string{"authorization": "SENTINEL-OTLP"},
	}
	safe := *live // the shallow copy handleApiConfig makes
	redactConfigSecrets(&safe)

	if live.ScopedTokens[0].Token != "SENTINEL-SCOPED" {
		t.Error("redaction mutated the LIVE config's scoped token - auth would break at runtime")
	}
	if live.OTLPHeaders["authorization"] != "SENTINEL-OTLP" {
		t.Error("redaction mutated the LIVE config's OTLP headers")
	}
}

// The round trip that makes redaction safe (#131). GET /api/config and POST
// /api/config are a loop: the portal POSTs {...currentConfigData, edits}, i.e.
// the redacted GET response. Without preserveRedactedSecrets, saving settings
// writes the placeholder to disk and the admin bearer token becomes the literal
// public string "[redacted]".
func TestPreserveRedactedSecretsSurvivesPortalRoundTrip(t *testing.T) {
	live := &config.GatewayConfig{
		ListenAddr:         ":2222",
		AuthToken:          "REAL-ADMIN",
		AntigravityToken:   "REAL-ANTIGRAVITY",
		LLMAPIKey:          "REAL-LLM",
		TrustedProxySecret: "REAL-PROXY",
		ClusterSecret:      "REAL-CLUSTER",
		TLSKeyPath:         "/real/tls.key",
		Tokens:             map[string]string{"REAL-TOKENKEY": "admin"},
		ScopedTokens:       []config.TokenScope{{Token: "REAL-SCOPED", Role: "operator"}},
		OTLPHeaders:        map[string]string{"authorization": "REAL-OTLP"},
	}

	// Exactly what the portal does: GET (redacted) -> spread -> POST.
	roundTripped := *live
	redactConfigSecrets(&roundTripped)
	incoming := roundTripped
	incoming.ListenAddr = ":3333" // the operator's actual edit

	preserveRedactedSecrets(&incoming, live)

	if incoming.AuthToken != "REAL-ADMIN" {
		t.Errorf("auth_token = %q after round trip, want REAL-ADMIN — the admin token would be destroyed or set to the placeholder", incoming.AuthToken)
	}
	for name, got := range map[string]string{
		"antigravity_token":    incoming.AntigravityToken,
		"llm_api_key":          incoming.LLMAPIKey,
		"trusted_proxy_secret": incoming.TrustedProxySecret,
		"cluster_secret":       incoming.ClusterSecret,
		"tls_key_path":         incoming.TLSKeyPath,
	} {
		if got == "" || got == redactedPlaceholder {
			t.Errorf("%s = %q after round trip — secret lost or corrupted", name, got)
		}
	}
	if incoming.Tokens == nil || incoming.Tokens["REAL-TOKENKEY"] != "admin" {
		t.Errorf("tokens map destroyed by round trip: %v", incoming.Tokens)
	}
	if len(incoming.ScopedTokens) != 1 || incoming.ScopedTokens[0].Token != "REAL-SCOPED" {
		t.Errorf("scoped token destroyed by round trip: %+v", incoming.ScopedTokens)
	}
	if incoming.OTLPHeaders["authorization"] != "REAL-OTLP" {
		t.Errorf("otlp header destroyed by round trip: %v", incoming.OTLPHeaders)
	}
	if incoming.ListenAddr != ":3333" {
		t.Errorf("the operator's actual edit was lost: %q", incoming.ListenAddr)
	}
}

// A real new value must still be honored — the portal has an antigravity-token
// field, and "unchanged" semantics must not make secrets unsettable.
func TestPreserveRedactedSecretsHonorsRealEdits(t *testing.T) {
	live := &config.GatewayConfig{AntigravityToken: "OLD", ClusterSecret: "OLD-CLUSTER"}
	incoming := config.GatewayConfig{AntigravityToken: "BRAND-NEW", ClusterSecret: redactedPlaceholder}

	preserveRedactedSecrets(&incoming, live)

	if incoming.AntigravityToken != "BRAND-NEW" {
		t.Errorf("a real edit was overwritten: %q", incoming.AntigravityToken)
	}
	if incoming.ClusterSecret != "OLD-CLUSTER" {
		t.Errorf("an untouched secret was not preserved: %q", incoming.ClusterSecret)
	}
}
