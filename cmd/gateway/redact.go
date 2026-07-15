package main

// Config redaction for GET /api/config (issue #131).
//
// This used to be four inline assignments in handleApiConfig. Every wave that
// added a secret to GatewayConfig had to remember to extend that list, and five
// did not — llm_api_key, cluster_secret, trusted_proxy_secret,
// scoped_tokens[].token and otlp_headers were all returned in plaintext to any
// admin caller (and to the web portal, which calls this endpoint).
//
// The fix is not just "add the missing five": it is that redaction now lives in
// one place with a reflection test (TestGatewayConfigFieldsAreClassified) that
// fails the build when a NEW GatewayConfig field appears without being
// classified secret or non-secret. A hand-maintained list is exactly what
// failed here, so the guard must not depend on anyone remembering.

import "github.com/olafkfreund/myrmex-hive/pkg/config"

// redactedPlaceholder marks a secret that IS set, without revealing it. An
// empty string would be ambiguous: operators could not tell "not configured"
// from "configured but hidden", which matters when debugging why, say, peer
// forwarding or an LLM backend is not working.
const redactedPlaceholder = "[redacted]"

// redactSecret returns the placeholder for a set secret, or "" when unset, so
// the response distinguishes configured-but-hidden from not-configured.
func redactSecret(s string) string {
	if s == "" {
		return ""
	}
	return redactedPlaceholder
}

// redactConfigSecrets zeroes every secret-bearing field on a COPY of the
// gateway config, preserving non-secret structure so the endpoint stays useful
// for debugging (scoped-token roles/agents, header names, file paths).
//
// cfg must be a shallow copy, not the live currentConfig: the maps and slices
// below are replaced wholesale rather than mutated in place precisely because a
// shallow copy shares them with the live config.
func redactConfigSecrets(cfg *config.GatewayConfig) {
	// --- Bearer/API tokens -------------------------------------------------
	cfg.AuthToken = redactSecret(cfg.AuthToken)
	cfg.AntigravityToken = redactSecret(cfg.AntigravityToken)
	cfg.LLMAPIKey = redactSecret(cfg.LLMAPIKey)
	cfg.TrustedProxySecret = redactSecret(cfg.TrustedProxySecret)
	cfg.ClusterSecret = redactSecret(cfg.ClusterSecret)

	// The KEYS of this map are the secret tokens, so it cannot be redacted in
	// place — it is dropped entirely. handleApiConfig surfaces a non-secret
	// tokens_count separately.
	cfg.Tokens = nil

	// ScopedTokens: the Token is secret, but the role/agents/tags/tools are
	// exactly what an operator needs to see to debug an authz decision. Keep
	// the shape, redact the credential.
	if cfg.ScopedTokens != nil {
		scrubbed := make([]config.TokenScope, len(cfg.ScopedTokens))
		copy(scrubbed, cfg.ScopedTokens)
		for i := range scrubbed {
			scrubbed[i].Token = redactSecret(scrubbed[i].Token)
		}
		cfg.ScopedTokens = scrubbed
	}

	// OTLPHeaders values commonly carry a hosted backend's auth token (the
	// field is documented for exactly that). Header NAMES are not secret and
	// are kept, so an operator can still see that auth is configured.
	if cfg.OTLPHeaders != nil {
		scrubbed := make(map[string]string, len(cfg.OTLPHeaders))
		for name, value := range cfg.OTLPHeaders {
			scrubbed[name] = redactSecret(value)
		}
		cfg.OTLPHeaders = scrubbed
	}

	// --- Key material ------------------------------------------------------
	// The private key path itself is not a secret value, but it points at one
	// and leaking layout helps an attacker; kept redacted as before.
	cfg.TLSKeyPath = redactSecret(cfg.TLSKeyPath)
}

// isPlaceholder reports whether an incoming config value carries no real
// secret: either absent, or the placeholder a client got back from a redacted
// GET.
func isPlaceholder(s string) bool {
	return s == "" || s == redactedPlaceholder
}

// preserveRedactedSecrets is the other half of redaction, and is NOT optional.
//
// GET /api/config and POST /api/config are a round trip: the web portal builds
// its POST body as `{...currentConfigData, <edited fields>}` — i.e. it spreads
// the REDACTED GET response straight back — and the POST handler writes the
// whole decoded struct to the config file. Without this merge:
//
//   - redacting to "" makes saving settings from the portal WIPE every secret
//     (that is a pre-existing bug: auth_token, tokens and tls_key_path are
//     already destroyed on save today), and
//   - redacting to a placeholder writes the literal "[redacted]" to disk,
//     which would make the admin bearer token the publicly-known string
//     "[redacted]" — strictly worse than the leak this all started from.
//
// So: a secret that arrives empty or as the placeholder means "unchanged" and
// is restored from live. Any other value is a real edit and is honored, which
// keeps the portal's antigravity-token field working.
func preserveRedactedSecrets(incoming, live *config.GatewayConfig) {
	if live == nil {
		return
	}

	if isPlaceholder(incoming.AuthToken) {
		incoming.AuthToken = live.AuthToken
	}
	if isPlaceholder(incoming.AntigravityToken) {
		incoming.AntigravityToken = live.AntigravityToken
	}
	if isPlaceholder(incoming.LLMAPIKey) {
		incoming.LLMAPIKey = live.LLMAPIKey
	}
	if isPlaceholder(incoming.TrustedProxySecret) {
		incoming.TrustedProxySecret = live.TrustedProxySecret
	}
	if isPlaceholder(incoming.ClusterSecret) {
		incoming.ClusterSecret = live.ClusterSecret
	}
	if isPlaceholder(incoming.TLSKeyPath) {
		incoming.TLSKeyPath = live.TLSKeyPath
	}

	// Tokens is dropped entirely by redaction (its keys are the secrets), so a
	// round-tripped POST always arrives nil and must not clear the live map.
	if incoming.Tokens == nil {
		incoming.Tokens = live.Tokens
	}

	// ScopedTokens come back with each Token redacted but role/agents/tags
	// intact, in the order GET returned them — restore by position. A caller
	// adding entries beyond the live set simply has no live counterpart, and
	// its explicit values stand.
	for i := range incoming.ScopedTokens {
		if isPlaceholder(incoming.ScopedTokens[i].Token) && i < len(live.ScopedTokens) {
			incoming.ScopedTokens[i].Token = live.ScopedTokens[i].Token
		}
	}

	// OTLP header names survive redaction, so restore values by name.
	for name, value := range incoming.OTLPHeaders {
		if isPlaceholder(value) {
			if liveValue, ok := live.OTLPHeaders[name]; ok {
				incoming.OTLPHeaders[name] = liveValue
			}
		}
	}
}
