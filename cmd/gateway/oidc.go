package main

// Native OIDC/JWKS bearer-token validation (issue #114).
//
// Uses coreos/go-oidc rather than hand-rolling JWT verification. This project's
// bar for a dependency is high (see CLAUDE.md) and the Prometheus exposition is
// hand-written for exactly that reason — but JWT validation is the opposite
// trade. "alg: none", RS256-vs-HS256 confusion, kid rotation, JWKS caching and
// clock skew are where reimplementing a spec buys CVEs rather than saving
// bytes. The cost is 3 modules / ~500K against a 20MB vendor tree.
//
// Opt-in and additive: with oidc_issuer unset nothing here runs, no discovery
// happens, and bearer tokens resolve exactly as before. A JWT that fails
// validation falls through to the static-token path, so existing deployments
// are untouched.

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// oidcVerifier caches the discovered provider's verifier. go-oidc handles JWKS
// fetching, caching and key rotation behind it.
//
// Built lazily rather than at startup on purpose: discovery is a network call
// to the IdP, and a gateway that refused to boot because the IdP was briefly
// unreachable would take static-token auth down with it. Lazy init retries on
// the next request instead.
var (
	oidcMu       sync.Mutex
	oidcVerifier *oidc.IDTokenVerifier
	oidcBuiltFor string // issuer|audience the cached verifier was built for
)

// rolePrecedence orders gateway roles from least to most privileged. A caller
// in several mapped groups gets the most privileged one, matching how group
// membership is normally additive.
var rolePrecedence = map[string]int{"read-only": 1, "operator": 2, "admin": 3}

// getOIDCVerifier returns a verifier for the configured issuer, discovering it
// on first use. Returns nil when OIDC is not configured.
func getOIDCVerifier(ctx context.Context, issuer, audience string) (*oidc.IDTokenVerifier, error) {
	if issuer == "" {
		return nil, nil
	}

	oidcMu.Lock()
	defer oidcMu.Unlock()

	// Rebuild if the config was reloaded to a different issuer/audience.
	key := issuer + "|" + audience
	if oidcVerifier != nil && oidcBuiltFor == key {
		return oidcVerifier, nil
	}

	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery for %q: %w", issuer, err)
	}
	// ClientID is the expected `aud`. Validate() guarantees it is non-empty
	// when the issuer is set — without it, any token this issuer minted for any
	// application would authenticate here.
	oidcVerifier = provider.Verifier(&oidc.Config{ClientID: audience})
	oidcBuiltFor = key
	log.Printf("OIDC enabled: issuer=%s audience=%s", issuer, audience)
	return oidcVerifier, nil
}

// looksLikeJWT is a cheap pre-filter so a static bearer token never triggers a
// discovery attempt or a verification error log. Three dot-separated segments
// is the JWS compact form; it says nothing about validity.
func looksLikeJWT(token string) bool {
	return strings.Count(token, ".") == 2 && !strings.HasPrefix(token, ".") && !strings.HasSuffix(token, ".")
}

// claimRoles pulls the caller's group/role values out of the configured claim.
// The claim is a string or an array of strings depending on the IdP, so both
// are accepted.
func claimRoles(claims map[string]interface{}, claimName string) []string {
	v, ok := claims[claimName]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case string:
		return []string{t}
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	}
	return nil
}

// mapClaimsToRole resolves the most privileged gateway role the caller's claim
// values map to. Returns "" when nothing matches — which denies, because
// requireAuth treats an empty role as unauthorized. There is deliberately no
// default role: a token from a valid issuer that maps to nothing is a caller we
// were never told about.
func mapClaimsToRole(claims map[string]interface{}, claimName string, roleMap map[string]string) string {
	if claimName == "" {
		claimName = "groups"
	}
	best := ""
	for _, value := range claimRoles(claims, claimName) {
		role, ok := roleMap[value]
		if !ok {
			continue
		}
		if rolePrecedence[role] > rolePrecedence[best] {
			best = role
		}
	}
	return best
}

// authenticateOIDC validates a bearer token as an OIDC JWT and maps its claims
// to a gateway role. It returns:
//   - ("", nil)  : not applicable — OIDC off, or the token is not a JWT. The
//     caller falls through to the static-token path.
//   - ("", err)  : the token IS a JWT but failed validation or mapped to no
//     role. The caller must NOT fall through to a role.
//   - (role, nil): validated.
//
// subject is the token's `sub`, returned so the audit trail records who acted
// rather than an anonymized token fragment.
func authenticateOIDC(ctx context.Context, cfg *config.GatewayConfig, token string) (role string, subject string, err error) {
	if cfg == nil || cfg.OIDCIssuer == "" || !looksLikeJWT(token) {
		return "", "", nil
	}

	verifier, err := getOIDCVerifier(ctx, cfg.OIDCIssuer, cfg.OIDCAudience)
	if err != nil {
		// Discovery failed (IdP down/misconfigured). Fail closed for JWTs
		// rather than falling through — a JWT is not a static token, and
		// treating an unverifiable one as "just not in the tokens map" would
		// be an oddly quiet way to lose authentication.
		return "", "", err
	}
	if verifier == nil {
		return "", "", nil
	}

	// Verify checks the signature against the JWKS, plus iss, aud and exp.
	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		return "", "", fmt.Errorf("oidc token rejected: %w", err)
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return "", "", fmt.Errorf("oidc claims unreadable: %w", err)
	}

	role = mapClaimsToRole(claims, cfg.OIDCRoleClaim, cfg.OIDCRoleMap)
	if role == "" {
		claimName := cfg.OIDCRoleClaim
		if claimName == "" {
			claimName = "groups"
		}
		return "", "", fmt.Errorf("oidc token for %q has no %s value in oidc_role_map", idToken.Subject, claimName)
	}
	return role, idToken.Subject, nil
}
