package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// fakeIdP is a real OIDC provider: it serves discovery + JWKS and mints signed
// tokens. Tests run go-oidc's actual verification path rather than a stub —
// stubbing the verifier would test nothing that matters.
type fakeIdP struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	signer jose.Signer
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	idp := &fakeIdP{key: key, signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer":                                idp.server.URL,
			"jwks_uri":                              idp.server.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: key.Public(), KeyID: "test-key", Algorithm: "RS256", Use: "sig"},
		}})
	})
	idp.server = httptest.NewServer(mux)
	t.Cleanup(idp.server.Close)
	return idp
}

// mint issues a signed JWT with the given claims.
func (i *fakeIdP) mint(t *testing.T, aud string, groups interface{}, exp time.Time) string {
	t.Helper()
	claims := map[string]interface{}{
		"iss":    i.server.URL,
		"sub":    "user@example.com",
		"aud":    aud,
		"exp":    exp.Unix(),
		"iat":    time.Now().Unix(),
		"groups": groups,
	}
	tok, err := jwt.Signed(i.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func oidcConfig(issuer string) *config.GatewayConfig {
	return &config.GatewayConfig{
		OIDCIssuer:   issuer,
		OIDCAudience: "myrmex",
		OIDCRoleMap: map[string]string{
			"myrmex-admins": "admin",
			"sre":           "operator",
			"viewers":       "read-only",
		},
	}
}

// resetOIDC clears the cached verifier so each test discovers its own IdP.
func resetOIDC(t *testing.T) {
	t.Helper()
	oidcMu.Lock()
	oidcVerifier = nil
	oidcBuiltFor = ""
	oidcMu.Unlock()
	t.Cleanup(func() {
		oidcMu.Lock()
		oidcVerifier = nil
		oidcBuiltFor = ""
		oidcMu.Unlock()
	})
}

func TestAuthenticateOIDCValidToken(t *testing.T) {
	resetOIDC(t)
	idp := newFakeIdP(t)
	cfg := oidcConfig(idp.server.URL)

	tok := idp.mint(t, "myrmex", []string{"sre"}, time.Now().Add(time.Hour))
	role, subject, err := authenticateOIDC(context.Background(), cfg, tok)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if role != "operator" {
		t.Errorf("role = %q, want operator", role)
	}
	if subject != "user@example.com" {
		t.Errorf("subject = %q — the audit trail needs the sub, not a token fragment", subject)
	}
}

// The attack this whole feature exists to stop: a token signed by someone
// else's key must not authenticate.
func TestAuthenticateOIDCRejectsForeignSignature(t *testing.T) {
	resetOIDC(t)
	realIdP := newFakeIdP(t)
	attacker := newFakeIdP(t)
	cfg := oidcConfig(realIdP.server.URL)

	// Attacker mints a token claiming the real issuer, signed with THEIR key.
	claims := map[string]interface{}{
		"iss": realIdP.server.URL, "sub": "attacker", "aud": "myrmex",
		"exp": time.Now().Add(time.Hour).Unix(), "groups": []string{"myrmex-admins"},
	}
	tok, err := jwt.Signed(attacker.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	role, _, err := authenticateOIDC(context.Background(), cfg, tok)
	if err == nil {
		t.Fatal("a token signed by a foreign key was ACCEPTED — this is the whole point of JWKS validation")
	}
	if role != "" {
		t.Errorf("role = %q, want empty", role)
	}
}

func TestAuthenticateOIDCRejectsExpired(t *testing.T) {
	resetOIDC(t)
	idp := newFakeIdP(t)
	cfg := oidcConfig(idp.server.URL)

	tok := idp.mint(t, "myrmex", []string{"myrmex-admins"}, time.Now().Add(-time.Hour))
	if _, _, err := authenticateOIDC(context.Background(), cfg, tok); err == nil {
		t.Fatal("an expired token was accepted")
	}
}

// Without an audience check, any token the issuer minted for ANY application
// would authenticate here. Validate() requires oidc_audience for this reason.
func TestAuthenticateOIDCRejectsWrongAudience(t *testing.T) {
	resetOIDC(t)
	idp := newFakeIdP(t)
	cfg := oidcConfig(idp.server.URL)

	tok := idp.mint(t, "some-other-app", []string{"myrmex-admins"}, time.Now().Add(time.Hour))
	if _, _, err := authenticateOIDC(context.Background(), cfg, tok); err == nil {
		t.Fatal("a token for another audience was accepted — confused deputy")
	}
}

// A valid token whose groups map to nothing must be denied, not defaulted.
func TestAuthenticateOIDCUnmappedGroupIsDenied(t *testing.T) {
	resetOIDC(t)
	idp := newFakeIdP(t)
	cfg := oidcConfig(idp.server.URL)

	tok := idp.mint(t, "myrmex", []string{"some-unrelated-group"}, time.Now().Add(time.Hour))
	role, _, err := authenticateOIDC(context.Background(), cfg, tok)
	if err == nil {
		t.Fatal("a token mapping to no role was accepted — there must be no default role")
	}
	if role != "" {
		t.Errorf("role = %q, want empty", role)
	}
}

// Backward compatibility: a static token must not be touched by OIDC.
func TestAuthenticateOIDCIgnoresStaticTokens(t *testing.T) {
	resetOIDC(t)
	idp := newFakeIdP(t)
	cfg := oidcConfig(idp.server.URL)

	// Not a JWT -> not applicable -> caller falls through to the static path.
	role, _, err := authenticateOIDC(context.Background(), cfg, "plain-static-token")
	if err != nil {
		t.Errorf("a static token must not error through the OIDC path: %v", err)
	}
	if role != "" {
		t.Errorf("role = %q, want empty (fall through)", role)
	}
}

// Opt-in: with no issuer configured, nothing happens — not even for a JWT.
func TestAuthenticateOIDCDisabled(t *testing.T) {
	resetOIDC(t)
	idp := newFakeIdP(t)
	tok := idp.mint(t, "myrmex", []string{"myrmex-admins"}, time.Now().Add(time.Hour))

	role, _, err := authenticateOIDC(context.Background(), &config.GatewayConfig{}, tok)
	if err != nil || role != "" {
		t.Errorf("OIDC disabled should be inert: role=%q err=%v", role, err)
	}
}

// Group membership is additive, so the most privileged mapped role wins.
func TestMapClaimsToRoleTakesMostPrivileged(t *testing.T) {
	roleMap := map[string]string{"viewers": "read-only", "sre": "operator", "myrmex-admins": "admin"}
	tests := []struct {
		name   string
		groups interface{}
		want   string
	}{
		{"single", []interface{}{"sre"}, "operator"},
		{"admin wins over operator", []interface{}{"sre", "myrmex-admins"}, "admin"},
		{"operator wins over read-only", []interface{}{"viewers", "sre"}, "operator"},
		{"unmapped only", []interface{}{"nope"}, ""},
		{"claim as a bare string", "sre", "operator"},
		{"missing claim", nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]interface{}{}
			if tc.groups != nil {
				claims["groups"] = tc.groups
			}
			if got := mapClaimsToRole(claims, "groups", roleMap); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLooksLikeJWT(t *testing.T) {
	for tok, want := range map[string]bool{
		"a.b.c":                 true,
		"plain-token":           false,
		"two.parts":             false,
		"a.b.c.d":               false,
		".b.c":                  false,
		"a.b.":                  false,
		strings.Repeat("x", 40): false,
	} {
		if got := looksLikeJWT(tok); got != want {
			t.Errorf("looksLikeJWT(%q) = %v, want %v", tok, got, want)
		}
	}
}
