package main

import (
	"context"
	"testing"
)

// contextKeyToken is overloaded: a bearer credential for static tokens, an
// identity for every SSO path. anonymizeToken is a redactor for CREDENTIALS —
// applied to an identity it destroys what the audit log exists to record (#143).
func TestAuditPrincipal(t *testing.T) {
	tests := []struct {
		name       string
		principal  string
		isIdentity bool
		want       string
	}{
		{"OIDC subject verbatim", "alice@example.com", true, "alice@example.com"},
		{"mTLS CN verbatim", "myrmex-operator-station", true, "myrmex-operator-station"},
		{"proxy identity verbatim", "bob@corp.example", true, "bob@corp.example"},
		// A bearer in the audit log would be a credential leak into a file
		// operators read, paste into issues, and ship to a SIEM.
		{"static bearer is redacted", "SUPER-SECRET-ADMIN-TOKEN", false, "SUPE...OKEN"},
		{"short bearer is redacted", "abc", false, "..."},
		{"no principal", "", false, "none"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), contextKeyToken, tc.principal)
			ctx = context.WithValue(ctx, contextKeyIdentity, tc.isIdentity)
			if got := auditPrincipal(ctx); got != tc.want {
				t.Errorf("auditPrincipal() = %q, want %q", got, tc.want)
			}
		})
	}
}

// The bug that motivated #143: anonymizeToken keeps 4 chars either side, so
// distinct identities sharing a prefix and suffix collapse to the same string.
// Company emails do this constantly (first.last@corp.com).
func TestAuditPrincipalIdentitiesDoNotCollide(t *testing.T) {
	a, b := "alice@example.com", "alicia@example.com"

	if anonymizeToken(a) != anonymizeToken(b) {
		t.Fatalf("premise broken: these were supposed to collide (%q vs %q)", anonymizeToken(a), anonymizeToken(b))
	}

	ctxA := context.WithValue(context.WithValue(context.Background(), contextKeyToken, a), contextKeyIdentity, true)
	ctxB := context.WithValue(context.WithValue(context.Background(), contextKeyToken, b), contextKeyIdentity, true)

	gotA, gotB := auditPrincipal(ctxA), auditPrincipal(ctxB)
	if gotA == gotB {
		t.Errorf("two different people both audit as %q — accountability is gone", gotA)
	}
	if gotA != a || gotB != b {
		t.Errorf("identities mangled: %q, %q", gotA, gotB)
	}
}

// Absent the marker (any caller that never set it), fail SAFE: treat the value
// as a credential and redact it. Leaking a bearer is worse than a vague entry.
func TestAuditPrincipalDefaultsToRedacting(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextKeyToken, "SUPER-SECRET-ADMIN-TOKEN")
	if got := auditPrincipal(ctx); got != "SUPE...OKEN" {
		t.Errorf("with no identity marker the value must be redacted, got %q", got)
	}
}
