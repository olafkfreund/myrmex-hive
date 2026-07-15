package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// signer mirrors what the gateway does when it writes an entry (signAuditData
// in cmd/gateway/main.go): sign SignedPayload with the host key, hex-encode.
type signer struct {
	ssh.Signer
	pub ssh.PublicKey
}

func newSigner(t *testing.T) signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer{Signer: s, pub: s.PublicKey()}
}

// sign returns the entry with PrevSig set and a valid Signature, exactly as the
// gateway would have written it.
func (s signer) sign(t *testing.T, e Entry, prevSig string) Entry {
	t.Helper()
	e.PrevSig = prevSig
	sig, err := s.Sign(rand.Reader, []byte(SignedPayload(e)))
	if err != nil {
		t.Fatal(err)
	}
	e.Signature = hex.EncodeToString(sig.Blob)
	return e
}

// buildLog writes a correctly signed, correctly chained log.
func buildLog(t *testing.T, s signer, entries ...Entry) (string, []Entry) {
	t.Helper()
	var lines []string
	var signed []Entry
	prev := ""
	for _, e := range entries {
		se := s.sign(t, e, prev)
		b, err := json.Marshal(se)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, string(b))
		signed = append(signed, se)
		prev = se.Signature
	}
	return strings.Join(lines, "\n") + "\n", signed
}

func sampleEntries() []Entry {
	return []Entry{
		{Timestamp: "2026-07-15T10:00:00Z", TokenID: "tok1", Role: "admin", Action: "api_call", AgentID: "web-1", Command: "uptime", Status: "success", Details: "ok"},
		{Timestamp: "2026-07-15T10:00:01Z", TokenID: "tok1", Role: "admin", Action: "api_call", AgentID: "db-1", Command: "df -h", Status: "success", Details: "ok"},
		{Timestamp: "2026-07-15T10:00:02Z", TokenID: "tok2", Role: "operator", Action: "alert", AgentID: "web-1", Command: "cpu", Status: "failure", Details: "value=95"},
	}
}

func TestVerifyCleanLog(t *testing.T) {
	s := newSigner(t)
	log, _ := buildLog(t, s, sampleEntries()...)

	got, err := Verify(strings.NewReader(log), s.pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 3 || got.Valid != 3 {
		t.Errorf("total=%d valid=%d, want 3/3", got.Total, got.Valid)
	}
	if got.Tampered() {
		t.Errorf("clean log reported as tampered: %+v", got)
	}
	if got.FirstBadLine != 0 {
		t.Errorf("FirstBadLine=%d, want 0", got.FirstBadLine)
	}
}

// The whole point of the signed audit log: editing an entry after the fact must
// be detected.
func TestVerifyDetectsEditedEntry(t *testing.T) {
	s := newSigner(t)
	log, signed := buildLog(t, s, sampleEntries()...)

	// Tamper: rewrite the command on entry 2, keeping its signature.
	tampered := signed[1]
	tampered.Command = "rm -rf /"
	b, _ := json.Marshal(tampered)
	lines := strings.Split(strings.TrimSpace(log), "\n")
	lines[1] = string(b)

	got, err := Verify(strings.NewReader(strings.Join(lines, "\n")), s.pub)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Tampered() {
		t.Fatal("an edited entry was NOT detected — the audit log is worthless if this passes")
	}
	if got.SigFailures != 1 {
		t.Errorf("SigFailures=%d, want 1", got.SigFailures)
	}
	if got.FirstBadLine != 2 {
		t.Errorf("FirstBadLine=%d, want 2", got.FirstBadLine)
	}
	if !strings.Contains(got.Results[1].Error, "signature verification failed") {
		t.Errorf("unexpected error text: %q", got.Results[1].Error)
	}
}

// Deleting an entry breaks the PrevSig chain even though every remaining
// signature is individually valid — this is what the chain is FOR.
func TestVerifyDetectsDeletedEntry(t *testing.T) {
	s := newSigner(t)
	log, _ := buildLog(t, s, sampleEntries()...)

	lines := strings.Split(strings.TrimSpace(log), "\n")
	// Drop the middle entry.
	spliced := []string{lines[0], lines[2]}

	got, err := Verify(strings.NewReader(strings.Join(spliced, "\n")), s.pub)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Tampered() {
		t.Fatal("a deleted entry was NOT detected — every signature is still valid, only the chain reveals it")
	}
	if got.ChainFailures != 1 {
		t.Errorf("ChainFailures=%d, want 1", got.ChainFailures)
	}
	if !strings.Contains(got.Results[1].Error, "chain break") {
		t.Errorf("unexpected error text: %q", got.Results[1].Error)
	}
	// The surviving entries' own signatures are untouched.
	if !got.Results[1].SigValid {
		t.Error("the entry's own signature should still be valid; only its chain link broke")
	}
}

// An entry signed by a different key must not verify — otherwise anyone could
// forge entries with their own key.
func TestVerifyRejectsForeignKey(t *testing.T) {
	real := newSigner(t)
	attacker := newSigner(t)

	log, _ := buildLog(t, attacker, sampleEntries()...)

	got, err := Verify(strings.NewReader(log), real.pub)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Tampered() {
		t.Fatal("entries signed by a foreign key verified against the real host key")
	}
	if got.Valid != 0 {
		t.Errorf("valid=%d, want 0", got.Valid)
	}
}

// A corrupt line must not derail the entries after it: prevSig is deliberately
// left untouched so later entries can still chain from the last good one.
func TestVerifyCorruptLineDoesNotBreakLaterChain(t *testing.T) {
	s := newSigner(t)
	entries := sampleEntries()
	log, _ := buildLog(t, s, entries...)
	lines := strings.Split(strings.TrimSpace(log), "\n")

	// Insert garbage between entry 1 and 2. Entry 2 still chains to entry 1.
	spliced := []string{lines[0], "{not json", lines[1], lines[2]}

	got, err := Verify(strings.NewReader(strings.Join(spliced, "\n")), s.pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.FirstBadLine != 2 {
		t.Errorf("FirstBadLine=%d, want 2 (the garbage line)", got.FirstBadLine)
	}
	if !strings.Contains(got.Results[1].Error, "invalid JSON") {
		t.Errorf("unexpected error: %q", got.Results[1].Error)
	}
	// Entries 3 and 4 (lines 3,4) must still verify — the garbage did not
	// poison prevSig.
	for _, i := range []int{2, 3} {
		if !got.Results[i].SigValid || !got.Results[i].ChainValid {
			t.Errorf("line %d should still verify after a corrupt line: %+v", got.Results[i].Line, got.Results[i])
		}
	}
}

func TestVerifyEmptyLog(t *testing.T) {
	s := newSigner(t)
	got, err := Verify(strings.NewReader(""), s.pub)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total != 0 || got.Tampered() {
		t.Errorf("empty log: %+v", got)
	}
}

// SignedPayload's field order is a wire contract: changing it silently
// invalidates every signature ever written.
func TestSignedPayloadOrderIsStable(t *testing.T) {
	got := SignedPayload(Entry{
		Timestamp: "T", TokenID: "TOK", Role: "R", Action: "A",
		AgentID: "AG", Command: "C", Status: "S", Details: "D", PrevSig: "P",
	})
	want := "T|TOK|R|A|AG|C|S|D|P"
	if got != want {
		t.Errorf("payload order changed — every historical signature is now unverifiable.\ngot:  %q\nwant: %q", got, want)
	}
}
