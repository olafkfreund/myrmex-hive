// Package audit re-verifies a gateway audit log: each entry's SSH signature
// over its own fields, and the PrevSig -> Signature chain linking it to the
// entry before it.
//
// This lived in cmd/myrmex (package main) and was therefore both untestable and
// unreachable from the gateway. The portal's audit viewer (#111) needs exactly
// the same verification, and a second implementation would be worse than none:
// the CLI and the portal could disagree about whether a log is tampered, and an
// operator would have no way to know which to believe.
//
// Verify takes an io.Reader rather than a path so the logic is testable without
// touching the filesystem — the coupling that left it with no tests at all.
package audit

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Entry mirrors the gateway's AuditEntry JSON shape (cmd/gateway/main.go).
type Entry struct {
	Timestamp string `json:"timestamp"`
	TokenID   string `json:"token_id"`
	Role      string `json:"role"`
	Action    string `json:"action"`
	AgentID   string `json:"agent_id,omitempty"`
	Command   string `json:"command,omitempty"`
	Status    string `json:"status"`
	Details   string `json:"details"`
	PrevSig   string `json:"prev_sig,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// LineResult is the verification outcome for a single audit entry.
type LineResult struct {
	Line       int    `json:"line"`
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	SigValid   bool   `json:"signature_valid"`
	ChainValid bool   `json:"chain_valid"`
	Error      string `json:"error,omitempty"`
	// Entry is the parsed entry, for callers that render the log rather than
	// just report on it (the portal's audit viewer, #111). nil when the line
	// could not be parsed. Additive: the CLI's existing output is unchanged.
	Entry *Entry `json:"entry,omitempty"`
}

// Result is the outcome of one full pass over an audit log.
type Result struct {
	Results       []LineResult
	Total         int
	Valid         int
	SigFailures   int
	ChainFailures int
	// FirstBadLine is the 1-based line number of the first entry with a
	// signature or chain failure, or 0 if every entry verified cleanly.
	FirstBadLine int
	// FirstBadReason is the LineResult.Error text for FirstBadLine.
	FirstBadReason string
}

// Tampered reports whether any entry failed signature or chain verification.
func (r Result) Tampered() bool {
	return r.SigFailures > 0 || r.ChainFailures > 0
}

// SignedPayload is the exact byte sequence the gateway signs for an entry.
// Exported so the signing side and the verifying side cannot drift: if this
// order changes, every historical signature becomes unverifiable.
func SignedPayload(e Entry) string {
	return strings.Join([]string{
		e.Timestamp, e.TokenID, e.Role, e.Action,
		e.AgentID, e.Command, e.Status, e.Details, e.PrevSig,
	}, "|")
}

// VerifyFile reads a host public key and an audit log from disk and verifies
// it. A returned error means the log or key could not be read/parsed, which is
// distinct from tamper being found — that is reported in Result.
func VerifyFile(logPath, hostKeyPath string) (Result, error) {
	var out Result

	keyBytes, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return out, fmt.Errorf("Failed to read host key %q: %v", hostKeyPath, err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		return out, fmt.Errorf("Failed to parse host public key %q: %v", hostKeyPath, err)
	}

	f, err := os.Open(logPath)
	if err != nil {
		return out, fmt.Errorf("Failed to open audit log %q: %v", logPath, err)
	}
	defer f.Close()

	out, err = Verify(f, pub)
	if err != nil {
		return out, fmt.Errorf("Failed to read audit log %q: %v", logPath, err)
	}
	return out, nil
}

// Verify checks every entry read from r against pub. The returned error is
// only for read failures; tamper is reported in Result.
func Verify(r io.Reader, pub ssh.PublicKey) (Result, error) {
	var out Result

	var prevSig string
	lineNum := 0

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out.Total++

		res := LineResult{Line: lineNum}

		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			res.Error = fmt.Sprintf("invalid JSON: %v", err)
			out.SigFailures++
			out.ChainFailures++
			if out.FirstBadLine == 0 {
				out.FirstBadLine = lineNum
				out.FirstBadReason = res.Error
			}
			out.Results = append(out.Results, res)
			// Leave prevSig untouched: nothing derived from this line can be
			// trusted, but later entries may still chain from the last entry
			// that did parse.
			continue
		}

		res.Timestamp = entry.Timestamp
		res.Action = entry.Action
		parsed := entry
		res.Entry = &parsed

		if entry.PrevSig == prevSig {
			res.ChainValid = true
		} else {
			out.ChainFailures++
			res.Error = fmt.Sprintf("chain break: prev_sig %q does not match previous entry's signature %q", entry.PrevSig, prevSig)
		}

		payload := SignedPayload(entry)

		blob, err := hex.DecodeString(entry.Signature)
		if err != nil {
			out.SigFailures++
			if res.Error != "" {
				res.Error += "; "
			}
			res.Error += fmt.Sprintf("invalid signature encoding: %v", err)
		} else {
			sig := &ssh.Signature{Format: pub.Type(), Blob: blob}
			if err := pub.Verify([]byte(payload), sig); err != nil {
				out.SigFailures++
				if res.Error != "" {
					res.Error += "; "
				}
				res.Error += fmt.Sprintf("signature verification failed: %v", err)
			} else {
				res.SigValid = true
			}
		}

		if (!res.SigValid || !res.ChainValid) && out.FirstBadLine == 0 {
			out.FirstBadLine = lineNum
			out.FirstBadReason = res.Error
		}

		out.Results = append(out.Results, res)
		prevSig = entry.Signature
	}

	if err := scanner.Err(); err != nil {
		return out, err
	}

	for _, r := range out.Results {
		if r.SigValid && r.ChainValid {
			out.Valid++
		}
	}

	return out, nil
}
