package main

// GET /api/audit — the signed audit log with per-entry verification status
// (issue #111).
//
// Read-only and admin-only: entries carry token IDs, the commands operators
// ran, and agent IDs. That is the fleet's activity history, and it is not
// operator- or read-only-role material.
//
// Verification reuses pkg/audit — the same code `myrmex audit verify` runs. A
// second implementation here would be worse than none: the portal and the CLI
// could disagree about whether a log was tampered with, and an operator would
// have no way to tell which one to believe.

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/olafkfreund/myrmex-hive/pkg/audit"
)

// auditAPIEntry is one row in the viewer: the entry's fields plus what
// verification concluded about it.
type auditAPIEntry struct {
	Line        int    `json:"line"`
	Timestamp   string `json:"timestamp"`
	TokenID     string `json:"token_id"`
	Role        string `json:"role"`
	Action      string `json:"action"`
	AgentID     string `json:"agent_id,omitempty"`
	Command     string `json:"command,omitempty"`
	Status      string `json:"status"`
	Details     string `json:"details,omitempty"`
	SigValid    bool   `json:"signature_valid"`
	ChainValid  bool   `json:"chain_valid"`
	VerifyError string `json:"verify_error,omitempty"`
}

// auditAPIResponse reports on the WHOLE log, and returns a filtered slice of it.
//
// The summary deliberately covers every entry, not just the filtered ones: the
// PrevSig chain only means anything over the complete log in order, so a
// "3 of 3 valid" computed from a filter would be a lie about the file.
type auditAPIResponse struct {
	Entries []auditAPIEntry `json:"entries"`
	Summary struct {
		Total          int    `json:"total"`
		Valid          int    `json:"valid"`
		SigFailures    int    `json:"signature_failures"`
		ChainFailures  int    `json:"chain_failures"`
		Tampered       bool   `json:"tampered"`
		FirstBadLine   int    `json:"first_bad_line,omitempty"`
		FirstBadReason string `json:"first_bad_reason,omitempty"`
	} `json:"summary"`
	Filtered  int  `json:"filtered"`
	Truncated bool `json:"truncated"`
}

// auditFilter is the set of filters #111 asks for: actor, agent, action, time.
type auditFilter struct {
	actor  string
	agent  string
	action string
	since  string
	until  string
}

// matches reports whether an entry passes the filter. Substring, case-
// insensitive, because operators grep for a partial agent id or token prefix.
// Timestamps are RFC3339 so lexical comparison is chronological.
func (f auditFilter) matches(e audit.Entry) bool {
	if f.actor != "" && !strings.Contains(strings.ToLower(e.TokenID), f.actor) {
		return false
	}
	if f.agent != "" && !strings.Contains(strings.ToLower(e.AgentID), f.agent) {
		return false
	}
	if f.action != "" && !strings.Contains(strings.ToLower(e.Action), f.action) {
		return false
	}
	if f.since != "" && e.Timestamp < f.since {
		return false
	}
	if f.until != "" && e.Timestamp > f.until {
		return false
	}
	return true
}

func auditFilterFromQuery(r *http.Request) auditFilter {
	q := r.URL.Query()
	return auditFilter{
		actor:  strings.ToLower(strings.TrimSpace(q.Get("actor"))),
		agent:  strings.ToLower(strings.TrimSpace(q.Get("agent"))),
		action: strings.ToLower(strings.TrimSpace(q.Get("action"))),
		since:  strings.TrimSpace(q.Get("since")),
		until:  strings.TrimSpace(q.Get("until")),
	}
}

// auditAPILimit bounds the response. An audit log grows without bound and the
// portal renders every row, so an unbounded read would eventually hang the
// browser rather than the gateway.
const auditAPIDefaultLimit = 200

func handleApiAudit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	setCORS(w, r)
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	// Read-only by construction: no other method is served.
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	currentConfigMu.RLock()
	logPath := ""
	if currentConfig != nil {
		logPath = currentConfig.AuditLogPath
	}
	currentConfigMu.RUnlock()

	if logPath == "" {
		http.Error(w, "Audit logging is not enabled (set audit_log_path)", http.StatusNotFound)
		return
	}

	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Configured but nothing written yet: an empty log, not an error.
			json.NewEncoder(w).Encode(auditAPIResponse{Entries: []auditAPIEntry{}})
			return
		}
		http.Error(w, "Failed to read audit log", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	// Verify against the LIVE host key rather than re-reading it from disk:
	// this is the very key the gateway signs with, so the portal cannot end up
	// verifying against a different key than the one in use.
	if hostKeySigner == nil {
		http.Error(w, "Host key unavailable; cannot verify audit signatures", http.StatusInternalServerError)
		return
	}
	result, err := audit.Verify(f, hostKeySigner.PublicKey())
	if err != nil {
		http.Error(w, "Failed to read audit log", http.StatusInternalServerError)
		return
	}

	var resp auditAPIResponse
	resp.Summary.Total = result.Total
	resp.Summary.Valid = result.Valid
	resp.Summary.SigFailures = result.SigFailures
	resp.Summary.ChainFailures = result.ChainFailures
	resp.Summary.Tampered = result.Tampered()
	resp.Summary.FirstBadLine = result.FirstBadLine
	resp.Summary.FirstBadReason = result.FirstBadReason

	limit := auditAPIDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	filter := auditFilterFromQuery(r)
	entries := []auditAPIEntry{}

	// Newest first: an operator opening the viewer wants what just happened.
	for i := len(result.Results) - 1; i >= 0; i-- {
		res := result.Results[i]
		if res.Entry == nil {
			// A line that would not parse. Surface it rather than hiding it —
			// unparseable content in a signed log is itself a finding — but it
			// has no fields to filter on, so only show it unfiltered.
			if filter == (auditFilter{}) {
				entries = append(entries, auditAPIEntry{
					Line:        res.Line,
					SigValid:    false,
					ChainValid:  false,
					VerifyError: res.Error,
				})
			}
			continue
		}
		if !filter.matches(*res.Entry) {
			continue
		}
		if len(entries) >= limit {
			resp.Truncated = true
			break
		}
		e := res.Entry
		entries = append(entries, auditAPIEntry{
			Line:      res.Line,
			Timestamp: e.Timestamp,
			// Written by auditPrincipal (#143): an identity (OIDC sub, mTLS CN,
			// proxy identity) verbatim, a static bearer already redacted. Either
			// way the raw credential is never on disk, and re-anonymizing here
			// would destroy the identity — which is the point of recording it.
			TokenID:     e.TokenID,
			Role:        e.Role,
			Action:      e.Action,
			AgentID:     e.AgentID,
			Command:     e.Command,
			Status:      e.Status,
			Details:     e.Details,
			SigValid:    res.SigValid,
			ChainValid:  res.ChainValid,
			VerifyError: res.Error,
		})
	}

	resp.Entries = entries
	resp.Filtered = len(entries)
	json.NewEncoder(w).Encode(resp)
}
