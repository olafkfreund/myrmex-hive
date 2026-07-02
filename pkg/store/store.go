// Package store provides durable, opt-in persistence of the Gateway's
// in-memory fleet inventory and audit-log index, so an operator sees the
// last-known fleet immediately after a Gateway restart instead of an empty
// list while agents reconnect (issues #44/#50). It is deliberately minimal:
// a single JSON snapshot file, written atomically. It provides no locking or
// coordination across multiple Gateway processes — true multi-gateway
// clustering is out of scope here (see #47/#56/#63).
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AgentRecord is a persisted snapshot of one agent's last-known inventory
// state, durable across gateway restarts. It mirrors the subset of
// cmd/gateway's AgentClient fields that are meaningful to show for an agent
// that isn't currently connected.
type AgentRecord struct {
	ID              string          `json:"id"`
	IP              string          `json:"ip,omitempty"`
	OSVersion       string          `json:"os_version,omitempty"`
	RunningServices []string        `json:"running_services,omitempty"`
	OpenPorts       []string        `json:"open_ports,omitempty"`
	LastSeen        time.Time       `json:"last_seen,omitempty"`
	LatestMetrics   json.RawMessage `json:"latest_metrics,omitempty"`
}

// AuditIndex is a compact, queryable summary of the signed audit log: total
// entry count, a per-action breakdown, and the chain-tip signature. Persisting
// this means a restart doesn't lose audit stats, even though the
// authoritative source of truth for the tamper-evident chain itself remains
// the audit log file on disk.
type AuditIndex struct {
	TotalEntries  int            `json:"total_entries"`
	ByAction      map[string]int `json:"by_action,omitempty"`
	LastSignature string         `json:"last_signature,omitempty"`
}

// Snapshot is the full persisted gateway state.
type Snapshot struct {
	SavedAt    time.Time     `json:"saved_at"`
	Agents     []AgentRecord `json:"agents,omitempty"`
	AuditIndex AuditIndex    `json:"audit_index"`
}

// Store persists a Snapshot to a single JSON file on disk. It is safe for
// concurrent use.
type Store struct {
	path string
	mu   sync.Mutex
}

// New returns a Store that persists to (and loads from) path.
func New(path string) *Store {
	return &Store{path: path}
}

// Path returns the file path this Store persists to.
func (s *Store) Path() string {
	return s.path
}

// Load reads and decodes the snapshot at Store's path. If the file does not
// exist yet (first run, or persistence just enabled), Load returns an empty,
// non-nil Snapshot and a nil error, so callers can treat "no prior state"
// the same as "load succeeded with nothing in it" without a special case.
func (s *Store) Load() (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Snapshot{}, nil
		}
		return nil, fmt.Errorf("store: reading state file %q: %w", s.path, err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("store: parsing state file %q: %w", s.path, err)
	}
	return &snap, nil
}

// Save atomically writes snap to Store's path: it writes to a temp file in
// the same directory then renames it into place, so a crash mid-write, or a
// concurrent Load, never observes a partially-written file. The temp (and
// therefore final) file is created with mode 0600 since fleet inventory
// (hostnames, IPs, running services, open ports) may be sensitive.
func (s *Store) Save(snap *Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("store: marshaling snapshot: %w", err)
	}

	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("store: creating state directory %q: %w", dir, err)
		}
	}

	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("store: creating temp state file: %w", err)
	}
	tmpPath := tmp.Name()
	// Best-effort cleanup; a no-op once the rename below succeeds.
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("store: writing temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store: closing temp state file: %w", err)
	}
	// os.CreateTemp already creates the file with mode 0600, but chmod
	// explicitly so that guarantee doesn't depend on that implementation
	// detail (and to override any restrictive umask making it more open).
	if err := os.Chmod(tmpPath, 0600); err != nil {
		return fmt.Errorf("store: chmod temp state file: %w", err)
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("store: renaming temp state file into place: %w", err)
	}
	return nil
}
