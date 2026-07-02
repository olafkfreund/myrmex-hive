package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreSaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "state.json"))

	want := &Snapshot{
		SavedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
		Agents: []AgentRecord{
			{
				ID:              "agent-1",
				IP:              "10.0.0.1",
				OSVersion:       "Ubuntu 22.04",
				RunningServices: []string{"sshd", "nginx"},
				OpenPorts:       []string{"22", "80"},
				LastSeen:        time.Date(2024, 1, 2, 3, 0, 0, 0, time.UTC),
				LatestMetrics:   json.RawMessage(`{"cpu_usage_percent":12.5}`),
			},
			{
				ID:        "agent-2",
				IP:        "10.0.0.2",
				OSVersion: "Debian 12",
			},
		},
		AuditIndex: AuditIndex{
			TotalEntries:  7,
			ByAction:      map[string]int{"api_call": 5, "config_update": 2},
			LastSignature: "deadbeef",
		},
	}

	if err := s.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal got: %v", err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("marshal want: %v", err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("round trip mismatch:\n got  = %s\n want = %s", gotJSON, wantJSON)
	}
}

func TestStoreLoadMissingFileReturnsEmptySnapshot(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "does-not-exist.json"))

	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load() error = %v, want nil", err)
	}
	if got == nil {
		t.Fatal("Load() returned nil snapshot, want empty non-nil snapshot")
	}
	if len(got.Agents) != 0 {
		t.Errorf("Load() Agents = %v, want empty", got.Agents)
	}
	if got.AuditIndex.TotalEntries != 0 || len(got.AuditIndex.ByAction) != 0 {
		t.Errorf("Load() AuditIndex = %+v, want zero value", got.AuditIndex)
	}
}

func TestStoreSaveOverwritesPreviousSnapshot(t *testing.T) {
	dir := t.TempDir()
	s := New(filepath.Join(dir, "state.json"))

	first := &Snapshot{AuditIndex: AuditIndex{TotalEntries: 1}}
	second := &Snapshot{AuditIndex: AuditIndex{TotalEntries: 2}}

	if err := s.Save(first); err != nil {
		t.Fatalf("Save(first) error = %v", err)
	}
	if err := s.Save(second); err != nil {
		t.Fatalf("Save(second) error = %v", err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.AuditIndex.TotalEntries != 2 {
		t.Errorf("Load().AuditIndex.TotalEntries = %d, want 2", got.AuditIndex.TotalEntries)
	}
}

func TestStoreLoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not valid json"), 0600); err != nil {
		t.Fatalf("os.WriteFile: %v", err)
	}

	s := New(path)
	if _, err := s.Load(); err == nil {
		t.Error("Load() error = nil, want error for invalid JSON")
	}
}
