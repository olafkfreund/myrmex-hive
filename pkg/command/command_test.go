package command

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// This is the agent's security boundary — the code that decides whether a
// command runs on a target machine at all, and the only thing standing between
// a compromised gateway and `rm -rf /` on a customer's fleet. It had zero tests.
//
// Success cases use real coreutils binaries (true/false/echo/printf) so the
// LookPath resolution step actually resolves; rejection cases can use any name,
// since they fail before execution.

func TestValidateCommand(t *testing.T) {
	list := []config.AllowedCommand{
		{Name: "true", ArgsRegex: "^$"},                         // no args permitted
		{Name: "echo", ArgsRegex: "^-n$"},                       // exactly "-n"
		{Name: "printf", ArgsRegex: "^(status|restart) nginx$"}, // anchored alternation
		{Name: "false", ArgsRegex: ""},                          // empty regex => zero args only
		{Name: "badregex", ArgsRegex: "([unclosed"},             // invalid pattern
	}

	tests := []struct {
		name        string
		cmd         string
		args        []string
		wantErr     bool
		errContains string
	}{
		{"allowlisted, no args", "true", nil, false, ""},
		{"NOT in allowlist is rejected", "rm", []string{"-rf", "/"}, true, "not in the approved allowlist"},
		{"arg matches anchored regex", "echo", []string{"-n"}, false, ""},
		{"arg fails regex", "echo", []string{"-e"}, true, "do not match"},
		{"extra arg fails anchored regex", "echo", []string{"-n", "/etc/passwd"}, true, "do not match"},
		{"multi-arg matches", "printf", []string{"restart", "nginx"}, false, ""},
		{"multi-arg wrong target rejected", "printf", []string{"restart", "sshd"}, true, "do not match"},
		{"multi-arg wrong action rejected", "printf", []string{"stop", "nginx"}, true, "do not match"},
		{"empty regex rejects any args", "false", []string{"x"}, true, "does not allow arguments"},
		{"empty regex allows zero args", "false", nil, false, ""},
		{"invalid regex in config is rejected", "badregex", nil, true, "invalid regex"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, err := validateCommand(tc.cmd, tc.args, list)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (resolved path %q)", path)
				}
				if tc.errContains != "" && !strings.Contains(err.Error(), tc.errContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !strings.HasPrefix(path, "/") {
				t.Errorf("resolved path %q is not absolute — PATH-substitution hardening failed", path)
			}
		})
	}
}

// A bare command name must resolve to an absolute path (LookPath), so a
// PATH-planted binary of the same name cannot be silently substituted.
func TestValidateCommandResolvesToAbsolutePath(t *testing.T) {
	list := []config.AllowedCommand{{Name: "echo", ArgsRegex: "^$"}}
	path, err := validateCommand("echo", nil, list)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(path, "/") {
		t.Errorf("path %q is not absolute", path)
	}
}

// An already-absolute command name is used verbatim — no LookPath, no
// substitution surface.
func TestValidateCommandKeepsAbsolutePath(t *testing.T) {
	abs, err := exec.LookPath("true")
	if err != nil {
		t.Skipf("no 'true' binary on PATH: %v", err)
	}
	list := []config.AllowedCommand{{Name: abs, ArgsRegex: "^$"}}
	got, err := validateCommand(abs, nil, list)
	if err != nil {
		t.Fatal(err)
	}
	if got != abs {
		t.Errorf("absolute path was rewritten: got %q, want %q", got, abs)
	}
}

// An unresolvable command name fails closed rather than running something
// unexpected.
func TestValidateCommandUnresolvableFailsClosed(t *testing.T) {
	list := []config.AllowedCommand{{Name: "definitely-not-a-real-binary-xyz", ArgsRegex: "^$"}}
	if _, err := validateCommand("definitely-not-a-real-binary-xyz", nil, list); err == nil {
		t.Fatal("an unresolvable command was accepted")
	}
}

// THE crown-jewel property: commands run via os/exec directly, never a shell.
// Shell metacharacters in arguments must reach the process as literal text —
// no expansion, no command substitution, no statement splitting.
func TestExecuteCommandDoesNotInvokeShell(t *testing.T) {
	list := []config.AllowedCommand{{Name: "echo", ArgsRegex: ".*"}}

	// $(whoami) would expand to a username under any shell.
	out, err := ExecuteCommand("echo", []string{"$(whoami)"}, list)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "$(whoami)" {
		t.Errorf("command substitution occurred: echo output %q, want the literal $(whoami)", strings.TrimSpace(out))
	}

	// A ';' would split into a second command under a shell; here it is just an
	// argument to echo.
	out, err = ExecuteCommand("echo", []string{"a", ";", "whoami"}, list)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "a ; whoami" {
		t.Errorf("statement splitting occurred: echo output %q, want the literal 'a ; whoami'", strings.TrimSpace(out))
	}
}

// Validation happens BEFORE execution: a disallowed command returns the
// allowlist error, not an exec error, so it never ran.
func TestExecuteCommandRejectsBeforeRunning(t *testing.T) {
	list := []config.AllowedCommand{{Name: "true", ArgsRegex: "^$"}}
	_, err := ExecuteCommand("rm", []string{"-rf", "/"}, list)
	if err == nil {
		t.Fatal("a non-allowlisted command was not rejected")
	}
	if !strings.Contains(err.Error(), "not in the approved allowlist") {
		t.Errorf("expected an allowlist rejection (proving it never executed), got: %v", err)
	}
}

func TestExecuteCommandReturnsOutputAndErrors(t *testing.T) {
	// A command that exits non-zero surfaces as an error.
	list := []config.AllowedCommand{{Name: "false", ArgsRegex: "^$"}}
	if _, err := ExecuteCommand("false", nil, list); err == nil {
		t.Error("a command exiting non-zero should return an error")
	}

	// A command that exits zero returns its output, no error.
	list = []config.AllowedCommand{{Name: "echo", ArgsRegex: "^hello$"}}
	out, err := ExecuteCommand("echo", []string{"hello"}, list)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "hello" {
		t.Errorf("output = %q, want hello", strings.TrimSpace(out))
	}
}

// DryRun validates identically but MUST NOT execute. Proof: `false` would exit
// non-zero if run (ExecuteCommand errors on it), but DryRun returns no error.
func TestDryRunValidatesWithoutExecuting(t *testing.T) {
	list := []config.AllowedCommand{{Name: "false", ArgsRegex: "^$"}}

	desc, err := DryRun("false", nil, list)
	if err != nil {
		t.Fatalf("DryRun errored on a valid command — did it execute? %v", err)
	}
	if !strings.Contains(desc, "dry-run") || !strings.Contains(desc, "/false") {
		t.Errorf("dry-run description missing the resolved path: %q", desc)
	}

	// It still enforces the allowlist.
	if _, err := DryRun("rm", []string{"-rf", "/"}, list); err == nil {
		t.Error("DryRun accepted a non-allowlisted command")
	}
}

// The hazard from #151, now CLOSED: validateCommand anchors every ArgsRegex to
// the whole joined argument string, so an un-anchored pattern no longer
// substring-matches. An author who writes "nginx" meaning "only nginx" is
// protected even though they forgot ^...$.
func TestUnanchoredRegexIsAnchoredForYou(t *testing.T) {
	list := []config.AllowedCommand{{Name: "echo", ArgsRegex: "nginx"}}

	// Injected content around the intended match must NOT pass.
	if _, err := validateCommand("echo", []string{"evil", "nginx"}, list); err == nil {
		t.Fatal("un-anchored regex substring-matched injected args — #151 not fixed")
	}

	// The intended exact match still works.
	if _, err := validateCommand("echo", []string{"nginx"}, list); err != nil {
		t.Fatalf("the intended exact arg was rejected: %v", err)
	}
}

// Anchoring must not break an author who already anchored: ^(?:^-h$)$ still
// matches only "-h".
func TestAlreadyAnchoredRegexStillWorks(t *testing.T) {
	list := []config.AllowedCommand{{Name: "echo", ArgsRegex: "^-h$"}}
	if _, err := validateCommand("echo", []string{"-h"}, list); err != nil {
		t.Errorf("already-anchored pattern rejected its intended arg: %v", err)
	}
	if _, err := validateCommand("echo", []string{"-h", "extra"}, list); err == nil {
		t.Error("already-anchored pattern accepted extra args")
	}
}
