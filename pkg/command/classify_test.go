package command_test

// Contract test for the audit classifier (#174).
//
// ClassifyResult matches on substrings of error messages produced elsewhere in
// this package. That is only safe if a reworded message breaks the build, so
// these cases GENERATE the messages from the real code paths (DryRun /
// ExecuteCommand) and wrap them exactly as cmd/agent does, rather than
// hard-coding what the text is believed to say.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/olafkfreund/myrmex-hive/pkg/command"
	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// asAgentWouldWrap reproduces cmd/agent's composition of a failed tool result,
// so what gets classified here is byte-identical to what crosses the tunnel.
func asAgentWouldWrap(err error, output string) string {
	return fmt.Sprintf("%s %v\nOutput:\n%s", command.ResultFailurePrefix, err, output)
}

func TestClassifyCoversEveryRealError(t *testing.T) {
	allow := []config.AllowedCommand{
		{Name: "echo", ArgsRegex: "hello"},
		{Name: "uptime"}, // no ArgsRegex: accepts no arguments at all
		{Name: "definitely-not-a-real-binary-xyz", ArgsRegex: ".*"},
		{Name: "badregex", ArgsRegex: "([unclosed"},
		{Name: "false", ArgsRegex: ".*"},
	}

	cases := []struct {
		name string
		run  func() (string, error)
		want string
	}{
		{
			name: "command absent from the allowlist",
			run:  func() (string, error) { return command.DryRun("bash", []string{"-c", "whoami"}, allow) },
			want: command.StatusDenied,
		},
		{
			name: "arguments fail the regex",
			run:  func() (string, error) { return command.DryRun("echo", []string{"goodbye"}, allow) },
			want: command.StatusDenied,
		},
		{
			name: "arguments supplied where none are permitted",
			run:  func() (string, error) { return command.DryRun("uptime", []string{"-x"}, allow) },
			want: command.StatusDenied,
		},
		{
			name: "allowlist itself has an invalid regex",
			run:  func() (string, error) { return command.DryRun("badregex", []string{"x"}, allow) },
			want: command.StatusDenied,
		},
		{
			name: "allowlisted binary is not installed",
			run: func() (string, error) {
				return command.DryRun("definitely-not-a-real-binary-xyz", []string{"x"}, allow)
			},
			want: command.StatusFailure,
		},
		{
			name: "approved command exits non-zero",
			run:  func() (string, error) { return command.ExecuteCommand("false", nil, allow) },
			want: command.StatusFailure,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := tc.run()
			if err == nil {
				t.Fatalf("expected this path to produce an error, got success with output %q", out)
			}
			text := asAgentWouldWrap(err, out)
			if got := command.ClassifyResult(text); got != tc.want {
				t.Errorf("ClassifyResult = %q, want %q\n  message was: %s", got, tc.want, text)
			}
		})
	}
}

// The timeout branch is the one failure this test cannot generate cheaply —
// ExecuteCommand's deadline is a fixed 30s. Pinned by shape instead, and
// called out so it is not mistaken for a generated case.
func TestClassifyHandlesTheTimeoutMessage(t *testing.T) {
	text := asAgentWouldWrap(fmt.Errorf("command timed out: %w", fmt.Errorf("signal: killed")), "")
	if got := command.ClassifyResult(text); got != command.StatusFailure {
		t.Errorf("timeout classified as %q, want %q", got, command.StatusFailure)
	}
}

func TestClassifySuccessfulOutput(t *testing.T) {
	allow := []config.AllowedCommand{{Name: "echo", ArgsRegex: "hello"}}
	out, err := command.ExecuteCommand("echo", []string{"hello"}, allow)
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if got := command.ClassifyResult(out); got != command.StatusSuccess {
		t.Errorf("successful output classified as %q, want %q", got, command.StatusSuccess)
	}
}

// A successful read whose CONTENT happens to quote a failure message must not
// be audited as a failure. This is why classification is gated on the prefix
// the agent adds rather than on the markers alone.
func TestClassifyDoesNotMisreadLogContent(t *testing.T) {
	logOutput := strings.Join([]string{
		"Jul 21 11:04:02 web-1 deploy[912]: command failed: exit status 7",
		"Jul 21 11:04:03 web-1 deploy[912]: retrying",
		`Jul 21 11:04:04 web-1 audit[77]: command "bash" is not in the approved allowlist`,
	}, "\n")
	if got := command.ClassifyResult(logOutput); got != command.StatusSuccess {
		t.Errorf("a successful log read was classified %q — log CONTENT is being read as the call's own outcome", got)
	}
}
