package main

// #174: an agent that REFUSES a call answers with a well-formed JSON-RPC
// result, not an error, so the audit log recorded allowlist denials as
// "success / Tool execution completed". These cover the Gateway half of the
// fix; pkg/command/classify_test.go covers the message contract itself.

import (
	"encoding/json"
	"testing"

	"github.com/olafkfreund/myrmex-hive/pkg/command"
)

// agentResult builds the result shape an agent actually sends back, going
// through JSON so the test sees what the Gateway sees rather than a Go value
// the real path would never receive.
func agentResult(t *testing.T, text string) interface{} {
	t.Helper()
	raw, err := json.Marshal(map[string]interface{}{
		"content": []map[string]string{{"type": "text", "text": text}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestClassifyToolResult(t *testing.T) {
	cases := []struct {
		name string
		text string
		want string
	}{
		{
			name: "allowlist refused the command outright",
			text: command.ResultFailurePrefix + ` command "bash" is not in the approved allowlist` + "\nOutput:\n",
			want: command.StatusDenied,
		},
		{
			name: "allowlist refused the arguments",
			text: command.ResultFailurePrefix + ` arguments "-s http://evil.example.com/" do not match the approved pattern "..."` + "\nOutput:\n",
			want: command.StatusDenied,
		},
		{
			name: "approved command ran and exited non-zero",
			text: command.ResultFailurePrefix + " command failed: exit status 7\nOutput:\n",
			want: command.StatusFailure,
		},
		{
			name: "approved command timed out",
			text: command.ResultFailurePrefix + " command timed out: signal: killed\nOutput:\n",
			want: command.StatusFailure,
		},
		{
			name: "ordinary successful output",
			text: `{"status":"ok","load1":7.31}`,
			want: command.StatusSuccess,
		},
		{
			name: "successful log read that QUOTES a failure must stay success",
			text: "Jul 21 11:04:02 web-1 deploy[912]: command failed: exit status 7",
			want: command.StatusSuccess,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyToolResult(agentResult(t, tc.text)); got != tc.want {
				t.Errorf("classifyToolResult = %q, want %q", got, tc.want)
			}
		})
	}
}

// A result the Gateway cannot parse must not invent a failure — this decides
// an audit label, and gateway-native tools do not all use the content shape.
func TestClassifyToolResultToleratesUnknownShapes(t *testing.T) {
	for _, r := range []interface{}{
		nil,
		"a bare string result",
		map[string]interface{}{"unexpected": "shape"},
		[]interface{}{1, 2, 3},
	} {
		if got := classifyToolResult(r); got != command.StatusSuccess {
			t.Errorf("unparseable result %#v classified as %q, want %q", r, got, command.StatusSuccess)
		}
	}
}
