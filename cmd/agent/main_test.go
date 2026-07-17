package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// cmd/agent runs on every target machine and had zero tests. These cover the
// two things that matter most on the agent: it verifies the gateway it dials
// (buildHostKeyCallback — the trust anchor that replaced InsecureIgnoreHostKey),
// and it validates tool arguments before touching the host (handleCallTool).

// --- test helpers ------------------------------------------------------------

func genPubKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return signer.PublicKey()
}

// callTool drives handleCallTool through its io.Writer seam and returns the
// decoded JSON-RPC response — exactly what the gateway would receive over the
// tunnel, without any SSH.
func callTool(t *testing.T, cfg *config.AgentConfig, name string, args interface{}) map[string]interface{} {
	t.Helper()
	var rawArgs json.RawMessage
	if args != nil {
		b, err := json.Marshal(args)
		if err != nil {
			t.Fatal(err)
		}
		rawArgs = b
	}
	params, err := json.Marshal(CallToolParams{Name: name, Arguments: rawArgs})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	handleCallTool(&buf, JsonRpcRequest{JsonRpc: "2.0", Method: "tools/call", Params: params, ID: 1}, cfg)

	var resp map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v (%s)", err, buf.String())
	}
	return resp
}

func isError(resp map[string]interface{}) bool { _, ok := resp["error"]; return ok }

func resultText(t *testing.T, resp map[string]interface{}) string {
	t.Helper()
	res, ok := resp["result"].(map[string]interface{})
	if !ok {
		t.Fatalf("no result in response: %v", resp)
	}
	content := res["content"].([]interface{})
	return content[0].(map[string]interface{})["text"].(string)
}

// --- buildHostKeyCallback: the agent's trust anchor --------------------------

func TestHostKeyPinnedMatchAndMismatch(t *testing.T) {
	realKey := genPubKey(t)
	attackerKey := genPubKey(t)

	cfg := &config.AgentConfig{
		GatewayHostKey: string(ssh.MarshalAuthorizedKey(realKey)),
	}
	cb, err := buildHostKeyCallback(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := cb("gw:2222", nil, realKey); err != nil {
		t.Errorf("pinned key rejected its own match: %v", err)
	}
	if err := cb("gw:2222", nil, attackerKey); err == nil {
		t.Fatal("a DIFFERENT key was accepted against a pinned host key — MITM would succeed")
	}
}

func TestHostKeyPinnedMalformedFailsClosed(t *testing.T) {
	cfg := &config.AgentConfig{GatewayHostKey: "not-a-valid-ssh-key"}
	if _, err := buildHostKeyCallback(cfg); err == nil {
		t.Fatal("a malformed pinned key was accepted; agent should refuse to build a callback")
	}
}

func TestHostKeyTOFULearnsThenPins(t *testing.T) {
	dir := t.TempDir()
	known := filepath.Join(dir, "gw.hostkey")
	cfg := &config.AgentConfig{KnownHostKeyPath: known}

	realKey := genPubKey(t)

	cb, err := buildHostKeyCallback(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// First connection: no stored key -> learn and accept.
	if err := cb("gw:2222", nil, realKey); err != nil {
		t.Fatalf("first-use connection rejected: %v", err)
	}
	stored, err := os.ReadFile(known)
	if err != nil {
		t.Fatalf("TOFU did not persist the key: %v", err)
	}
	if !strings.Contains(string(stored), strings.Fields(string(ssh.MarshalAuthorizedKey(realKey)))[1]) {
		t.Error("persisted key does not match the presented key")
	}

	// Second connection, same key -> accepted.
	cb2, _ := buildHostKeyCallback(cfg)
	if err := cb2("gw:2222", nil, realKey); err != nil {
		t.Errorf("matching stored key rejected on reconnect: %v", err)
	}
}

// The crown jewel: once a key is learned, a DIFFERENT key must be rejected as a
// possible MITM. This is the entire point of the agent verifying the gateway.
func TestHostKeyTOFURejectsMITM(t *testing.T) {
	dir := t.TempDir()
	known := filepath.Join(dir, "gw.hostkey")
	cfg := &config.AgentConfig{KnownHostKeyPath: known}

	realKey := genPubKey(t)
	attackerKey := genPubKey(t)

	cb, _ := buildHostKeyCallback(cfg)
	if err := cb("gw:2222", nil, realKey); err != nil { // learn realKey
		t.Fatal(err)
	}

	err := cb("gw:2222", nil, attackerKey) // attacker presents a different key
	if err == nil {
		t.Fatal("a mismatched host key was ACCEPTED after TOFU — MITM undetected")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected a host-key mismatch error, got: %v", err)
	}
}

// --- handleCallTool: argument validation before touching the host -----------

func TestFileReadRejectsTraversalAndRelativePaths(t *testing.T) {
	cfg := &config.AgentConfig{} // no allowlist needed; validation fails first

	for _, tc := range []struct{ name, path, want string }{
		{"relative path", "etc/passwd", "absolute path"},
		{"traversal", "/var/log/../../etc/shadow", "traversal"},
		{"empty path", "", "absolute path"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp := callTool(t, cfg, "file_read", map[string]string{"path": tc.path})
			if !isError(resp) {
				t.Fatalf("path %q was accepted; expected rejection", tc.path)
			}
			msg := resp["error"].(map[string]interface{})["message"].(string)
			if !strings.Contains(msg, tc.want) {
				t.Errorf("error %q does not mention %q", msg, tc.want)
			}
		})
	}
}

// Defense in depth: even a well-formed absolute path is re-checked against the
// allowlist (cat must be permitted). A valid path with cat NOT allowlisted is
// still rejected.
func TestFileReadEnforcesAllowlist(t *testing.T) {
	cfg := &config.AgentConfig{} // cat not allowlisted
	resp := callTool(t, cfg, "file_read", map[string]string{"path": "/etc/hostname"})
	txt := resultText(t, resp)
	if !strings.Contains(txt, "not in the approved allowlist") {
		t.Errorf("a valid path with cat un-allowlisted should be rejected by the allowlist; got: %q", txt)
	}
}

func TestFileReadReadsAnAllowedFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "data.txt")
	if err := os.WriteFile(f, []byte("hello from the agent"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.AgentConfig{AllowedCommands: []config.AllowedCommand{{Name: "cat", ArgsRegex: ".*"}}}

	resp := callTool(t, cfg, "file_read", map[string]string{"path": f})
	if isError(resp) {
		t.Fatalf("valid file_read errored: %v", resp["error"])
	}
	if got := resultText(t, resp); !strings.Contains(got, "hello from the agent") {
		t.Errorf("file contents not returned: %q", got)
	}
}

func TestServiceControlValidatesActionAndName(t *testing.T) {
	cfg := &config.AgentConfig{}

	// Bad action.
	resp := callTool(t, cfg, "service_control", map[string]string{"action": "obliterate", "service": "nginx"})
	if !isError(resp) {
		t.Error("invalid action was accepted")
	}

	// Bad service name (shell metacharacters).
	resp = callTool(t, cfg, "service_control", map[string]string{"action": "restart", "service": "nginx; rm -rf /"})
	if !isError(resp) {
		t.Error("service name with injection characters was accepted")
	}
	msg := resp["error"].(map[string]interface{})["message"].(string)
	if !strings.Contains(msg, "Invalid service name") {
		t.Errorf("expected service-name rejection, got %q", msg)
	}
}

func TestCallToolUnknownToolIsRejected(t *testing.T) {
	resp := callTool(t, &config.AgentConfig{}, "definitely_not_a_tool", map[string]string{})
	if !isError(resp) {
		t.Fatal("an unknown tool was not rejected")
	}
	if msg := resp["error"].(map[string]interface{})["message"].(string); !strings.Contains(msg, "Tool not found") {
		t.Errorf("expected 'Tool not found', got %q", msg)
	}
}

// run_command through the agent is enforced by the (now-tested) allowlist, so a
// non-allowlisted command is rejected end to end.
func TestRunCommandHonoursAllowlist(t *testing.T) {
	cfg := &config.AgentConfig{AllowedCommands: []config.AllowedCommand{{Name: "uptime", ArgsRegex: "^$"}}}
	resp := callTool(t, cfg, "run_command", RunCommandArgs{Name: "rm", Args: []string{"-rf", "/"}})
	if got := resultText(t, resp); !strings.Contains(got, "not in the approved allowlist") {
		t.Errorf("non-allowlisted run_command should be rejected; got %q", got)
	}
}

// --- tailFile: bounded read -------------------------------------------------

func TestTailFile(t *testing.T) {
	f := filepath.Join(t.TempDir(), "log.txt")
	if err := os.WriteFile(f, []byte("l1\nl2\nl3\nl4\nl5\n"), 0644); err != nil {
		t.Fatal(err)
	}

	got, err := tailFile(f, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got != "l4\nl5" {
		t.Errorf("tail 2 = %q, want last two lines", got)
	}

	// Fewer lines than the window returns them all.
	got, _ = tailFile(f, 100)
	if strings.Count(got, "\n") != 4 {
		t.Errorf("tail 100 of a 5-line file = %q", got)
	}

	// Missing file errors rather than returning empty.
	if _, err := tailFile(filepath.Join(t.TempDir(), "nope"), 10); err == nil {
		t.Error("tailFile on a missing file should error")
	}
}
