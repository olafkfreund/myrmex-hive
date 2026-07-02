package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/olafkfreund/mcp-os-agent/pkg/config"
)

func TestIntegrationAgentGateway(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mcp-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Generate SSH Keys
	// Gateway Host Key
	hostPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}
	hostKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(hostPriv),
	})
	hostKeyPath := filepath.Join(tmpDir, "host_key")
	if err := os.WriteFile(hostKeyPath, hostKeyBytes, 0600); err != nil {
		t.Fatalf("failed to write host key: %v", err)
	}

	// Agent Keypair
	agentPub, agentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate agent key: %v", err)
	}

	// Convert private key to PKCS#8 PEM
	privBytes, err := x509.MarshalPKCS8PrivateKey(agentPriv)
	if err != nil {
		t.Fatalf("failed to marshal agent private key: %v", err)
	}
	agentPrivPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})
	agentKeyPath := filepath.Join(tmpDir, "agent_key")
	if err := os.WriteFile(agentKeyPath, agentPrivPEM, 0600); err != nil {
		t.Fatalf("failed to write agent private key: %v", err)
	}

	// Agent Public Key in Authorized Keys format
	sshPub, err := ssh.NewPublicKey(agentPub)
	if err != nil {
		t.Fatalf("failed to create ssh pubkey: %v", err)
	}
	authKeysBytes := ssh.MarshalAuthorizedKey(sshPub)
	authKeysPath := filepath.Join(tmpDir, "authorized_keys")
	if err := os.WriteFile(authKeysPath, authKeysBytes, 0600); err != nil {
		t.Fatalf("failed to write authorized_keys: %v", err)
	}

	// 2. Start Gateway SSH Server on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	listenAddr := listener.Addr().String()

	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !bytes.Equal(key.Marshal(), sshPub.Marshal()) {
				return nil, fmt.Errorf("unauthorized public key")
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"agent-id": conn.User(),
				},
			}, nil
		},
	}
	signer, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse host private key: %v", err)
	}
	sshConfig.AddHostKey(signer)

	// Accept loop for SSH connections
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed
			}
			go handleSSHConnection(conn, sshConfig)
		}
	}()
	defer listener.Close()

	// 3. Connect the Agent client programmatically (mock running agent main)
	agentCfg := &config.AgentConfig{
		GatewayAddr:    listenAddr,
		PrivateKeyPath: agentKeyPath,
		AgentID:        "test-agent-1",
		AllowedCommands: []config.AllowedCommand{
			{Name: "uptime", ArgsRegex: "^$"},
			{Name: "echo", ArgsRegex: "^[a-zA-Z0-9\\s]+$"},
		},
	}

	// Read key and parse signer
	agentKeyBytes, err := os.ReadFile(agentCfg.PrivateKeyPath)
	if err != nil {
		t.Fatalf("failed to read agent private key: %v", err)
	}
	agentSigner, err := ssh.ParsePrivateKey(agentKeyBytes)
	if err != nil {
		t.Fatalf("failed to parse agent private key: %v", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            agentCfg.AgentID,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(agentSigner)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	// Dial gateway
	conn, err := net.Dial("tcp", listenAddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, listenAddr, clientConfig)
	if err != nil {
		t.Fatalf("failed to create client conn: %v", err)
	}
	defer sshConn.Close()

	go ssh.DiscardRequests(reqs)
	go func() {
		for newChan := range chans {
			newChan.Reject(ssh.Prohibited, "no incoming")
		}
	}()

	channel, channelRequests, err := sshConn.OpenChannel("mcp", nil)
	if err != nil {
		t.Fatalf("failed to open mcp channel: %v", err)
	}
	defer channel.Close()
	go ssh.DiscardRequests(channelRequests)

	// Mock Agent request reading in a background loop
	// This matches what the agent does in connectAndServe
	agentReader := bufio.NewReader(channel)
	go func() {
		for {
			line, err := agentReader.ReadBytes('\n')
			if err != nil {
				return
			}
			var req JsonRpcRequest
			if err := json.Unmarshal(line, &req); err == nil {
				// Handle it using the agent's logic (since it's a test, let's process it)
				// Wait! We can import handleRequest from main, but since it's defined in cmd/agent/main.go (package main),
				// it's in a different folder/package, so we cannot easily call it.
				// However, we can write a mini handler here, or just verify the gateway's multiplexing.
				// Let's implement a mini-handler that responds to list and call.
				var resp JsonRpcResponse
				resp.JsonRpc = "2.0"
				resp.ID = req.ID

				switch req.Method {
				case "tools/list":
					resp.Result = map[string]interface{}{
						"tools": []map[string]interface{}{
							{"name": "get_metrics", "description": "Metrics"},
							{"name": "run_command", "description": "Run command"},
						},
					}
				case "tools/call":
					var params CallToolParams
					json.Unmarshal(req.Params, &params)
					if params.Name == "get_metrics" {
						resp.Result = map[string]interface{}{
							"content": []map[string]interface{}{
								{"type": "text", "text": `{"cpu_usage_percent":10.5}`},
							},
						}
					} else if params.Name == "run_command" {
						var args struct {
							Name string   `json:"name"`
							Args []string `json:"args"`
						}
						json.Unmarshal(params.Arguments, &args)
						if args.Name == "uptime" {
							resp.Result = map[string]interface{}{
								"content": []map[string]interface{}{
									{"type": "text", "text": "up 1 day"},
								},
							}
						} else {
							resp.Error = JsonRpcError{Code: -32603, Message: "Rejected"}
						}
					}
				}
				respBytes, _ := json.Marshal(resp)
				respBytes = append(respBytes, '\n')
				channel.Write(respBytes)
			}
		}
	}()

	// Wait for agent to register with Gateway
	time.Sleep(100 * time.Millisecond)

	// 4. Test Gateway routing
	cli := getAgent("test-agent-1")
	if cli == nil {
		t.Fatalf("agent test-agent-1 did not register successfully")
	}

	// Test tools/list routing
	t.Run("Tools List", func(t *testing.T) {
		req := JsonRpcRequest{
			JsonRpc: "2.0",
			Method:  "tools/list",
			ID:      1,
		}
		resp := cli.Call(req)
		if resp.Error != nil {
			t.Fatalf("tools/list failed: %v", resp.Error)
		}
		var result struct {
			Tools []map[string]interface{} `json:"tools"`
		}
		resBytes, _ := json.Marshal(resp.Result)
		json.Unmarshal(resBytes, &result)
		if len(result.Tools) != 2 {
			t.Errorf("expected 2 tools, got %d", len(result.Tools))
		}
	})

	// Test call metrics tool
	t.Run("Call Metrics", func(t *testing.T) {
		params := CallToolParams{Name: "get_metrics"}
		paramsBytes, _ := json.Marshal(params)
		req := JsonRpcRequest{
			JsonRpc: "2.0",
			Method:  "tools/call",
			Params:  paramsBytes,
			ID:      2,
		}
		resp := cli.Call(req)
		if resp.Error != nil {
			t.Fatalf("call get_metrics failed: %v", resp.Error)
		}
		var callResult struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		resBytes, _ := json.Marshal(resp.Result)
		json.Unmarshal(resBytes, &callResult)
		if len(callResult.Content) == 0 || !bytes.Contains([]byte(callResult.Content[0].Text), []byte("cpu_usage_percent")) {
			t.Errorf("unexpected content: %v", callResult)
		}
	})

	// Test approved command execution
	t.Run("Approved Command", func(t *testing.T) {
		cmdArgs := struct {
			Name string   `json:"name"`
			Args []string `json:"args"`
		}{Name: "uptime"}
		cmdArgsBytes, _ := json.Marshal(cmdArgs)
		params := CallToolParams{Name: "run_command", Arguments: cmdArgsBytes}
		paramsBytes, _ := json.Marshal(params)
		req := JsonRpcRequest{
			JsonRpc: "2.0",
			Method:  "tools/call",
			Params:  paramsBytes,
			ID:      3,
		}
		resp := cli.Call(req)
		if resp.Error != nil {
			t.Fatalf("call run_command failed: %v", resp.Error)
		}
		var callResult struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		resBytes, _ := json.Marshal(resp.Result)
		json.Unmarshal(resBytes, &callResult)
		if len(callResult.Content) == 0 || callResult.Content[0].Text != "up 1 day" {
			t.Errorf("expected 'up 1 day', got: %v", callResult)
		}
	})

	// Test unapproved command execution
	t.Run("Unapproved Command", func(t *testing.T) {
		cmdArgs := struct {
			Name string   `json:"name"`
			Args []string `json:"args"`
		}{Name: "rm", Args: []string{"-rf", "/"}}
		cmdArgsBytes, _ := json.Marshal(cmdArgs)
		params := CallToolParams{Name: "run_command", Arguments: cmdArgsBytes}
		paramsBytes, _ := json.Marshal(params)
		req := JsonRpcRequest{
			JsonRpc: "2.0",
			Method:  "tools/call",
			Params:  paramsBytes,
			ID:      4,
		}
		resp := cli.Call(req)
		if resp.Error == nil {
			t.Errorf("expected error for unapproved command, got nil result: %v", resp.Result)
		}
	})
}

func TestAuthorizeToolCall(t *testing.T) {
	agentTags := map[string][]string{
		"agent-1": {"prod", "web"},
		"agent-2": {"staging"},
	}

	tests := []struct {
		name    string
		scope   *config.TokenScope
		agentID string
		tool    string
		wantErr bool
	}{
		{
			name:    "nil scope is unrestricted",
			scope:   nil,
			agentID: "agent-1",
			tool:    "run_command",
			wantErr: false,
		},
		{
			name:    "agent id allowed",
			scope:   &config.TokenScope{Agents: []string{"agent-1"}},
			agentID: "agent-1",
			tool:    "run_command",
			wantErr: false,
		},
		{
			name:    "agent id denied",
			scope:   &config.TokenScope{Agents: []string{"agent-1"}},
			agentID: "agent-2",
			tool:    "run_command",
			wantErr: true,
		},
		{
			name:    "tag allowed",
			scope:   &config.TokenScope{Tags: []string{"prod"}},
			agentID: "agent-1",
			tool:    "run_command",
			wantErr: false,
		},
		{
			name:    "tag denied",
			scope:   &config.TokenScope{Tags: []string{"prod"}},
			agentID: "agent-2",
			tool:    "run_command",
			wantErr: true,
		},
		{
			name:    "agent restricted with no matching agent id or tag",
			scope:   &config.TokenScope{Agents: []string{"agent-9"}, Tags: []string{"nope"}},
			agentID: "agent-1",
			tool:    "run_command",
			wantErr: true,
		},
		{
			name:    "tool allowed",
			scope:   &config.TokenScope{Tools: []string{"run_command", "get_metrics"}},
			agentID: "agent-1",
			tool:    "get_metrics",
			wantErr: false,
		},
		{
			name:    "tool denied",
			scope:   &config.TokenScope{Tools: []string{"get_metrics"}},
			agentID: "agent-1",
			tool:    "run_command",
			wantErr: true,
		},
		{
			name:    "gateway-native tool skips agent check",
			scope:   &config.TokenScope{Agents: []string{"agent-1"}},
			agentID: "gateway",
			tool:    "ask_gemma",
			wantErr: false,
		},
		{
			name:    "gateway-native tool still honors tool scope",
			scope:   &config.TokenScope{Agents: []string{"agent-1"}, Tools: []string{"humanize_syslog"}},
			agentID: "gateway",
			tool:    "ask_gemma",
			wantErr: true,
		},
		{
			name:    "agent and tool both allowed",
			scope:   &config.TokenScope{Agents: []string{"agent-1"}, Tools: []string{"run_command"}},
			agentID: "agent-1",
			tool:    "run_command",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := authorizeToolCall(tt.scope, agentTags, tt.agentID, tt.tool)
			if tt.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
		})
	}
}

func TestToolTier(t *testing.T) {
	tests := []struct {
		name string
		cfg  *config.GatewayConfig
		tool string
		want string
	}{
		{
			name: "nil config defaults to read",
			cfg:  nil,
			tool: "run_command",
			want: "read",
		},
		{
			name: "unconfigured risk tiers defaults to read",
			cfg:  &config.GatewayConfig{},
			tool: "run_command",
			want: "read",
		},
		{
			name: "unlisted tool defaults to read",
			cfg:  &config.GatewayConfig{RiskTiers: map[string]string{"service_control": "mutate"}},
			tool: "get_metrics",
			want: "read",
		},
		{
			name: "listed tool returns configured tier",
			cfg:  &config.GatewayConfig{RiskTiers: map[string]string{"run_command": "destructive"}},
			tool: "run_command",
			want: "destructive",
		},
		{
			name: "listed mutate tier",
			cfg:  &config.GatewayConfig{RiskTiers: map[string]string{"service_control": "mutate"}},
			tool: "service_control",
			want: "mutate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := toolTier(tt.cfg, tt.tool); got != tt.want {
				t.Errorf("toolTier(%+v, %q) = %q, want %q", tt.cfg, tt.tool, got, tt.want)
			}
		})
	}
}

func TestRateLimitAllow(t *testing.T) {
	const limit = 3
	key := "TestRateLimitAllow|token|agent|run_command"

	for i := 0; i < limit; i++ {
		if !rateLimitAllow(key, limit) {
			t.Fatalf("call %d: expected allow within limit %d", i+1, limit)
		}
	}
	if rateLimitAllow(key, limit) {
		t.Fatalf("call %d: expected block once over limit %d", limit+1, limit)
	}

	// A distinct key gets its own independent window and is unaffected by a
	// different key's exhausted window.
	otherKey := "TestRateLimitAllow|other-token|agent|run_command"
	if !rateLimitAllow(otherKey, limit) {
		t.Errorf("expected distinct key to have its own independent window")
	}

	// perMinute <= 0 disables rate limiting entirely, regardless of history.
	if !rateLimitAllow(key, 0) {
		t.Errorf("expected rateLimitAllow to always allow when perMinute <= 0")
	}
}

func TestApprovalStoreTransitions(t *testing.T) {
	// logAuditEvent (invoked by every approval decision) reads currentConfig
	// for the configured audit log path. Production always sets it in
	// main() before serving requests, but this test binary never calls
	// main(), so seed a minimal config pointed at a scratch file and restore
	// whatever was there afterward.
	currentConfigMu.Lock()
	prevCfg := currentConfig
	currentConfig = &config.GatewayConfig{AuditLogPath: filepath.Join(t.TempDir(), "audit.log")}
	currentConfigMu.Unlock()
	t.Cleanup(func() {
		currentConfigMu.Lock()
		currentConfig = prevCfg
		currentConfigMu.Unlock()
	})

	adminCtx := context.WithValue(context.Background(), contextKeyRole, "admin")
	adminCtx = context.WithValue(adminCtx, contextKeyToken, "admin-token-1234")

	newDecisionRequest := func(ctx context.Context, id, decision string) *http.Request {
		body := fmt.Sprintf(`{"id":%q,"decision":%q}`, id, decision)
		req := httptest.NewRequest(http.MethodPost, "/api/approvals", strings.NewReader(body))
		return req.WithContext(ctx)
	}

	t.Run("create then approve", func(t *testing.T) {
		approval, err := createPendingApproval(adminCtx, "no-such-agent", "run_command", `{"name":"uptime"}`, "destructive")
		if err != nil {
			t.Fatalf("createPendingApproval failed: %v", err)
		}
		if approval.Status != "pending" {
			t.Fatalf("expected new approval status %q, got %q", "pending", approval.Status)
		}

		rec := httptest.NewRecorder()
		handleApiApprovalDecision(rec, newDecisionRequest(adminCtx, approval.ID, "approve"))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 approving a pending request, got %d: %s", rec.Code, rec.Body.String())
		}

		approvalsMu.Lock()
		gotStatus := approvals[approval.ID].Status
		approvalsMu.Unlock()
		if gotStatus != "approved" {
			t.Errorf("expected stored status %q, got %q", "approved", gotStatus)
		}

		// Re-deciding an already-decided approval must fail, not silently
		// re-execute the underlying tool call.
		rec2 := httptest.NewRecorder()
		handleApiApprovalDecision(rec2, newDecisionRequest(adminCtx, approval.ID, "approve"))
		if rec2.Code != http.StatusConflict {
			t.Errorf("expected 409 re-deciding an already-approved request, got %d", rec2.Code)
		}
	})

	t.Run("create then reject", func(t *testing.T) {
		approval, err := createPendingApproval(adminCtx, "no-such-agent", "run_command", `{"name":"rm"}`, "destructive")
		if err != nil {
			t.Fatalf("createPendingApproval failed: %v", err)
		}

		rec := httptest.NewRecorder()
		handleApiApprovalDecision(rec, newDecisionRequest(adminCtx, approval.ID, "reject"))
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 rejecting a pending request, got %d: %s", rec.Code, rec.Body.String())
		}

		var resp map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response body: %v", err)
		}
		if resp["status"] != "rejected" {
			t.Errorf("expected response status %q, got %q", "rejected", resp["status"])
		}

		approvalsMu.Lock()
		gotStatus := approvals[approval.ID].Status
		approvalsMu.Unlock()
		if gotStatus != "rejected" {
			t.Errorf("expected stored status %q, got %q", "rejected", gotStatus)
		}
	})

	t.Run("unknown id returns 404", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handleApiApprovalDecision(rec, newDecisionRequest(adminCtx, "does-not-exist", "approve"))
		if rec.Code != http.StatusNotFound {
			t.Errorf("expected 404 for unknown approval id, got %d", rec.Code)
		}
	})

	t.Run("non-admin role forbidden", func(t *testing.T) {
		approval, err := createPendingApproval(adminCtx, "no-such-agent", "run_command", `{}`, "destructive")
		if err != nil {
			t.Fatalf("createPendingApproval failed: %v", err)
		}

		operatorCtx := context.WithValue(context.Background(), contextKeyRole, "operator")
		rec := httptest.NewRecorder()
		handleApiApprovalDecision(rec, newDecisionRequest(operatorCtx, approval.ID, "approve"))
		if rec.Code != http.StatusForbidden {
			t.Errorf("expected 403 for non-admin decision, got %d", rec.Code)
		}

		// The approval must remain untouched by the rejected attempt.
		approvalsMu.Lock()
		gotStatus := approvals[approval.ID].Status
		approvalsMu.Unlock()
		if gotStatus != "pending" {
			t.Errorf("expected approval to remain pending after forbidden decision, got %q", gotStatus)
		}
	})
}
