package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
