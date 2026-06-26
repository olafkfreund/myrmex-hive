package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/olafkfreund/mcp-os-agent/pkg/config"
	"github.com/olafkfreund/mcp-os-agent/pkg/llm"
)

// UpstreamCaller defines the interface for all external/upstream MCP servers (SSE and Stdio)
type UpstreamCaller interface {
	GetName() string
	GetStatus() string
	GetURL() string
	Call(req JsonRpcRequest) (*JsonRpcResponse, error)
	Stop()
}

// JSON-RPC messages matching MCP specification
type JsonRpcRequest struct {
	JsonRpc string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

type JsonRpcResponse struct {
	JsonRpc string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   interface{} `json:"error,omitempty"`
	ID      interface{} `json:"id"`
}

type JsonRpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type AskGemmaArgs struct {
	AgentID string `json:"agent_id"`
	Prompt  string `json:"prompt"`
}

type HumanizeSyslogArgs struct {
	AgentID string `json:"agent_id"`
	LogLine string `json:"log_line"`
}

func normalizeID(id interface{}) string {
	if id == nil {
		return ""
	}
	switch v := id.(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%.0f", v)
	case int:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// Multiplexed channel client for thread-safe SSH MCP communication
type AgentClient struct {
	agentID         string
	ipAddress       string
	osVersion       string
	runningServices []string
	openPorts       []string
	channel         ssh.Channel
	pending         map[string]chan JsonRpcResponse
	mu              sync.Mutex
	writeMu         sync.Mutex
}

func NewAgentClient(agentID string, ipAddress string, channel ssh.Channel) *AgentClient {
	client := &AgentClient{
		agentID:   agentID,
		ipAddress: ipAddress,
		channel:   channel,
		pending:   make(map[string]chan JsonRpcResponse),
	}
	go client.readLoop()
	go client.querySystemInfo()
	return client
}

func (c *AgentClient) querySystemInfo() {
	// Wait a moment for registration to fully settle
	time.Sleep(200 * time.Millisecond)

	callParams := CallToolParams{
		Name: "get_system_info",
	}
	callParamsBytes, _ := json.Marshal(callParams)
	req := JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  callParamsBytes,
		ID:      "sysinfo-" + fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	resp := c.Call(req)
	if resp.Error != nil {
		log.Printf("[%s] failed to query system info: %v", c.agentID, resp.Error)
		c.mu.Lock()
		c.osVersion = "Unknown OS"
		c.mu.Unlock()
		return
	}

	resultMap, ok := resp.Result.(map[string]interface{})
	if !ok {
		log.Printf("[%s] invalid response format for system info", c.agentID)
		return
	}
	contentArr, ok := resultMap["content"].([]interface{})
	if !ok || len(contentArr) == 0 {
		log.Printf("[%s] no content in system info response", c.agentID)
		return
	}
	contentObj, ok := contentArr[0].(map[string]interface{})
	if !ok {
		return
	}
	textVal, ok := contentObj["text"].(string)
	if !ok {
		return
	}

	type SystemInfo struct {
		OSVersion       string   `json:"os_version"`
		RunningServices []string `json:"running_services"`
		OpenPorts       []string `json:"open_ports"`
	}

	var info SystemInfo
	if err := json.Unmarshal([]byte(textVal), &info); err != nil {
		log.Printf("[%s] failed to unmarshal system info text: %v", c.agentID, err)
		return
	}

	c.mu.Lock()
	c.osVersion = info.OSVersion
	c.runningServices = info.RunningServices
	c.openPorts = info.OpenPorts
	c.mu.Unlock()
	log.Printf("[%s] system info updated: OS=%s, Services=%d, Ports=%d", c.agentID, c.osVersion, len(c.runningServices), len(c.openPorts))
}

func (c *AgentClient) readLoop() {
	reader := bufio.NewReader(c.channel)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			c.cleanup(err)
			return
		}

		var resp JsonRpcResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			log.Printf("[%s] failed to unmarshal response: %v", c.agentID, err)
			continue
		}

		c.mu.Lock()
		normID := normalizeID(resp.ID)
		ch, exists := c.pending[normID]
		if exists {
			ch <- resp
			delete(c.pending, normID)
		}
		c.mu.Unlock()
	}
}

func (c *AgentClient) cleanup(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	log.Printf("[%s] connection closed: %v", c.agentID, err)
	for id, ch := range c.pending {
		ch <- JsonRpcResponse{
			JsonRpc: "2.0",
			Error: JsonRpcError{
				Code:    -32603,
				Message: fmt.Sprintf("Agent connection lost: %v", err),
			},
			ID: id,
		}
		delete(c.pending, id)
	}
	removeAgent(c.agentID)
}

func (c *AgentClient) Call(req JsonRpcRequest) JsonRpcResponse {
	ch := make(chan JsonRpcResponse, 1)
	normID := normalizeID(req.ID)

	c.mu.Lock()
	c.pending[normID] = ch
	c.mu.Unlock()

	data, err := json.Marshal(req)
	if err != nil {
		c.mu.Lock()
		delete(c.pending, normID)
		c.mu.Unlock()
		return JsonRpcResponse{
			JsonRpc: "2.0",
			Error:   JsonRpcError{Code: -32603, Message: "Marshal error"},
			ID:      req.ID,
		}
	}
	data = append(data, '\n')

	c.writeMu.Lock()
	_, err = c.channel.Write(data)
	c.writeMu.Unlock()

	if err != nil {
		c.mu.Lock()
		delete(c.pending, normID)
		c.mu.Unlock()
		return JsonRpcResponse{
			JsonRpc: "2.0",
			Error:   JsonRpcError{Code: -32603, Message: fmt.Sprintf("Write error: %v", err)},
			ID:      req.ID,
		}
	}

	select {
	case resp := <-ch:
		return resp
	case <-time.After(35 * time.Second): // Slightly longer than command execution timeout (30s)
		c.mu.Lock()
		delete(c.pending, normID)
		c.mu.Unlock()
		return JsonRpcResponse{
			JsonRpc: "2.0",
			Error:   JsonRpcError{Code: -32603, Message: "Request timeout"},
			ID:      req.ID,
		}
	}
}

var (
	agents            = make(map[string]*AgentClient)
	agentsMu          sync.RWMutex
	llmCli            *llm.Client
	configFilePath    string
	currentConfig     *config.GatewayConfig
	currentConfigMu   sync.RWMutex
	upstreamClients   = make(map[string]UpstreamCaller)
	upstreamClientsMu sync.RWMutex
)

func addAgent(agentID string, ip string, channel ssh.Channel) {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	agents[agentID] = NewAgentClient(agentID, ip, channel)
	log.Printf("Agent registered: %s (IP: %s)", agentID, ip)
}

func removeAgent(agentID string) {
	agentsMu.Lock()
	defer agentsMu.Unlock()
	delete(agents, agentID)
	log.Printf("Agent removed: %s", agentID)
}

func getAgent(agentID string) *AgentClient {
	agentsMu.RLock()
	defer agentsMu.RUnlock()
	return agents[agentID]
}

func listAgentIDs() []string {
	agentsMu.RLock()
	defer agentsMu.RUnlock()
	list := make([]string, 0, len(agents))
	for id := range agents {
		list = append(list, id)
	}
	return list
}

var httpActive bool

func main() {
	configPath := flag.String("config", "gateway_config.json", "Path to gateway config")
	flag.Parse()

	// Disable logs on stdout so they don't corrupt MCP stdio protocol
	log.SetOutput(os.Stderr)
	log.Println("Starting MCP Gateway...")

	cfg, err := config.LoadGatewayConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	configFilePath = *configPath
	currentConfig = cfg

	// Generate a secure Auth Token if none is set
	if cfg.AuthToken == "" {
		tokenBytes := make([]byte, 32)
		if _, err := rand.Read(tokenBytes); err == nil {
			cfg.AuthToken = fmt.Sprintf("%x", tokenBytes)
			log.Printf("[SECURITY] Generated secure Auth Token: %s", cfg.AuthToken)
			// Save token to disk
			if configFilePath != "" {
				fileBytes, _ := json.MarshalIndent(cfg, "", "  ")
				_ = os.WriteFile(configFilePath, fileBytes, 0644)
			}
		}
	}

	// Initialize Local LLM Client if configured
	if cfg.OllamaURL != "" {
		llmCli = llm.NewClient(cfg.OllamaURL, cfg.OllamaModel)
		log.Printf("Local LLM initialized (Ollama model: %s at %s)", cfg.OllamaModel, cfg.OllamaURL)
	}

	// Start Upstream MCP clients if configured
	reloadUpstreamClients(cfg)

	// 1. Start SSH Server in background
	go startSSHServer(cfg)

	// 2. Start HTTP/SSE Server if configured
	if cfg.HTTPAddr != "" {
		httpActive = true
		go startHTTPServer(cfg)
	}

	// 3. Start MCP Stdio Server (reads from stdin, writes to stdout)
	startStdioMCPServer()
}

func generateTransientHostKey() (ssh.Signer, error) {
	log.Println("WARNING: Generating a transient host key. Agent connections will see changed host keys upon restart!")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	privateKeyPEM := pem.EncodeToMemory(pemBlock)

	return ssh.ParsePrivateKey(privateKeyPEM)
}

func startSSHServer(cfg *config.GatewayConfig) {
	sshConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Authentication checks
			if cfg.AuthorizedKeysPath == "" {
				log.Printf("WARNING: AuthorizedKeysPath is empty. Accepting ALL agent connections (insecure!).")
				return nil, nil
			}

			authBytes, err := os.ReadFile(cfg.AuthorizedKeysPath)
			if err != nil {
				return nil, fmt.Errorf("failed to read authorized keys: %w", err)
			}

			// Parse authorized keys
			authorized := false
			rest := authBytes
			var authKey ssh.PublicKey
			for len(rest) > 0 {
				authKey, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
				if err != nil {
					break
				}
				if bytes.Equal(key.Marshal(), authKey.Marshal()) {
					authorized = true
					break
				}
			}

			if !authorized {
				return nil, fmt.Errorf("public key not authorized")
			}

			return &ssh.Permissions{
				Extensions: map[string]string{
					"agent-id": conn.User(),
				},
			}, nil
		},
	}

	// Load Host Key
	var hostKey ssh.Signer
	if cfg.HostKeyPath != "" {
		keyBytes, err := os.ReadFile(cfg.HostKeyPath)
		if err != nil {
			log.Fatalf("Failed to read host key %s: %v", cfg.HostKeyPath, err)
		}
		hostKey, err = ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			log.Fatalf("Failed to parse host key: %v", err)
		}
	} else {
		var err error
		hostKey, err = generateTransientHostKey()
		if err != nil {
			log.Fatalf("Failed to generate transient key: %v", err)
		}
	}
	sshConfig.AddHostKey(hostKey)

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.ListenAddr, err)
	}
	log.Printf("SSH Gateway listening on %s...", cfg.ListenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept incoming TCP: %v", err)
			continue
		}

		go handleSSHConnection(conn, sshConfig)
	}
}

func handleSSHConnection(conn net.Conn, sshConfig *ssh.ServerConfig) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, sshConfig)
	if err != nil {
		log.Printf("SSH handshake failed: %v", err)
		return
	}
	defer sshConn.Close()

	agentID := sshConn.Permissions.Extensions["agent-id"]
	if agentID == "" {
		agentID = "unknown-agent"
	}

	log.Printf("Secure SSH session established for agent: %s", agentID)

	go ssh.DiscardRequests(reqs)

	remoteAddr := conn.RemoteAddr().String()
	ip, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		ip = remoteAddr
	}

	for newChan := range chans {
		if newChan.ChannelType() != "mcp" {
			newChan.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}

		channel, requests, err := newChan.Accept()
		if err != nil {
			log.Printf("Could not accept channel: %v", err)
			return
		}

		go ssh.DiscardRequests(requests)

		// Register agent
		addAgent(agentID, ip, channel)
	}
}

type ResponseSender func(resp JsonRpcResponse)

func startStdioMCPServer() {
	reader := bufio.NewReader(os.Stdin)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				if httpActive {
					log.Println("Stdio EOF reached. HTTP/SSE gateway server remains active. Blocking...")
					select {} // Block forever
				}
				break
			}
			log.Printf("Error reading stdin: %v", err)
			return
		}

		var req JsonRpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			sendErrorDirect(func(resp JsonRpcResponse) {
				sendResponse(os.Stdout, resp)
			}, nil, -32700, "Parse error")
			continue
		}

		sendCallback := func(resp JsonRpcResponse) {
			sendResponse(os.Stdout, resp)
		}
		go handleClientRequest(req, sendCallback)
	}
}

func handleClientRequest(req JsonRpcRequest, send ResponseSender) {
	switch req.Method {
	case "initialize":
		handleInitialize(req, send)
	case "tools/list":
		handleListTools(req, send)
	case "tools/call":
		handleCallTool(req, send)
	default:
		sendErrorDirect(send, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func handleInitialize(req JsonRpcRequest, send ResponseSender) {
	response := JsonRpcResponse{
		JsonRpc: "2.0",
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"serverInfo": map[string]interface{}{
				"name":    "mcp-gateway",
				"version": "1.0.0",
			},
		},
		ID: req.ID,
	}
	send(response)
}

func handleListTools(req JsonRpcRequest, send ResponseSender) {
	// List Gateway level tools
	tools := []map[string]interface{}{
		{
			"name":        "gateway__list_agents",
			"description": "List all currently connected Linux Agents",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}

	if llmCli != nil {
		tools = append(tools, map[string]interface{}{
			"name":        "gateway__ask_gemma",
			"description": "Instruct Gemma LLM to decide on actions and coordinate execution securely on a target agent.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"agent_id": map[string]interface{}{
						"type":        "string",
						"description": "The target Agent Node ID",
					},
					"prompt": map[string]interface{}{
						"type":        "string",
						"description": "What you want to accomplish on the agent (e.g. 'check memory and explain it')",
					},
				},
				"required": []string{"agent_id", "prompt"},
			},
		})

		tools = append(tools, map[string]interface{}{
			"name":        "gateway__humanize_syslog",
			"description": "Humanizes a syslog entry or warning using Gemma LLM",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"agent_id": map[string]interface{}{
						"type":        "string",
						"description": "The agent ID source",
					},
					"log_line": map[string]interface{}{
						"type":        "string",
						"description": "The raw syslog or event line",
					},
				},
				"required": []string{"agent_id", "log_line"},
			},
		})
	}

	// Query each connected agent for their tools
	agentsMu.RLock()
	for id, cli := range agents {
		// Send tools/list to agent
		agentReq := JsonRpcRequest{
			JsonRpc: "2.0",
			Method:  "tools/list",
			ID:      fmt.Sprintf("gw-list-%s-%d", id, time.Now().UnixNano()),
		}
		resp := cli.Call(agentReq)
		if resp.Error == nil && resp.Result != nil {
			var result struct {
				Tools []map[string]interface{} `json:"tools"`
			}
			resultBytes, _ := json.Marshal(resp.Result)
			if err := json.Unmarshal(resultBytes, &result); err == nil {
				for _, tool := range result.Tools {
					toolName, _ := tool["name"].(string)
					// Rewrite tool name: <agent_id>__<tool_name>
					tool["name"] = fmt.Sprintf("%s__%s", id, toolName)
					tools = append(tools, tool)
				}
			}
		}
	}
	agentsMu.RUnlock()

	// Query each connected upstream server for their tools
	upstreamClientsMu.RLock()
	for name, uc := range upstreamClients {
		if uc.GetStatus() == "connected" {
			agentReq := JsonRpcRequest{
				JsonRpc: "2.0",
				Method:  "tools/list",
				ID:      fmt.Sprintf("gw-upstream-list-%s-%d", name, time.Now().UnixNano()),
			}
			resp, err := uc.Call(agentReq)
			if err == nil && resp.Error == nil && resp.Result != nil {
				var result struct {
					Tools []map[string]interface{} `json:"tools"`
				}
				resultBytes, _ := json.Marshal(resp.Result)
				if err := json.Unmarshal(resultBytes, &result); err == nil {
					for _, tool := range result.Tools {
						toolName, _ := tool["name"].(string)
						// Rewrite tool name: <upstream_name>__<tool_name>
						tool["name"] = fmt.Sprintf("%s__%s", name, toolName)
						tools = append(tools, tool)
					}
				}
			}
		}
	}
	upstreamClientsMu.RUnlock()

	response := JsonRpcResponse{
		JsonRpc: "2.0",
		Result: map[string]interface{}{
			"tools": tools,
		},
		ID: req.ID,
	}
	send(response)
}

func handleCallTool(req JsonRpcRequest, send ResponseSender) {
	var params CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		sendErrorDirect(send, req.ID, -32602, "Invalid params")
		return
	}

	// 1. Check if it's a Gateway tool
	if strings.HasPrefix(params.Name, "gateway__") {
		handleGatewayToolCall(params.Name, params.Arguments, req.ID, send)
		return
	}

	// 2. Otherwise route to the appropriate Agent
	parts := strings.SplitN(params.Name, "__", 2)
	if len(parts) < 2 {
		sendErrorDirect(send, req.ID, -32601, fmt.Sprintf("Invalid tool name format: %s", params.Name))
		return
	}

	agentID := parts[0]
	agentToolName := parts[1]

	// Check if this is an upstream MCP server call
	upstreamClientsMu.RLock()
	uc, isUpstream := upstreamClients[agentID]
	upstreamClientsMu.RUnlock()

	if isUpstream {
		go func() {
			forwardParams := CallToolParams{
				Name:      agentToolName,
				Arguments: params.Arguments,
			}
			forwardParamsBytes, _ := json.Marshal(forwardParams)
			upstreamReq := JsonRpcRequest{
				JsonRpc: "2.0",
				Method:  "tools/call",
				Params:  forwardParamsBytes,
				ID:      req.ID,
			}
			resp, err := uc.Call(upstreamReq)
			if err != nil {
				sendErrorDirect(send, req.ID, -32603, fmt.Sprintf("Upstream server %q call failed: %v", agentID, err))
				return
			}
			send(*resp)
		}()
		return
	}

	cli := getAgent(agentID)
	if cli == nil {
		sendErrorDirect(send, req.ID, -32603, fmt.Sprintf("Agent or upstream server %q is not connected", agentID))
		return
	}

	// Forward request over SSH channel, rewriting the tool name
	forwardParams := CallToolParams{
		Name:      agentToolName,
		Arguments: params.Arguments,
	}
	forwardParamsBytes, _ := json.Marshal(forwardParams)

	agentReq := JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  forwardParamsBytes,
		ID:      req.ID,
	}

	resp := cli.Call(agentReq)
	send(resp)
}

func handleGatewayToolCall(name string, argsRaw json.RawMessage, reqID interface{}, send ResponseSender) {
	switch name {
	case "gateway__list_agents":
		list := listAgentIDs()
		response := JsonRpcResponse{
			JsonRpc: "2.0",
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": fmt.Sprintf("Connected Agents: %s", strings.Join(list, ", ")),
					},
				},
			},
			ID: reqID,
		}
		send(response)

	case "gateway__humanize_syslog":
		var args HumanizeSyslogArgs
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			sendErrorDirect(send, reqID, -32602, "Invalid arguments")
			return
		}

		if llmCli == nil {
			sendErrorDirect(send, reqID, -32603, "Local LLM is not configured on this Gateway")
			return
		}

		humanized, err := llmCli.HumanizeLog(args.LogLine)
		if err != nil {
			sendErrorDirect(send, reqID, -32603, fmt.Sprintf("LLM error: %v", err))
			return
		}

		response := JsonRpcResponse{
			JsonRpc: "2.0",
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": humanized,
					},
				},
			},
			ID: reqID,
		}
		send(response)

	case "gateway__ask_gemma":
		var args AskGemmaArgs
		if err := json.Unmarshal(argsRaw, &args); err != nil {
			sendErrorDirect(send, reqID, -32602, "Invalid arguments")
			return
		}

		if llmCli == nil {
			sendErrorDirect(send, reqID, -32603, "Local LLM is not configured on this Gateway")
			return
		}

		cli := getAgent(args.AgentID)
		if cli == nil {
			sendErrorDirect(send, reqID, -32603, fmt.Sprintf("Agent %q is not connected", args.AgentID))
			return
		}

		// Implement Gemma-orchestrated security loop
		executeGemmaOrchestration(args.AgentID, cli, args.Prompt, reqID, send)

	default:
		sendErrorDirect(send, reqID, -32601, fmt.Sprintf("Tool not found: %s", name))
	}
}

type GemmaCommandSelection struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
}

func executeGemmaOrchestration(agentID string, cli *AgentClient, userPrompt string, reqID interface{}, send ResponseSender) {
	// 1. Get tools allowed on that agent
	agentReq := JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/list",
		ID:      fmt.Sprintf("gw-list-%s-%d", agentID, time.Now().UnixNano()),
	}
	resp := cli.Call(agentReq)
	if resp.Error != nil {
		sendErrorDirect(send, reqID, -32603, fmt.Sprintf("Failed to list agent tools: %v", resp.Error))
		return
	}

	// Prompt Gemma
	toolsJSON, _ := json.Marshal(resp.Result)
	prompt := fmt.Sprintf(`You are a system administrator assistant. The user wants to perform an action on agent "%s".
The agent exposes the following tools:
%s

The user request is: "%s"

If the request is purely informational (like getting metrics), select the tool name and arguments. If it's a command execution, select "run_command" with the appropriate command name and arguments.
You MUST respond with ONLY a JSON object in this format (no markdown formatting, no comments, no backticks, just raw JSON):
{
  "tool_name": "get_metrics" | "run_command",
  "arguments": {
    "name": "command_name_if_run_command",
    "args": ["arg1", "arg2"]
  }
}

JSON output:`, agentID, string(toolsJSON), userPrompt)

	gemmaOutput, err := llmCli.Generate(prompt)
	if err != nil {
		sendErrorDirect(send, reqID, -32603, fmt.Sprintf("LLM generation failed: %v", err))
		return
	}

	// Strip potential markdown backticks from LLM output
	cleanOutput := strings.TrimSpace(gemmaOutput)
	cleanOutput = strings.TrimPrefix(cleanOutput, "```json")
	cleanOutput = strings.TrimPrefix(cleanOutput, "```")
	cleanOutput = strings.TrimSuffix(cleanOutput, "```")
	cleanOutput = strings.TrimSpace(cleanOutput)

	var selection struct {
		ToolName  string          `json:"tool_name"`
		Arguments json.RawMessage `json:"arguments"`
	}

	if err := json.Unmarshal([]byte(cleanOutput), &selection); err != nil {
		sendErrorDirect(send, reqID, -32603, fmt.Sprintf("Gemma returned invalid plan JSON: %s. Error: %v", cleanOutput, err))
		return
	}

	// 2. Call the tool on the Agent
	callReq := JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  nil, // populated below
		ID:      reqID,
	}

	callParams := CallToolParams{
		Name:      selection.ToolName,
		Arguments: selection.Arguments,
	}
	callReq.Params, _ = json.Marshal(callParams)

	agentResp := cli.Call(callReq)

	// 3. Humanize the output back to the user
	var resultStr string
	if agentResp.Error != nil {
		errBytes, _ := json.Marshal(agentResp.Error)
		resultStr = fmt.Sprintf("Error: %s", string(errBytes))
	} else {
		// Parse response content
		var callResult struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		resultBytes, _ := json.Marshal(agentResp.Result)
		_ = json.Unmarshal(resultBytes, &callResult)
		if len(callResult.Content) > 0 {
			resultStr = callResult.Content[0].Text
		} else {
			resultStr = string(resultBytes)
		}
	}

	humanizePrompt := fmt.Sprintf(`You are a system administrator assistant. A tool command was executed on agent "%s" based on user's instruction: "%s".
The tool called was: "%s" with arguments "%s".
The execution output from the agent was:
%s

Please summarize the results in plain English, explaining if the operation succeeded, what metrics were found (if any), or why it failed. Be concise (1-3 sentences).

Summary:`, agentID, userPrompt, selection.ToolName, string(selection.Arguments), resultStr)

	summary, err := llmCli.Generate(humanizePrompt)
	if err != nil {
		// Fallback to sending the raw output
		send(agentResp)
		return
	}

	finalResponse := JsonRpcResponse{
		JsonRpc: "2.0",
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": summary,
				},
				{
					"type": "text",
					"text": fmt.Sprintf("\n[Raw Execution Output]\n%s", resultStr),
				},
			},
		},
		ID: reqID,
	}
	send(finalResponse)
}

var writeMu sync.Mutex

func sendResponse(w io.Writer, resp JsonRpcResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return
	}
	data = append(data, '\n')
	writeMu.Lock()
	_, _ = w.Write(data)
	writeMu.Unlock()
}

func sendError(w io.Writer, id interface{}, code int, message string) {
	response := JsonRpcResponse{
		JsonRpc: "2.0",
		Error: JsonRpcError{
			Code:    code,
			Message: message,
		},
		ID: id,
	}
	sendResponse(w, response)
}

func sendErrorDirect(send ResponseSender, id interface{}, code int, message string) {
	response := JsonRpcResponse{
		JsonRpc: "2.0",
		Error: JsonRpcError{
			Code:    code,
			Message: message,
		},
		ID: id,
	}
	send(response)
}

// HTTP Server and Server-Sent Events (SSE) Transport implementation
type SseSession struct {
	id        string
	writeChan chan []byte
}

var (
	sseSessions   = make(map[string]*SseSession)
	sseSessionsMu sync.Mutex
)

func startHTTPServer(cfg *config.GatewayConfig) {
	httpActive = true
	http.HandleFunc("/sse", requireAuth(handleSse))
	http.HandleFunc("/message", requireAuth(handleMessage))
	http.HandleFunc("/api/status", requireAuth(handleApiStatus))
	http.HandleFunc("/api/config", requireAuth(handleApiConfig))
	http.HandleFunc("/api/keys", requireAuth(handleApiKeys))
	http.HandleFunc("/api/call", requireAuth(handleApiCall))
	http.HandleFunc("/api/tools", requireAuth(handleApiTools))
	http.HandleFunc("/api/chat", requireAuth(handleApiChat))
	http.HandleFunc("/logo.png", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "assets/images/logo.png")
	})
	http.HandleFunc("/", handlePortal)

	var tlsConfig *tls.Config
	if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			log.Fatalf("Failed to load TLS certificate or key: %v", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	} else {
		log.Println("WARNING: No TLS certificate paths specified. Generating dynamic self-signed certificate in-memory...")
		cert, err := generateSelfSignedCert()
		if err != nil {
			log.Fatalf("Failed to generate self-signed certificate: %v", err)
		}
		tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
	}

	server := &http.Server{
		Addr:      cfg.HTTPAddr,
		TLSConfig: tlsConfig,
	}

	log.Printf("Secure HTTPS/SSE Gateway listening on https://%s...", cfg.HTTPAddr)
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("HTTPS/SSE server failed: %v", err)
	}
}

func requireAuth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		currentConfigMu.RLock()
		token := currentConfig.AuthToken
		currentConfigMu.RUnlock()

		// Skip auth if token is empty (for fallback/development only)
		if token == "" {
			handler(w, r)
			return
		}

		// Check Authorization header
		authHeader := r.Header.Get("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			if strings.TrimPrefix(authHeader, "Bearer ") == token {
				handler(w, r)
				return
			}
		}

		// Check query parameter
		if r.URL.Query().Get("token") == token {
			handler(w, r)
			return
		}

		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func generateSelfSignedCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"MCP-Hive"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	template.DNSNames = []string{"localhost", "gateway"}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPem, keyPem)
}

func handleSse(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

	sessionID := fmt.Sprintf("session-%d", time.Now().UnixNano())
	session := &SseSession{
		id:        sessionID,
		writeChan: make(chan []byte, 100),
	}

	sseSessionsMu.Lock()
	sseSessions[sessionID] = session
	sseSessionsMu.Unlock()

	defer func() {
		sseSessionsMu.Lock()
		delete(sseSessions, sessionID)
		sseSessionsMu.Unlock()
	}()

	token := r.URL.Query().Get("token")
	if token != "" {
		fmt.Fprintf(w, "event: endpoint\ndata: /message?session_id=%s&token=%s\n\n", sessionID, token)
	} else {
		fmt.Fprintf(w, "event: endpoint\ndata: /message?session_id=%s\n\n", sessionID)
	}
	flusher.Flush()

	for {
		select {
		case msg := <-session.writeChan:
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", string(msg))
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func handleMessage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		http.Error(w, "Missing session_id", http.StatusBadRequest)
		return
	}

	sseSessionsMu.Lock()
	session, exists := sseSessions[sessionID]
	sseSessionsMu.Unlock()

	if !exists {
		http.Error(w, "Invalid or expired session", http.StatusBadRequest)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Read error", http.StatusInternalServerError)
		return
	}

	var req JsonRpcRequest
	if err := json.Unmarshal(body, &req); err != nil {
		sendSseError(session, nil, -32700, "Parse error")
		w.WriteHeader(http.StatusOK)
		return
	}

	go func() {
		sendCallback := func(resp JsonRpcResponse) {
			respBytes, err := json.Marshal(resp)
			if err == nil {
				session.writeChan <- respBytes
			}
		}
		handleClientRequest(req, sendCallback)
	}()

	w.WriteHeader(http.StatusAccepted)
}

func sendSseError(session *SseSession, id interface{}, code int, message string) {
	response := JsonRpcResponse{
		JsonRpc: "2.0",
		Error: JsonRpcError{
			Code:    code,
			Message: message,
		},
		ID: id,
	}
	respBytes, err := json.Marshal(response)
	if err == nil {
		session.writeChan <- respBytes
	}
}

// Upstream SSE client implementation for connecting to other MCP servers
type UpstreamClient struct {
	Name       string
	URL        string
	Status     string // "connected", "connecting", "error: ..."
	postURL    string
	sessionID  string
	pending    map[string]chan JsonRpcResponse
	pendingMu  sync.Mutex
	httpClient *http.Client
	stopChan   chan struct{}
}

func NewUpstreamClient(name, sseURL string) *UpstreamClient {
	return &UpstreamClient{
		Name:       name,
		URL:        sseURL,
		Status:     "connecting",
		pending:    make(map[string]chan JsonRpcResponse),
		httpClient: &http.Client{Timeout: 35 * time.Second},
		stopChan:   make(chan struct{}),
	}
}

func (uc *UpstreamClient) GetName() string   { return uc.Name }
func (uc *UpstreamClient) GetStatus() string { return uc.Status }
func (uc *UpstreamClient) GetURL() string    { return uc.URL }
func (uc *UpstreamClient) Stop()             { close(uc.stopChan) }

func (uc *UpstreamClient) ConnectAndRead() {
	uc.Status = "connecting"
	resp, err := uc.httpClient.Get(uc.URL)
	if err != nil {
		uc.Status = fmt.Sprintf("error: connection failed: %v", err)
		return
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	var currentEvent string
	var currentData string
	for {
		select {
		case <-uc.stopChan:
			return
		default:
		}
		lineBytes, err := reader.ReadBytes('\n')
		if err != nil {
			uc.Status = fmt.Sprintf("error: disconnected: %v", err)
			return
		}
		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			if currentEvent == "endpoint" {
				u, err := url.Parse(currentData)
				if err != nil {
					uc.Status = fmt.Sprintf("error: invalid endpoint URL: %v", err)
					return
				}
				uc.sessionID = u.Query().Get("session_id")
				base, _ := url.Parse(uc.URL)
				uc.postURL = base.ResolveReference(u).String()
				uc.Status = "connected"
				break
			}
			currentEvent = ""
			currentData = ""
			continue
		}
		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			currentData = strings.TrimPrefix(line, "data: ")
		}
	}

	// Read events in loop
	for {
		select {
		case <-uc.stopChan:
			return
		default:
		}
		lineBytes, err := reader.ReadBytes('\n')
		if err != nil {
			uc.Status = fmt.Sprintf("error: event read error: %v", err)
			return
		}
		line := strings.TrimSpace(string(lineBytes))
		if line == "" {
			if currentEvent == "message" && currentData != "" {
				var resp JsonRpcResponse
				if err := json.Unmarshal([]byte(currentData), &resp); err == nil {
					idStr := normalizeID(resp.ID)
					uc.pendingMu.Lock()
					ch, exists := uc.pending[idStr]
					if exists {
						ch <- resp
						delete(uc.pending, idStr)
					}
					uc.pendingMu.Unlock()
				}
			}
			currentEvent = ""
			currentData = ""
			continue
		}
		if strings.HasPrefix(line, "event: ") {
			currentEvent = strings.TrimPrefix(line, "event: ")
		} else if strings.HasPrefix(line, "data: ") {
			currentData = strings.TrimPrefix(line, "data: ")
		}
	}
}

func (uc *UpstreamClient) Call(req JsonRpcRequest) (*JsonRpcResponse, error) {
	if uc.Status != "connected" {
		return nil, fmt.Errorf("upstream client is not connected (status: %s)", uc.Status)
	}
	idStr := normalizeID(req.ID)
	ch := make(chan JsonRpcResponse, 1)

	uc.pendingMu.Lock()
	uc.pending[idStr] = ch
	uc.pendingMu.Unlock()

	reqBytes, err := json.Marshal(req)
	if err != nil {
		uc.pendingMu.Lock()
		delete(uc.pending, idStr)
		uc.pendingMu.Unlock()
		return nil, err
	}

	resp, err := uc.httpClient.Post(uc.postURL, "application/json", bytes.NewReader(reqBytes))
	if err != nil {
		uc.pendingMu.Lock()
		delete(uc.pending, idStr)
		uc.pendingMu.Unlock()
		return nil, err
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		uc.pendingMu.Lock()
		delete(uc.pending, idStr)
		uc.pendingMu.Unlock()
		return nil, fmt.Errorf("non-accepted status: %d", resp.StatusCode)
	}

	select {
	case r := <-ch:
		return &r, nil
	case <-time.After(30 * time.Second):
		uc.pendingMu.Lock()
		delete(uc.pending, idStr)
		uc.pendingMu.Unlock()
		return nil, fmt.Errorf("request timed out waiting for upstream SSE response")
	}
}

// StdioUpstreamClient manages a local stdio-based external MCP server subprocess.
type StdioUpstreamClient struct {
	Name      string
	Command   string
	Args      []string
	Env       []string
	Cmd       *exec.Cmd
	Stdin     io.WriteCloser
	Stdout    io.ReadCloser
	Stderr    io.ReadCloser
	Pending   map[string]chan JsonRpcResponse
	PendingMu sync.Mutex
	Status    string // "connected", "error: ..."
	StopChan  chan struct{}
}

func NewStdioUpstreamClient(name, cmdStr string, args []string, envMap map[string]string) *StdioUpstreamClient {
	var envSlice []string
	for k, v := range envMap {
		envSlice = append(envSlice, fmt.Sprintf("%s=%s", k, v))
	}
	envSlice = append(envSlice, os.Environ()...) // inherit host environment

	return &StdioUpstreamClient{
		Name:     name,
		Command:  cmdStr,
		Args:     args,
		Env:      envSlice,
		Pending:  make(map[string]chan JsonRpcResponse),
		Status:   "disconnected",
		StopChan: make(chan struct{}),
	}
}

func (s *StdioUpstreamClient) GetName() string   { return s.Name }
func (s *StdioUpstreamClient) GetStatus() string { return s.Status }
func (s *StdioUpstreamClient) GetURL() string {
	return s.Command + " " + strings.Join(s.Args, " ")
}

func (s *StdioUpstreamClient) Start() error {
	s.Cmd = exec.Command(s.Command, s.Args...)
	s.Cmd.Env = s.Env

	var err error
	s.Stdin, err = s.Cmd.StdinPipe()
	if err != nil {
		s.Status = fmt.Sprintf("error: stdin pipe failed: %v", err)
		return err
	}

	s.Stdout, err = s.Cmd.StdoutPipe()
	if err != nil {
		s.Status = fmt.Sprintf("error: stdout pipe failed: %v", err)
		return err
	}

	s.Stderr, err = s.Cmd.StderrPipe()
	if err != nil {
		s.Status = fmt.Sprintf("error: stderr pipe failed: %v", err)
		return err
	}

	// Logging stderr
	go func() {
		scanner := bufio.NewScanner(s.Stderr)
		for scanner.Scan() {
			log.Printf("[%s STDERR] %s", s.Name, scanner.Text())
		}
	}()

	if err := s.Cmd.Start(); err != nil {
		s.Status = fmt.Sprintf("error: start failed: %v", err)
		return err
	}

	s.Status = "connected"
	log.Printf("External Stdio MCP Server %q started successfully (PID: %d)", s.Name, s.Cmd.Process.Pid)

	go s.readLoop()
	return nil
}

func (s *StdioUpstreamClient) readLoop() {
	scanner := bufio.NewScanner(s.Stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		var resp JsonRpcResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			log.Printf("[%s STDOUT] non-JSON output: %s", s.Name, string(line))
			continue
		}

		idStr := normalizeID(resp.ID)
		s.PendingMu.Lock()
		ch, exists := s.Pending[idStr]
		if exists {
			ch <- resp
			delete(s.Pending, idStr)
		}
		s.PendingMu.Unlock()
	}

	s.Status = "disconnected"
	log.Printf("External Stdio MCP Server %q process exited.", s.Name)
}

func (s *StdioUpstreamClient) Call(req JsonRpcRequest) (*JsonRpcResponse, error) {
	if s.Status != "connected" {
		return nil, fmt.Errorf("external stdio server %q is not running", s.Name)
	}

	idStr := normalizeID(req.ID)
	ch := make(chan JsonRpcResponse, 1)

	s.PendingMu.Lock()
	s.Pending[idStr] = ch
	s.PendingMu.Unlock()

	reqBytes, err := json.Marshal(req)
	if err != nil {
		s.PendingMu.Lock()
		delete(s.Pending, idStr)
		s.PendingMu.Unlock()
		return nil, err
	}

	reqBytes = append(reqBytes, '\n')
	if _, err := s.Stdin.Write(reqBytes); err != nil {
		s.PendingMu.Lock()
		delete(s.Pending, idStr)
		s.PendingMu.Unlock()
		return nil, fmt.Errorf("failed writing to stdin: %w", err)
	}

	select {
	case r := <-ch:
		return &r, nil
	case <-time.After(35 * time.Second):
		s.PendingMu.Lock()
		delete(s.Pending, idStr)
		s.PendingMu.Unlock()
		return nil, fmt.Errorf("request timed out awaiting stdio response")
	}
}

func (s *StdioUpstreamClient) Stop() {
	close(s.StopChan)
	if s.Stdin != nil {
		s.Stdin.Close()
	}
	if s.Cmd != nil && s.Cmd.Process != nil {
		s.Cmd.Process.Kill()
	}
}

func reloadUpstreamClients(cfg *config.GatewayConfig) {
	upstreamClientsMu.Lock()
	defer upstreamClientsMu.Unlock()

	// Stop existing ones
	for _, uc := range upstreamClients {
		uc.Stop()
	}
	upstreamClients = make(map[string]UpstreamCaller)

	// Start new ones (Legacy list)
	for _, s := range cfg.UpstreamServers {
		uc := NewUpstreamClient(s.Name, s.URL)
		upstreamClients[s.Name] = uc
		go func(client *UpstreamClient) {
			for {
				select {
				case <-client.stopChan:
					return
				default:
					client.ConnectAndRead()
					// Retry after 5 seconds if disconnected
					time.Sleep(5 * time.Second)
				}
			}
		}(uc)
	}

	// Start new ones (Extended external_mcp_servers list)
	for _, s := range cfg.ExternalMcpServers {
		if s.Transport == "sse" {
			uc := NewUpstreamClient(s.Name, s.URL)
			upstreamClients[s.Name] = uc
			go func(client *UpstreamClient) {
				for {
					select {
					case <-client.stopChan:
						return
					default:
						client.ConnectAndRead()
						time.Sleep(5 * time.Second)
					}
				}
			}(uc)
		} else if s.Transport == "stdio" {
			suc := NewStdioUpstreamClient(s.Name, s.Command, s.Args, s.Env)
			upstreamClients[s.Name] = suc
			err := suc.Start()
			if err != nil {
				log.Printf("Failed to start local external stdio MCP server %q: %v", s.Name, err)
			}
		}
	}
}

func reloadGatewaySettings(newCfg *config.GatewayConfig) {
	currentConfigMu.Lock()
	currentConfig = newCfg
	currentConfigMu.Unlock()

	// Reload LLM client
	if newCfg.OllamaURL != "" {
		llmCli = llm.NewClient(newCfg.OllamaURL, newCfg.OllamaModel)
		log.Printf("Reloaded LLM client (Ollama model: %s at %s)", newCfg.OllamaModel, newCfg.OllamaURL)
	} else {
		llmCli = nil
	}
	// Reload Upstream SSE clients
	reloadUpstreamClients(newCfg)
}

// HTTP API Handlers for Portal Management
func handleApiStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	type AgentStatusInfo struct {
		ID              string   `json:"id"`
		IP              string   `json:"ip"`
		OSVersion       string   `json:"os_version"`
		RunningServices []string `json:"running_services"`
		OpenPorts       []string `json:"open_ports"`
	}

	agentsMu.RLock()
	agentList := make([]AgentStatusInfo, 0, len(agents))
	for _, client := range agents {
		client.mu.Lock()
		info := AgentStatusInfo{
			ID:              client.agentID,
			IP:              client.ipAddress,
			OSVersion:       client.osVersion,
			RunningServices: client.runningServices,
			OpenPorts:       client.openPorts,
		}
		if info.OSVersion == "" {
			info.OSVersion = "Loading..."
		}
		client.mu.Unlock()
		agentList = append(agentList, info)
	}
	agentsMu.RUnlock()

	upstreamClientsMu.RLock()
	type UpstreamStatus struct {
		Name   string `json:"name"`
		URL    string `json:"url"`
		Status string `json:"status"`
	}
	upstreams := make([]UpstreamStatus, 0, len(upstreamClients))
	for name, uc := range upstreamClients {
		upstreams = append(upstreams, UpstreamStatus{
			Name:   name,
			URL:    uc.GetURL(),
			Status: uc.GetStatus(),
		})
	}
	upstreamClientsMu.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"agents":    agentList,
		"upstreams": upstreams,
	})
}

func handleApiConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method == http.MethodGet {
		currentConfigMu.RLock()
		cfg := currentConfig
		currentConfigMu.RUnlock()
		json.NewEncoder(w).Encode(cfg)
		return
	}

	if r.Method == http.MethodPost {
		var newCfg config.GatewayConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, "Invalid configuration JSON", http.StatusBadRequest)
			return
		}

		// Enforce HTTPS on all upstream connections
		for _, s := range newCfg.UpstreamServers {
			if !strings.HasPrefix(strings.ToLower(s.URL), "https://") {
				http.Error(w, fmt.Sprintf("Upstream connection %q URL must use secure HTTPS", s.Name), http.StatusForbidden)
				return
			}
		}

		// Write to disk if we have a configFilePath
		if configFilePath != "" {
			fileBytes, err := json.MarshalIndent(newCfg, "", "  ")
			if err != nil {
				http.Error(w, "Failed to serialize configuration", http.StatusInternalServerError)
				return
			}
			if err := os.WriteFile(configFilePath, fileBytes, 0644); err != nil {
				http.Error(w, fmt.Sprintf("Failed to write config file: %v", err), http.StatusInternalServerError)
				return
			}
		}

		reloadGatewaySettings(&newCfg)
		json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "config": newCfg})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleApiKeys(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	currentConfigMu.RLock()
	keysPath := currentConfig.AuthorizedKeysPath
	currentConfigMu.RUnlock()

	if keysPath == "" {
		http.Error(w, "AuthorizedKeysPath is not configured", http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		content, err := os.ReadFile(keysPath)
		if err != nil && !os.IsNotExist(err) {
			http.Error(w, fmt.Sprintf("Failed to read authorized keys file: %v", err), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"keys": string(content)})
		return
	}

	if r.Method == http.MethodPost {
		var body struct {
			Keys string `json:"keys"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}

		if err := os.WriteFile(keysPath, []byte(body.Keys), 0600); err != nil {
			http.Error(w, fmt.Sprintf("Failed to write authorized keys: %v", err), http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func handleApiCall(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	argsBytes, _ := json.Marshal(body.Arguments)
	callParams := CallToolParams{
		Name:      body.Name,
		Arguments: argsBytes,
	}
	callParamsBytes, _ := json.Marshal(callParams)
	req := JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  callParamsBytes,
		ID:      "api-" + fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	done := make(chan JsonRpcResponse, 1)
	sendCallback := func(resp JsonRpcResponse) {
		done <- resp
	}
	go handleClientRequest(req, sendCallback)

	select {
	case resp := <-done:
		json.NewEncoder(w).Encode(resp)
	case <-time.After(35 * time.Second):
		http.Error(w, "Request timed out", http.StatusGatewayTimeout)
	}
}

func handleApiTools(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	done := make(chan JsonRpcResponse, 1)
	sendCallback := func(resp JsonRpcResponse) {
		done <- resp
	}
	req := JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/list",
		ID:      "api-tools-" + fmt.Sprintf("%d", time.Now().UnixNano()),
	}
	go handleListTools(req, sendCallback)

	select {
	case resp := <-done:
		if resp.Error != nil {
			http.Error(w, fmt.Sprintf("Error listing tools: %v", resp.Error), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp.Result)
	case <-time.After(35 * time.Second):
		http.Error(w, "Request timed out", http.StatusGatewayTimeout)
	}
}

type ChatMessage struct {
	Role string `json:"role"`
	Text string `json:"text"`
}

type ChatRequest struct {
	Provider string        `json:"provider"`
	Prompt   string        `json:"prompt"`
	History  []ChatMessage `json:"history,omitempty"`
	System   string        `json:"system,omitempty"`
}

func handleApiChat(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ChatRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	currentConfigMu.RLock()
	token := currentConfig.AntigravityToken
	ollamaURL := currentConfig.OllamaURL
	ollamaModel := currentConfig.OllamaModel
	currentConfigMu.RUnlock()

	var replyText string
	var err error

	if req.Provider == "antigravity" || req.Provider == "gemini" {
		if token == "" {
			http.Error(w, "Antigravity Token is not configured in settings", http.StatusBadRequest)
			return
		}
		replyText, err = callGeminiAPI(token, req.System, req.Prompt, req.History)
	} else {
		// Use Ollama (Gemma)
		if ollamaURL == "" {
			http.Error(w, "Ollama URL is not configured", http.StatusBadRequest)
			return
		}
		fullPrompt := ""
		if req.System != "" {
			fullPrompt += "System Instruction:\n" + req.System + "\n\n"
		}
		for _, msg := range req.History {
			fullPrompt += msg.Role + ": " + msg.Text + "\n"
		}
		fullPrompt += "user: " + req.Prompt + "\nassistant:"

		var cli *llm.Client
		if llmCli != nil {
			cli = llmCli
		} else {
			cli = llm.NewClient(ollamaURL, ollamaModel)
		}
		replyText, err = cli.Generate(fullPrompt)
	}

	if err != nil {
		http.Error(w, fmt.Sprintf("LLM generation failed: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"response": replyText})
}

func callGeminiAPI(token, systemPrompt, prompt string, history []ChatMessage) (string, error) {
	type Part struct {
		Text string `json:"text"`
	}
	type Content struct {
		Role  string `json:"role"`
		Parts []Part `json:"parts"`
	}
	type SystemInstruction struct {
		Parts []Part `json:"parts"`
	}
	type GeminiRequest struct {
		Contents          []Content          `json:"contents"`
		SystemInstruction *SystemInstruction `json:"systemInstruction,omitempty"`
	}

	var contents []Content
	for _, m := range history {
		role := m.Role
		if role == "assistant" || role == "model" {
			role = "model"
		} else {
			role = "user"
		}
		contents = append(contents, Content{
			Role:  role,
			Parts: []Part{{Text: m.Text}},
		})
	}
	contents = append(contents, Content{
		Role:  "user",
		Parts: []Part{{Text: prompt}},
	})

	geminiReq := GeminiRequest{
		Contents: contents,
	}

	if systemPrompt != "" {
		geminiReq.SystemInstruction = &SystemInstruction{
			Parts: []Part{{Text: systemPrompt}},
		}
	}

	reqBytes, err := json.Marshal(geminiReq)
	if err != nil {
		return "", err
	}

	apiURL := "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=" + token
	resp, err := http.Post(apiURL, "application/json", bytes.NewReader(reqBytes))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Gemini API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	type Candidate struct {
		Content struct {
			Parts []Part `json:"parts"`
		} `json:"content"`
	}
	type GeminiResponse struct {
		Candidates []Candidate `json:"candidates"`
	}

	var geminiResp GeminiResponse
	if err := json.NewDecoder(resp.Body).Decode(&geminiResp); err != nil {
		return "", err
	}

	if len(geminiResp.Candidates) == 0 || len(geminiResp.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("no content generated by Gemini")
	}

	return geminiResp.Candidates[0].Content.Parts[0].Text, nil
}

func handlePortal(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(PortalHTML))
}

const PortalHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Myrmex Hive Gateway Control Center</title>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #1d2021;
            --bg-secondary: #282828;
            --border-color: #3c3836;
            --text-primary: #ebdbb2;
            --text-secondary: #a89984;
            --accent: #fe8019;
            --accent-hover: #fabd2f;
            --success: #b8bb26;
            --danger: #fb4934;
            --warning: #fabd2f;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: 'Fira Code', 'Courier New', monospace;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        header {
            background-color: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 15px 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .logo-section {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .logo-icon {
            font-size: 24px;
        }

        .logo-title {
            font-size: 20px;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent), var(--accent-hover));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .status-badge {
            display: flex;
            align-items: center;
            gap: 8px;
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.3);
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: 500;
            color: var(--success);
        }

        .pulse {
            width: 8px;
            height: 8px;
            background-color: var(--success);
            border-radius: 50%;
            box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
            animation: pulse 1.5s infinite;
        }

        @keyframes pulse {
            0% {
                transform: scale(0.95);
                box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
            }
            70% {
                transform: scale(1);
                box-shadow: 0 0 0 6px rgba(16, 185, 129, 0);
            }
            100% {
                transform: scale(0.95);
                box-shadow: 0 0 0 0 rgba(16, 185, 129, 0);
            }
        }

        .nav-tabs {
            display: flex;
            gap: 10px;
            margin: 20px 30px 0 30px;
            border-bottom: 1px solid var(--border-color);
        }

        .tab-btn {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            padding: 12px 24px;
            font-size: 15px;
            font-weight: 500;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            transition: all 0.2s ease;
        }

        .tab-btn:hover {
            color: var(--text-primary);
        }

        .tab-btn.active {
            color: var(--accent);
            border-bottom-color: var(--accent);
        }

        main {
            padding: 30px;
            flex-grow: 1;
            display: flex;
            flex-direction: column;
        }

        .tab-content {
            display: none;
            flex-grow: 1;
            animation: fadeIn 0.3s ease;
        }

        .tab-content.active {
            display: flex;
            flex-direction: column;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .grid-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 24px;
            margin-bottom: 30px;
        }

        .card {
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
            transition: all 0.2s ease;
        }

        .card:hover {
            border-color: rgba(0, 240, 255, 0.4);
            transform: translateY(-2px);
        }

        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 12px;
        }

        .card-title {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
        }

        .card-value {
            font-size: 28px;
            font-weight: 700;
            color: var(--accent);
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-size: 14px;
            font-weight: 500;
            color: var(--text-secondary);
        }

        .form-control {
            width: 100%;
            background-color: rgba(11, 15, 25, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 12px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 14px;
            transition: all 0.2s ease;
        }

        .form-control:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 8px rgba(0, 240, 255, 0.2);
        }

        textarea.form-control {
            resize: vertical;
            min-height: 120px;
        }

        .btn {
            background-color: var(--accent);
            color: #0b0f19;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn:hover {
            background-color: var(--accent-hover);
            box-shadow: 0 0 12px rgba(0, 240, 255, 0.3);
        }

        .btn-danger {
            background-color: var(--danger);
            color: white;
        }

        .btn-danger:hover {
            background-color: #dc2626;
            box-shadow: 0 0 12px rgba(239, 68, 68, 0.3);
        }

        .btn-secondary {
            background-color: transparent;
            border: 1px solid var(--border-color);
            color: var(--text-primary);
        }

        .btn-secondary:hover {
            background-color: rgba(255, 255, 255, 0.05);
            border-color: var(--text-secondary);
            box-shadow: none;
        }

        .alert {
            padding: 14px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 14px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .alert-success {
            background-color: rgba(16, 185, 129, 0.1);
            border: 1px solid var(--success);
            color: var(--success);
        }

        .alert-danger {
            background-color: rgba(239, 68, 68, 0.1);
            border: 1px solid var(--danger);
            color: var(--danger);
        }

        /* Playground Layout */
        .playground-container {
            display: grid;
            grid-template-columns: 400px 1fr;
            gap: 30px;
            flex-grow: 1;
        }

        @media (max-width: 960px) {
            .playground-container {
                grid-template-columns: 1fr;
            }
        }

        .terminal-container {
            display: flex;
            flex-direction: column;
            flex-grow: 1;
            background-color: #05070c;
            border: 1px solid var(--border-color);
            border-radius: 12px;
            overflow: hidden;
            min-height: 400px;
        }

        .terminal-header {
            background-color: rgba(21, 27, 44, 0.8);
            border-bottom: 1px solid var(--border-color);
            padding: 10px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 13px;
            color: var(--text-secondary);
        }

        .terminal-body {
            flex-grow: 1;
            padding: 20px;
            font-family: 'Fira Code', monospace;
            font-size: 14px;
            line-height: 1.6;
            overflow-y: auto;
            white-space: pre-wrap;
            color: #d1d5db;
        }

        /* Lists and Tables */
        .item-list {
            list-style: none;
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .item-row {
            background-color: rgba(11, 15, 25, 0.4);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 14px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .item-name {
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .item-meta {
            font-size: 13px;
            color: var(--text-secondary);
        }

        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
        }

        .status-dot.connected { background-color: var(--success); }
        .status-dot.connecting { background-color: var(--warning); animation: pulse-warning 1.5s infinite; }
        .status-dot.error { background-color: var(--danger); }

        @keyframes pulse-warning {
            0% { transform: scale(0.95); opacity: 0.5; }
            50% { transform: scale(1.1); opacity: 1; }
            100% { transform: scale(0.95); opacity: 0.5; }
        }

        .upstream-actions {
            display: flex;
            gap: 8px;
        }

        .spinner {
            width: 16px;
            height: 16px;
            border: 2px solid rgba(255,255,255,0.2);
            border-top: 2px solid white;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
            display: inline-block;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Agent Details Drawer */
        #agent-details-drawer {
            position: fixed;
            top: 0;
            left: -400px;
            width: 380px;
            height: 100%;
            background-color: var(--bg-secondary);
            border-right: 1px solid var(--border-color);
            box-shadow: 10px 0 30px rgba(0, 0, 0, 0.5);
            z-index: 998;
            transition: left 0.3s cubic-bezier(0.165, 0.84, 0.44, 1);
            display: flex;
            flex-direction: column;
            padding: 20px;
        }

        #agent-details-drawer.open {
            left: 0;
        }

        .drawer-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 15px;
            margin-bottom: 20px;
        }

        .drawer-body {
            flex-grow: 1;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        .drawer-section h4 {
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--text-secondary);
            margin-bottom: 10px;
            border-left: 3px solid var(--accent);
            padding-left: 8px;
        }

        .drawer-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        .drawer-table td {
            padding: 8px 0;
            border-bottom: 1px solid rgba(255, 255, 255, 0.02);
        }

        .drawer-table td:first-child {
            color: var(--text-secondary);
            width: 110px;
        }

        .tag-container {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 5px;
        }

        .svc-tag {
            background-color: rgba(0, 240, 255, 0.05);
            border: 1px solid rgba(0, 240, 255, 0.2);
            color: var(--accent);
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 12px;
            font-family: 'Fira Code', monospace;
        }

        .port-tag {
            background-color: rgba(16, 185, 129, 0.05);
            border: 1px solid rgba(16, 185, 129, 0.2);
            color: var(--success);
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 12px;
            font-family: 'Fira Code', monospace;
        }

        /* Metric Progress Bars and Load Cards */
        .metric-bar-container {
            margin-bottom: 12px;
        }
        .metric-label-row {
            display: flex;
            justify-content: space-between;
            font-size: 12px;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }
        .metric-bar-bg {
            height: 8px;
            background-color: rgba(255, 255, 255, 0.05);
            border-radius: 4px;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.05);
        }
        .metric-bar-fill {
            height: 100%;
            width: 0%;
            background: linear-gradient(90deg, var(--accent) 0%, #00bcff 100%);
            border-radius: 4px;
            transition: width 0.5s ease-in-out;
        }
        .metric-bar-fill.warning {
            background: linear-gradient(90deg, #ff9f43 0%, #ffc048 100%);
        }
        .metric-bar-fill.danger {
            background: linear-gradient(90deg, #ea5455 0%, #ff7675 100%);
        }
        .load-cards-row {
            display: flex;
            gap: 10px;
            margin-bottom: 12px;
        }
        .load-card {
            flex: 1;
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid var(--border-color);
            padding: 8px;
            border-radius: 6px;
            text-align: center;
        }
        .load-card-val {
            font-size: 16px;
            font-weight: 700;
            color: var(--accent);
            margin-top: 4px;
        }
        .load-card-lbl {
            font-size: 10px;
            color: var(--text-secondary);
            text-transform: uppercase;
        }

        /* Assistant FAB Button */
        #assistant-fab-btn {
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: var(--bg-secondary);
            color: var(--accent);
            border: 1px solid var(--accent);
            font-family: 'Fira Code', 'Courier New', monospace;
            font-weight: bold;
            font-size: 22px;
            width: 50px;
            height: 50px;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 4px;
            cursor: pointer;
            box-shadow: 0 4px 20px rgba(254, 128, 25, 0.2);
            z-index: 999;
            transition: all 0.2s ease;
        }

        #assistant-fab-btn:hover {
            background: var(--accent);
            color: var(--bg-primary);
            box-shadow: 0 6px 24px rgba(254, 128, 25, 0.4);
        }

        /* Assistant Window */
        #assistant-window {
            position: fixed;
            bottom: 105px;
            right: 30px;
            width: 420px;
            height: 550px;
            background-color: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.5);
            display: none;
            flex-direction: column;
            overflow: hidden;
            z-index: 999;
            animation: slideUp 0.3s cubic-bezier(0.165, 0.84, 0.44, 1);
            backdrop-filter: blur(10px);
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(20px) scale(0.95); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .assistant-header {
            padding: 16px;
            border-bottom: 1px solid var(--border-color);
            background: rgba(21, 27, 44, 0.9);
            display: flex;
            flex-direction: column;
            gap: 12px;
        }

        .assistant-title-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-weight: 600;
        }

        .assistant-controls-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .close-btn {
            background: transparent;
            border: none;
            color: var(--text-secondary);
            font-size: 20px;
            cursor: pointer;
            transition: color 0.2s;
        }

        .close-btn:hover {
            color: var(--danger);
        }

        #assistant-chat-log {
            flex-grow: 1;
            padding: 16px;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 12px;
            background: rgba(11, 15, 25, 0.3);
        }

        .ast-msg {
            padding: 10px 14px;
            border-radius: 12px;
            max-width: 85%;
            font-size: 14px;
            line-height: 1.4;
            word-break: break-word;
        }

        .ast-msg h1, .ast-msg h2, .ast-msg h3, .ast-msg h4 {
            margin-top: 8px;
            margin-bottom: 4px;
            color: var(--accent);
        }
        .ast-msg h1 { font-size: 1.15rem; }
        .ast-msg h2 { font-size: 1.05rem; }
        .ast-msg h3 { font-size: 0.95rem; }
        .ast-msg h4 { font-size: 0.85rem; }
        .ast-msg ul, .ast-msg ol {
            margin-left: 20px;
            margin-bottom: 6px;
        }
        .ast-msg li {
            margin-bottom: 3px;
        }
        .ast-msg code {
            font-family: 'Fira Code', monospace;
            background-color: rgba(255, 255, 255, 0.08);
            padding: 2px 5px;
            border-radius: 3px;
            font-size: 0.9em;
            color: var(--accent-hover);
        }
        .ast-msg pre {
            background-color: rgba(0, 0, 0, 0.25);
            border: 1px solid var(--border-color);
            padding: 6px 10px;
            border-radius: 4px;
            overflow-x: auto;
            margin: 6px 0;
        }
        .ast-msg pre code {
            background-color: transparent;
            padding: 0;
            color: var(--text-primary);
        }

        .ast-msg.user {
            background-color: var(--accent);
            color: #0b0f19;
            align-self: flex-end;
            border-bottom-right-radius: 2px;
        }

        .ast-msg.assistant {
            background-color: rgba(255, 255, 255, 0.05);
            color: var(--text-primary);
            border: 1px solid var(--border-color);
            align-self: flex-start;
            border-bottom-left-radius: 2px;
        }

        .ast-msg.system {
            background-color: rgba(245, 158, 11, 0.1);
            color: var(--warning);
            border: 1px solid rgba(245, 158, 11, 0.2);
            align-self: center;
            font-size: 13px;
            text-align: center;
            max-width: 95%;
        }

        .ast-msg.agent-action {
            background-color: rgba(0, 240, 255, 0.05);
            color: var(--accent);
            border: 1px solid rgba(0, 240, 255, 0.2);
            align-self: center;
            font-size: 13px;
            font-family: 'Fira Code', monospace;
            max-width: 95%;
            display: flex;
            flex-direction: column;
            gap: 6px;
        }

        .assistant-input-area {
            padding: 12px 16px;
            border-top: 1px solid var(--border-color);
            background: rgba(21, 27, 44, 0.9);
            display: flex;
            gap: 8px;
            align-items: center;
        }

        #assistant-input-field {
            flex-grow: 1;
            background-color: rgba(11, 15, 25, 0.6);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 8px 12px;
            color: var(--text-primary);
            font-family: inherit;
            font-size: 14px;
            outline: none;
        }

        #assistant-input-field:focus {
            border-color: var(--accent);
        }

        #ast-mic-btn {
            background: transparent;
            border: 1px solid var(--border-color);
            border-radius: 4px;
            width: auto;
            min-width: 55px;
            padding: 0 10px;
            height: 36px;
            font-family: inherit;
            font-weight: bold;
            font-size: 11px;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            transition: all 0.2s;
            color: var(--text-secondary);
        }

        #ast-mic-btn:hover {
            border-color: var(--accent);
            color: var(--accent);
        }

        #ast-mic-btn.mic-active {
            background: rgba(239, 68, 68, 0.2);
            border-color: var(--danger);
            color: var(--danger);
            animation: micPulse 1.5s infinite;
        }

        @keyframes micPulse {
            0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
            70% { box-shadow: 0 0 0 8px rgba(239, 68, 68, 0); }
            100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
        }
    </style>
</head>
<body>
    <header>
        <div class="logo-section">
            <img src="/logo.png" alt="Myrmex Hive" style="width: 32px; height: 32px; border: 1px solid var(--accent); border-radius: 4px; image-rendering: pixelated; display: block;">
            <div class="logo-title">Myrmex Hive Gateway</div>
        </div>
        <div class="status-badge">
            <span class="pulse"></span>
            <span>Gateway Active</span>
        </div>
    </header>

    <div class="nav-tabs">
        <button class="tab-btn active" onclick="switchTab('dashboard')">Dashboard</button>
        <button class="tab-btn" onclick="switchTab('playground')">Playground</button>
        <button class="tab-btn" onclick="switchTab('keys')">SSH Authorized Keys</button>
        <button class="tab-btn" onclick="switchTab('config')">Configuration</button>
    </div>

    <main>
        <!-- Dashboard Tab -->
        <div id="dashboard" class="tab-content active">
            <div class="grid-container">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Connected Edge Agents</span>
                    </div>
                    <span class="card-value" id="count-agents">0</span>
                </div>
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Upstream MCP Servers</span>
                    </div>
                    <span class="card-value" id="count-upstreams">0</span>
                </div>
            </div>

            <div class="grid-container" style="grid-template-columns: 1fr 1fr; gap: 30px;">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Edge Node Connections (Secure Outbound Tunnel)</span>
                    </div>
                    <ul class="item-list" id="agents-list">
                        <li class="item-row"><span class="item-name">No agents connected. Connect agents outbound to port 2222.</span></li>
                    </ul>
                </div>
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Upstream Connections (SSE Clients)</span>
                    </div>
                    <ul class="item-list" id="upstreams-list">
                        <li class="item-row"><span class="item-name">No upstream servers configured.</span></li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- Playground Tab -->
        <div id="playground" class="tab-content">
            <div class="playground-container">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Execute MCP Tools</span>
                    </div>
                    <div class="form-group">
                        <label for="play-tool">Select Target Tool</label>
                        <select id="play-tool" class="form-control" onchange="onToolSelect()">
                            <option value="">-- Load tools first --</option>
                        </select>
                    </div>
                    <div class="form-group" id="tool-description-box" style="display:none; margin-bottom: 15px;">
                        <span style="font-size: 13px; color: var(--text-secondary); line-height: 1.4;" id="tool-description"></span>
                    </div>
                    <div class="form-group">
                        <label for="play-args">Arguments (JSON)</label>
                        <textarea id="play-args" class="form-control" style="font-family: 'Fira Code', monospace; min-height: 150px;">{}</textarea>
                    </div>
                    <button class="btn" id="run-btn" onclick="callTool()">
                        <span>Execute Tool</span>
                    </button>
                </div>

                <div class="terminal-container">
                    <div class="terminal-header">
                        <span>Console Output</span>
                        <span id="response-status">Idle</span>
                    </div>
                    <div class="terminal-body" id="terminal-out">Waiting for command...</div>
                </div>
            </div>
        </div>

        <!-- SSH Keys Tab -->
        <div id="keys" class="tab-content">
            <div class="card" style="width: 100%; flex-grow: 1; display: flex; flex-direction: column;">
                <div class="card-header">
                    <span class="card-title">Manage SSH Public Keys</span>
                </div>
                <div style="margin-bottom: 15px; font-size: 14px; color: var(--text-secondary);">
                    Paste public keys of agents authorized to connect to the Gateway (one key per line).
                </div>
                <div id="keys-alert"></div>
                <div class="form-group" style="flex-grow: 1; display: flex; flex-direction: column; margin-bottom: 24px;">
                    <textarea id="ssh-keys-area" class="form-control" style="font-family: 'Fira Code', monospace; flex-grow: 1; min-height: 250px;"></textarea>
                </div>
                <div>
                    <button class="btn" onclick="saveKeys()" id="save-keys-btn">Save Authorized Keys</button>
                </div>
            </div>
        </div>

        <!-- Config Tab -->
        <div id="config" class="tab-content">
            <div class="grid-container" style="grid-template-columns: 1fr 1fr; gap: 30px;">
                <div class="card">
                    <div class="card-header">
                        <span class="card-title">Gateway Settings</span>
                    </div>
                    <div id="config-alert"></div>
                    <div class="form-group">
                        <label for="cfg-listen">SSH Listener Address</label>
                        <input type="text" id="cfg-listen" class="form-control" placeholder=":2222">
                        <span style="font-size: 11px; color: var(--text-secondary); margin-top: 4px; display: block;">Requires process restart to apply changes.</span>
                    </div>
                    <div class="form-group">
                        <label for="cfg-http">HTTP Listener Address</label>
                        <input type="text" id="cfg-http" class="form-control" placeholder=":8080">
                        <span style="font-size: 11px; color: var(--text-secondary); margin-top: 4px; display: block;">Requires process restart to apply changes.</span>
                    </div>
                    <div class="form-group">
                        <label for="cfg-ollama-url">Ollama Server URL</label>
                        <input type="text" id="cfg-ollama-url" class="form-control" placeholder="http://p510.tail833f7.ts.net:11434">
                    </div>
                    <div class="form-group">
                        <label for="cfg-ollama-model">Ollama Model</label>
                        <input type="text" id="cfg-ollama-model" class="form-control" placeholder="gemma4:e4b">
                    </div>
                    <div class="form-group">
                        <label for="cfg-antigravity-token">Antigravity Token (Gemini API Key)</label>
                        <input type="password" id="cfg-antigravity-token" class="form-control" placeholder="AIzaSy...">
                    </div>
                    <button class="btn" onclick="saveConfig()">Save Settings</button>
                </div>

                <div class="card" style="display: flex; flex-direction: column; gap: 20px;">
                    <div>
                        <div class="card-header">
                            <span class="card-title">Add External / Upstream MCP Connection</span>
                        </div>
                        <div id="upstream-alert"></div>
                        <div class="form-group">
                            <label for="up-name">Server Name (alphanumeric, e.g. "gcp")</label>
                            <input type="text" id="up-name" class="form-control" placeholder="gcp">
                        </div>
                        <div class="form-group">
                            <label for="up-transport">Transport Type</label>
                            <select id="up-transport" class="form-control" onchange="toggleTransportFields()">
                                <option value="sse">Remote SSE Connection (HTTPS)</option>
                                <option value="stdio">Local Stdio Subprocess (Command)</option>
                            </select>
                        </div>
                        <div id="sse-fields">
                            <div class="form-group">
                                <label for="up-url">SSE Connection URL</label>
                                <input type="text" id="up-url" class="form-control" placeholder="https://192.168.1.50:8080/sse">
                            </div>
                        </div>
                        <div id="stdio-fields" style="display: none;">
                            <div class="form-group">
                                <label for="up-cmd">Subprocess Command</label>
                                <input type="text" id="up-cmd" class="form-control" placeholder="npx">
                            </div>
                            <div class="form-group">
                                <label for="up-args">Arguments (space separated)</label>
                                <input type="text" id="up-args" class="form-control" placeholder="-y @modelcontextprotocol/server-gcp">
                            </div>
                            <div class="form-group">
                                <label for="up-env">Environment Variables (key=val, comma-separated)</label>
                                <input type="text" id="up-env" class="form-control" placeholder="GOOGLE_APPLICATION_CREDENTIALS=/app/gcp-credentials.json">
                            </div>
                        </div>
                        <button class="btn" onclick="addUpstream()">Register Server</button>
                    </div>

                    <div style="border-top: 1px solid var(--border-color); padding-top: 20px;">
                        <div class="card-header" style="margin-bottom: 12px; padding-bottom: 6px;">
                            <span class="card-title" style="font-size: 14px;">WebMCP Integration Connection</span>
                        </div>
                        <div style="font-size: 13px; line-height: 1.5; color: var(--text-secondary);">
                            <p style="margin-bottom: 8px;">Connect external MCP clients securely via WebMCP SSE:</p>
                            <div style="background: rgba(0, 240, 255, 0.05); border: 1px solid var(--border-color); padding: 10px; border-radius: 6px; font-family: 'Fira Code', monospace; font-size: 11px; word-break: break-all; margin-bottom: 8px;" id="webmcp-connection-string">
                                https://localhost:8080/sse?token=YOUR_TOKEN
                            </div>
                            <p style="font-size: 11px; color: var(--warning);">⚠️ Note: Enforce TLS/HTTPS at all times. Connection is authenticated via the token query parameter.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <div id="login-modal" style="display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(29, 32, 33, 0.98); z-index: 1000; justify-content: center; align-items: center; flex-direction: column;">
        <div class="card" style="width: 400px; text-align: center; border-color: var(--accent);">
            <div class="logo-section" style="justify-content: center; margin-bottom: 20px;">
                <img src="/logo.png" alt="Myrmex Hive" style="width: 48px; height: 48px; border: 1px solid var(--accent); border-radius: 4px; image-rendering: pixelated; display: block; margin-right: 10px;">
                <div class="logo-title">Myrmex Hive Access</div>
            </div>
            <p style="font-size: 14px; color: var(--text-secondary); margin-bottom: 20px;">Please enter the secure Gateway Auth Token to continue.</p>
            <div class="form-group">
                <input type="password" id="login-token-input" class="form-control" placeholder="Paste Auth Token..." style="text-align: center;">
            </div>
            <button class="btn" onclick="submitLoginToken()" style="width: 100%;">Connect</button>
        </div>
    </div>

    <!-- Agent Details Drawer (Left Side) -->
    <div id="agent-details-drawer">
        <div class="drawer-header">
            <span id="drawer-agent-title" style="font-size: 15px; font-weight: 700; color: var(--accent); display: flex; align-items: center; gap: 8px;">[Agent Details]</span>
            <button class="close-btn" onclick="closeAgentDetails()">&times;</button>
        </div>
        <div class="drawer-body">
            <div class="drawer-section">
                <h4>System Information</h4>
                <table class="drawer-table">
                    <tr><td><strong>Agent ID:</strong></td><td id="det-id">-</td></tr>
                    <tr><td><strong>IP Address:</strong></td><td id="det-ip">-</td></tr>
                    <tr><td><strong>OS Version:</strong></td><td id="det-os">-</td></tr>
                </table>
            </div>

            <div class="drawer-section" id="det-metrics-section">
                <h4>System Load & Usage</h4>
                <div id="det-metrics-loading" style="font-size:13px; color:var(--text-secondary);">Loading metrics...</div>
                <div id="det-metrics-content" style="display: none;">
                    <div class="load-cards-row">
                        <div class="load-card">
                            <div class="load-card-lbl">1 min</div>
                            <div class="load-card-val" id="det-load-1m">-</div>
                        </div>
                        <div class="load-card">
                            <div class="load-card-lbl">5 min</div>
                            <div class="load-card-val" id="det-load-5m">-</div>
                        </div>
                        <div class="load-card">
                            <div class="load-card-lbl">15 min</div>
                            <div class="load-card-val" id="det-load-15m">-</div>
                        </div>
                    </div>
                    
                    <div class="metric-bar-container">
                        <div class="metric-label-row">
                            <span>CPU Usage</span>
                            <span id="det-cpu-val">-</span>
                        </div>
                        <div class="metric-bar-bg">
                            <div class="metric-bar-fill" id="det-cpu-fill"></div>
                        </div>
                    </div>
                    
                    <div class="metric-bar-container">
                        <div class="metric-label-row">
                            <span>Memory Usage</span>
                            <span id="det-mem-val">-</span>
                        </div>
                        <div class="metric-bar-bg">
                            <div class="metric-bar-fill" id="det-mem-fill"></div>
                        </div>
                    </div>
                    
                    <div class="metric-bar-container">
                        <div class="metric-label-row">
                            <span>Disk Usage</span>
                            <span id="det-disk-val">-</span>
                        </div>
                        <div class="metric-bar-bg">
                            <div class="metric-bar-fill" id="det-disk-fill"></div>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="drawer-section">
                <h4>Running Services</h4>
                <div class="tag-container" id="det-services">
                    <!-- populated dynamically -->
                </div>
            </div>

            <div class="drawer-section">
                <h4>Open TCP Ports</h4>
                <div class="tag-container" id="det-ports">
                    <!-- populated dynamically -->
                </div>
            </div>
        </div>
    </div>

    <!-- Assistant FAB & Window -->
    <button id="assistant-fab-btn" onclick="toggleAssistant()" title="Open Myrmex Assistant">🤖</button>
    <div id="assistant-window">
        <div class="assistant-header">
            <div class="assistant-title-row">
                <span style="font-size: 15px; font-weight: 700; color: var(--accent); display: flex; align-items: center; gap: 8px;">🤖 Myrmex Assistant</span>
                <button class="close-btn" onclick="toggleAssistant()">&times;</button>
            </div>
            <div class="assistant-controls-row">
                <select id="ast-provider" class="form-control" style="padding: 4px 8px; font-size: 12px; width: 160px; background-color: var(--bg-primary);">
                    <option value="antigravity">Antigravity (Gemini)</option>
                    <option value="ollama">Local LLM (Ollama)</option>
                </select>
                <div style="display: flex; gap: 6px; align-items: center;">
                    <label style="display: flex; align-items: center; gap: 4px; font-size: 12px; color: var(--text-secondary); margin: 0; cursor: pointer; user-select: none;">
                        <input type="checkbox" id="ast-voice-active" style="cursor: pointer;">
                        Talk Back
                    </label>
                </div>
            </div>
        </div>
        <div id="assistant-chat-log">
            <div class="ast-msg system">
                Hi! I am your Myrmex Assistant. I can monitor status, read logs, or execute approved commands using available tools. How can I help you?
            </div>
        </div>
        <div class="assistant-input-area">
            <button id="ast-mic-btn" onclick="toggleVoiceInput()" title="Start Voice Input">[REC]</button>
            <input type="text" id="assistant-input-field" placeholder="Ask assistant..." onkeydown="if(event.key === 'Enter') sendAssistantMessage()">
            <button class="btn" style="padding: 8px 16px; border-radius: 6px;" onclick="sendAssistantMessage()">Send</button>
        </div>
    </div>

    <script>
        let currentTab = 'dashboard';
        let connectedAgentsDetails = {};
        let toolsCatalog = {};
        let currentConfigData = null;
        let authToken = localStorage.getItem('mcp_hive_token');

        // Check if token is passed in query string
        const urlParams = new URLSearchParams(window.location.search);
        if (urlParams.has('token')) {
            authToken = urlParams.get('token');
            localStorage.setItem('mcp_hive_token', authToken);
            // clean up URL query string
            const url = new URL(window.location.href);
            url.searchParams.delete('token');
            window.history.replaceState({}, document.title, url.pathname);
        }

        function checkAuth() {
            if (!authToken) {
                document.getElementById('login-modal').style.display = 'flex';
                return false;
            }
            document.getElementById('login-modal').style.display = 'none';
            return true;
        }

        function submitLoginToken() {
            const input = document.getElementById('login-token-input').value.trim();
            if (input) {
                authToken = input;
                localStorage.setItem('mcp_hive_token', authToken);
                document.getElementById('login-modal').style.display = 'none';
                initPortal();
            }
        }

        async function authFetch(url, options = {}) {
            if (!options.headers) {
                options.headers = {};
            }
            if (authToken) {
                options.headers['Authorization'] = 'Bearer ' + authToken;
            }
            try {
                const res = await fetch(url, options);
                if (res.status === 401) {
                    localStorage.removeItem('mcp_hive_token');
                    authToken = null;
                    checkAuth();
                    throw new Error('Unauthorized');
                }
                return res;
            } catch (err) {
                if (err.message === 'Unauthorized') {
                    throw err;
                }
                throw err;
            }
        }

        function switchTab(tabId) {
            if (!checkAuth()) return;
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

            const activeBtn = Array.from(document.querySelectorAll('.tab-btn')).find(btn => btn.innerText.toLowerCase() === tabId.toLowerCase() || (tabId === 'keys' && btn.innerText.includes('SSH')));
            if (activeBtn) activeBtn.classList.add('active');
            
            const targetContent = document.getElementById(tabId);
            if (targetContent) targetContent.classList.add('active');

            currentTab = tabId;
            if (tabId === 'playground') {
                loadTools();
            } else if (tabId === 'keys') {
                loadKeys();
            } else if (tabId === 'config') {
                loadConfig();
            }
        }

        async function fetchStatus() {
            if (!authToken) return;
            try {
                const res = await authFetch('/api/status');
                if (!res.ok) throw new Error('Failed to fetch status');
                const data = await res.json();

                // Update counts
                document.getElementById('count-agents').innerText = data.agents ? data.agents.length : 0;
                document.getElementById('count-upstreams').innerText = data.upstreams ? data.upstreams.length : 0;

                // Update Edge Agents List
                const agentsList = document.getElementById('agents-list');
                if (!data.agents || data.agents.length === 0) {
                    agentsList.innerHTML = '<li class="item-row"><span class="item-name">No agents connected. Connect agents outbound to port 2222.</span></li>';
                } else {
                    agentsList.innerHTML = data.agents.map(agent => {
                        connectedAgentsDetails[agent.id] = agent;
                        return '<li class="item-row" style="cursor: pointer; transition: all 0.2s;" onclick="showAgentDetails(\'' + agent.id + '\')">' +
                            '<span class="item-name">' + agent.id + '</span>' +
                            '<span class="item-meta" style="color: var(--accent);">' + agent.ip + ' | ' + agent.os_version + '</span>' +
                            '</li>';
                    }).join('');
                }

                // Update Upstream List
                const upstreamsList = document.getElementById('upstreams-list');
                if (!data.upstreams || data.upstreams.length === 0) {
                    upstreamsList.innerHTML = '<li class="item-row"><span class="item-name">No upstream servers configured.</span></li>';
                } else {
                    upstreamsList.innerHTML = data.upstreams.map(up => {
                        let dotClass = 'connecting';
                        if (up.status === 'connected') dotClass = 'connected';
                        else if (up.status.startsWith('error')) dotClass = 'error';

                        return '<li class="item-row">' +
                            '<span class="item-name"><span class="status-dot ' + dotClass + '"></span>' + up.name + '</span>' +
                            '<div class="upstream-actions">' +
                                '<span class="item-meta" style="margin-right: 15px;">' + up.status + ' (' + up.url + ')</span>' +
                                '<button class="btn btn-danger" style="padding: 4px 8px; font-size: 11px;" onclick="deleteUpstream(\'' + up.name + '\')">Remove</button>' +
                            '</div>' +
                        '</li>';
                    }).join('');
                }
            } catch (err) {
                console.error(err);
            }
        }

        async function loadTools() {
            const playToolSelect = document.getElementById('play-tool');
            playToolSelect.innerHTML = '<option value="">Loading tools...</option>';
            try {
                const res = await authFetch('/api/tools');
                if (!res.ok) throw new Error('Failed to load tools');
                const data = await res.json();
                
                toolsCatalog = {};
                playToolSelect.innerHTML = '<option value="">-- Select a tool to run --</option>';

                if (data.tools && data.tools.length > 0) {
                    data.tools.forEach(t => {
                        toolsCatalog[t.name] = t;
                        const option = document.createElement('option');
                        option.value = t.name;
                        option.innerText = t.name;
                        playToolSelect.appendChild(option);
                    });
                } else {
                    playToolSelect.innerHTML = '<option value="">No tools registered. Wait for agents.</option>';
                }
            } catch (err) {
                playToolSelect.innerHTML = '<option value="">Error loading tools</option>';
                console.error(err);
            }
        }

        function onToolSelect() {
            const toolName = document.getElementById('play-tool').value;
            const descBox = document.getElementById('tool-description-box');
            const descEl = document.getElementById('tool-description');
            const argsArea = document.getElementById('play-args');

            if (!toolName || !toolsCatalog[toolName]) {
                descBox.style.display = 'none';
                argsArea.value = '{}';
                return;
            }

            const tool = toolsCatalog[toolName];
            descEl.innerText = tool.description || 'No description provided.';
            descBox.style.display = 'block';

            // Prefill arguments structure if schema exists
            const argsObj = {};
            if (tool.inputSchema && tool.inputSchema.properties) {
                Object.keys(tool.inputSchema.properties).forEach(prop => {
                    const p = tool.inputSchema.properties[prop];
                    argsObj[prop] = p.type === 'string' ? '' : (p.type === 'array' ? [] : (p.type === 'object' ? {} : null));
                });
            }
            argsArea.value = JSON.stringify(argsObj, null, 2);
        }

        async function callTool() {
            const toolName = document.getElementById('play-tool').value;
            const argsText = document.getElementById('play-args').value;
            const termOut = document.getElementById('terminal-out');
            const runBtn = document.getElementById('run-btn');
            const respStatus = document.getElementById('response-status');

            if (!toolName) {
                alert('Please select a tool first!');
                return;
            }

            let argsParsed;
            try {
                argsParsed = JSON.parse(argsText);
            } catch (e) {
                alert('Arguments must be valid JSON: ' + e.message);
                return;
            }

            termOut.innerText = 'Calling tool ' + toolName + '...\nWaiting for response...';
            termOut.style.color = '#d1d5db';
            respStatus.innerText = 'Running';
            runBtn.disabled = true;
            runBtn.innerHTML = '<span class="spinner"></span> <span>Running...</span>';

            try {
                const res = await authFetch('/api/call', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: toolName, arguments: argsParsed })
                });

                if (!res.ok) {
                    const text = await res.text();
                    throw new Error(text || 'HTTP error ' + res.status);
                }

                const data = await res.json();
                runBtn.disabled = false;
                runBtn.innerHTML = '<span>Execute Tool</span>';

                if (data.error) {
                    termOut.innerText = 'Error (' + data.error.code + '): ' + data.error.message;
                    termOut.style.color = 'var(--danger)';
                    respStatus.innerText = 'Failed';
                } else {
                    termOut.innerText = JSON.stringify(data.result, null, 2);
                    termOut.style.color = '#34d399';
                    respStatus.innerText = 'Success';
                }
            } catch (err) {
                termOut.innerText = 'Call failed:\n' + err.message;
                termOut.style.color = 'var(--danger)';
                respStatus.innerText = 'Error';
                runBtn.disabled = false;
                runBtn.innerHTML = '<span>Execute Tool</span>';
            }
        }

        async function loadKeys() {
            const area = document.getElementById('ssh-keys-area');
            area.value = 'Loading authorized keys...';
            try {
                const res = await authFetch('/api/keys');
                if (!res.ok) throw new Error();
                const data = await res.json();
                area.value = data.keys || '';
            } catch (e) {
                area.value = 'Failed to load keys.';
            }
        }

        async function saveKeys() {
            const btn = document.getElementById('save-keys-btn');
            const alertBox = document.getElementById('keys-alert');
            const originalText = btn.innerText;

            btn.disabled = true;
            btn.innerText = 'Saving...';
            alertBox.innerHTML = '';

            try {
                const res = await authFetch('/api/keys', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ keys: document.getElementById('ssh-keys-area').value })
                });
                if (!res.ok) throw new Error(await res.text());
                
                alertBox.innerHTML = '<div class="alert alert-success">Authorized keys saved successfully!</div>';
            } catch (e) {
                alertBox.innerHTML = '<div class="alert alert-danger">Failed to save keys: ' + e.message + '</div>';
            } finally {
                btn.disabled = false;
                btn.innerText = originalText;
            }
        }

        async function loadConfig() {
            try {
                const res = await authFetch('/api/config');
                if (!res.ok) throw new Error();
                const data = await res.json();
                currentConfigData = data;

                document.getElementById('cfg-listen').value = data.listen_addr || '';
                document.getElementById('cfg-http').value = data.http_addr || '';
                document.getElementById('cfg-ollama-url').value = data.ollama_url || '';
                document.getElementById('cfg-ollama-model').value = data.ollama_model || '';
                document.getElementById('cfg-antigravity-token').value = data.antigravity_token || '';

                const webMcpUrl = window.location.origin + '/sse?token=' + (authToken || 'YOUR_AUTH_TOKEN');
                const connectionBox = document.getElementById('webmcp-connection-string');
                if (connectionBox) {
                    connectionBox.innerText = webMcpUrl;
                }
            } catch (e) {
                console.error('Failed to load config');
            }
        }

        async function saveConfig() {
            const alertBox = document.getElementById('config-alert');
            alertBox.innerHTML = '';

            if (!currentConfigData) return;

            const updatedConfig = {
                ...currentConfigData,
                listen_addr: document.getElementById('cfg-listen').value,
                http_addr: document.getElementById('cfg-http').value,
                ollama_url: document.getElementById('cfg-ollama-url').value,
                ollama_model: document.getElementById('cfg-ollama-model').value,
                antigravity_token: document.getElementById('cfg-antigravity-token').value
            };

            try {
                const res = await authFetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updatedConfig)
                });
                if (!res.ok) throw new Error(await res.text());
                
                const data = await res.json();
                currentConfigData = data.config;
                alertBox.innerHTML = '<div class="alert alert-success">Gateway settings saved successfully!</div>';
            } catch (e) {
                alertBox.innerHTML = '<div class="alert alert-danger">Failed to save config: ' + e.message + '</div>';
            }
        }

        async function addUpstream() {
            const alertBox = document.getElementById('upstream-alert');
            const nameEl = document.getElementById('up-name');
            const transport = document.getElementById('up-transport').value;

            alertBox.innerHTML = '';
            const name = nameEl.value.trim();
            if (!name) {
                alertBox.innerHTML = '<div class="alert alert-danger">Server Name is required!</div>';
                return;
            }

            if (!currentConfigData) {
                await loadConfig();
            }

            const extServers = currentConfigData.external_mcp_servers || [];
            const legacyServers = currentConfigData.upstream_servers || [];

            // Check if name already exists
            if (extServers.some(s => s.name === name) || legacyServers.some(s => s.name === name)) {
                alertBox.innerHTML = '<div class="alert alert-danger">A connection with name "' + name + '" already exists!</div>';
                return;
            }

            let newServer = { name: name, transport: transport };

            if (transport === 'sse') {
                const urlEl = document.getElementById('up-url');
                const url = urlEl.value.trim();
                if (!url) {
                    alertBox.innerHTML = '<div class="alert alert-danger">SSE URL is required!</div>';
                    return;
                }
                if (!url.toLowerCase().startsWith('https://')) {
                    alertBox.innerHTML = '<div class="alert alert-danger">Upstream connections must use secure HTTPS (URL must start with https://)</div>';
                    return;
                }
                newServer.url = url;
            } else {
                const cmdEl = document.getElementById('up-cmd');
                const argsEl = document.getElementById('up-args');
                const envEl = document.getElementById('up-env');

                const cmd = cmdEl.value.trim();
                if (!cmd) {
                    alertBox.innerHTML = '<div class="alert alert-danger">Subprocess Command is required!</div>';
                    return;
                }
                newServer.command = cmd;

                // Parse arguments
                let args = [];
                const rawArgs = argsEl.value.trim();
                if (rawArgs) {
                    args = rawArgs.split(/\s+/).map(s => s.trim()).filter(s => s);
                }
                newServer.args = args;

                // Parse env
                let env = {};
                const rawEnv = envEl.value.trim();
                if (rawEnv) {
                    rawEnv.split(',').forEach(kv => {
                        const parts = kv.split('=');
                        if (parts.length >= 2) {
                            const k = parts[0].trim();
                            const v = parts.slice(1).join('=').trim();
                            if (k) env[k] = v;
                        }
                    });
                }
                newServer.env = env;
            }

            extServers.push(newServer);

            const updatedConfig = {
                ...currentConfigData,
                external_mcp_servers: extServers
            };

            try {
                const res = await authFetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updatedConfig)
                });
                if (!res.ok) throw new Error(await res.text());

                const data = await res.json();
                currentConfigData = data.config;
                nameEl.value = '';
                document.getElementById('up-url').value = '';
                document.getElementById('up-cmd').value = '';
                document.getElementById('up-args').value = '';
                document.getElementById('up-env').value = '';
                alertBox.innerHTML = '<div class="alert alert-success">External MCP server registered successfully!</div>';
                fetchStatus();
            } catch (e) {
                alertBox.innerHTML = '<div class="alert alert-danger">Registration failed: ' + e.message + '</div>';
            }
        }

        async function deleteUpstream(name) {
            if (!confirm('Are you sure you want to remove upstream connection "' + name + '"?')) return;

            if (!currentConfigData) {
                await loadConfig();
            }

            const extServers = (currentConfigData.external_mcp_servers || []).filter(s => s.name !== name);
            const legacyServers = (currentConfigData.upstream_servers || []).filter(s => s.name !== name);

            const updatedConfig = {
                ...currentConfigData,
                upstream_servers: legacyServers,
                external_mcp_servers: extServers
            };

            try {
                const res = await authFetch('/api/config', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(updatedConfig)
                });
                if (!res.ok) throw new Error(await res.text());
                const data = await res.json();
                currentConfigData = data.config;
                fetchStatus();
            } catch (e) {
                alert('Deletion failed: ' + e.message);
            }
        }

        function toggleTransportFields() {
            const transport = document.getElementById('up-transport').value;
            if (transport === 'sse') {
                document.getElementById('sse-fields').style.display = 'block';
                document.getElementById('stdio-fields').style.display = 'none';
            } else {
                document.getElementById('sse-fields').style.display = 'none';
                document.getElementById('stdio-fields').style.display = 'block';
            }
        }

        function initPortal() {
            if (!checkAuth()) return;
            fetchStatus();
        }

        // Initialize status polling
        initPortal();
        setInterval(fetchStatus, 5000);

        // --- Assistant Logic ---
        let assistantOpen = false;
        let assistantHistory = [];
        let speechRecognition = null;
        let isListening = false;

        function toggleAssistant() {
            const win = document.getElementById('assistant-window');
            assistantOpen = !assistantOpen;
            win.style.display = assistantOpen ? 'flex' : 'none';
            if (assistantOpen) {
                document.getElementById('assistant-input-field').focus();
            }
        }

        // Initialize Speech Recognition
        const SpeechRecognitionApi = window.SpeechRecognition || window.webkitSpeechRecognition;
        if (SpeechRecognitionApi) {
            speechRecognition = new SpeechRecognitionApi();
            speechRecognition.continuous = false;
            speechRecognition.interimResults = false;
            speechRecognition.lang = 'en-US';

            speechRecognition.onstart = () => {
                isListening = true;
                const micBtn = document.getElementById('ast-mic-btn');
                if (micBtn) {
                    micBtn.classList.add('mic-active');
                    micBtn.title = 'Listening... Click to stop';
                }
            };

            speechRecognition.onresult = (event) => {
                const transcript = event.results[0][0].transcript;
                const inputField = document.getElementById('assistant-input-field');
                if (inputField) {
                    inputField.value = transcript;
                }
                sendAssistantMessage();
            };

            speechRecognition.onerror = (event) => {
                console.error('Speech recognition error:', event.error);
                stopListening();
            };

            speechRecognition.onend = () => {
                stopListening();
            };
        } else {
            const micBtn = document.getElementById('ast-mic-btn');
            if (micBtn) micBtn.style.display = 'none';
        }

        function toggleVoiceInput() {
            if (!speechRecognition) return;
            if (isListening) {
                speechRecognition.stop();
            } else {
                speechRecognition.start();
            }
        }

        function stopListening() {
            isListening = false;
            const micBtn = document.getElementById('ast-mic-btn');
            if (micBtn) {
                micBtn.classList.remove('mic-active');
                micBtn.title = 'Start Voice Input';
            }
        }

        function speakText(text) {
            const voiceActive = document.getElementById('ast-voice-active').checked;
            if (!voiceActive) return;
            if ('speechSynthesis' in window) {
                window.speechSynthesis.cancel();
                // strip markdown formatting and JSON blocks
                let clean = text;
                clean = clean.replace(/\x60\x60\x60json[\s\S]*?\x60\x60\x60/g, '');
                clean = clean.replace(/\x60\x60\x60[\s\S]*?\x60\x60\x60/g, '');
                clean = clean.replace(/[\*#_\x60\[\]]/g, '');
                
                const utterance = new SpeechSynthesisUtterance(clean);
                window.speechSynthesis.speak(utterance);
            }
        }

        function renderMarkdown(text) {
            if (!text) return '';
            
            // Escape HTML
            let html = text
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;');
            
            // Code blocks
            html = html.replace(/\x60\x60\x60(.*?)\n([\s\S]*?)\x60\x60\x60/g, function(match, lang, code) {
                return '<pre><code class="language-' + lang.trim() + '">' + code.trim() + '</code></pre>';
            });

            // Inline code
            html = html.replace(/\x60([^\x60]+)\x60/g, '<code>$1</code>');

            // Headers
            html = html.replace(/^#### (.*?)$/gm, '<h4>$1</h4>');
            html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
            html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
            html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');

            // Bold
            html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
            html = html.replace(/__([^_]+)__/g, '<strong>$1</strong>');

            // Italic
            html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
            html = html.replace(/_([^_]+)_/g, '<em>$1</em>');

            // Lists
            const lines = html.split('\n');
            let inList = false;
            let listType = null;
            for (let i = 0; i < lines.length; i++) {
                let line = lines[i].trim();
                let matchUl = line.match(/^[\*\-\+]\s+(.*)$/);
                let matchOl = line.match(/^(\d+)\.\s+(.*)$/);

                if (matchUl) {
                    let content = matchUl[1];
                    let prefix = '';
                    if (!inList || listType !== 'ul') {
                        prefix = (inList ? '</' + listType + '>' : '') + '<ul>';
                        inList = true;
                        listType = 'ul';
                    }
                    lines[i] = prefix + '<li>' + content + '</li>';
                } else if (matchOl) {
                    let content = matchOl[2];
                    let prefix = '';
                    if (!inList || listType !== 'ol') {
                        prefix = (inList ? '</' + listType + '>' : '') + '<ol>';
                        inList = true;
                        listType = 'ol';
                    }
                    lines[i] = prefix + '<li>' + content + '</li>';
                } else {
                    if (inList) {
                        lines[i] = '</' + listType + '>' + lines[i];
                        inList = false;
                        listType = null;
                    }
                }
            }
            if (inList) {
                lines[lines.length - 1] += '</' + listType + '>';
            }
            html = lines.join('\n');

            // Replace newlines with <br> excluding pre blocks
            const parts = html.split(/(<pre>[\s\S]*?<\/pre>)/);
            for (let i = 0; i < parts.length; i++) {
                if (!parts[i].startsWith('<pre>')) {
                    parts[i] = parts[i].replace(/\n/g, '<br>');
                }
            }
            html = parts.join('');

            return html;
        }

        function appendAssistantMessage(role, text, type = 'text') {
            const chatLog = document.getElementById('assistant-chat-log');
            if (!chatLog) return;
            const msgEl = document.createElement('div');
            msgEl.className = 'ast-msg ' + role;
            if (type === 'code') {
                const pre = document.createElement('pre');
                pre.style.whiteSpace = 'pre-wrap';
                pre.style.margin = '0';
                pre.innerText = text;
                msgEl.appendChild(pre);
            } else if (role === 'assistant' || role === 'user' || role === 'system') {
                msgEl.innerHTML = renderMarkdown(text);
            } else {
                msgEl.innerText = text;
            }
            chatLog.appendChild(msgEl);
            chatLog.scrollTop = chatLog.scrollHeight;
        }

        async function sendAssistantMessage() {
            const inputField = document.getElementById('assistant-input-field');
            if (!inputField) return;
            const prompt = inputField.value.trim();
            if (!prompt) return;

            inputField.value = '';
            appendAssistantMessage('user', prompt);

            await runAgentLoop(prompt);
        }

        async function runAgentLoop(userPrompt) {
            const provider = document.getElementById('ast-provider').value;
            
            const countAgents = document.getElementById('count-agents').innerText;
            const countUpstreams = document.getElementById('count-upstreams').innerText;
            
            const toolNames = Object.keys(toolsCatalog);
            
            const systemPrompt = 
                'You are the Myrmex Assistant. You can monitor status and run approved commands using tools.' +
                ' Context: Connected Edge Agents count = ' + countAgents + '; Registered Upstream Servers count = ' + countUpstreams + '.' +
                ' Available tools: ' + JSON.stringify(toolNames) + '.' +
                ' If you need to perform an action (e.g. check status, run command, read logs), respond with a SINGLE JSON command block:' +
                ' {"call": "tool_name", "arguments": {...}}' +
                ' Do not include other text when calling a tool. If you do not need any tools to answer, respond normally with plain text.';

            let promptToModel = userPrompt;
            let loopCount = 0;
            const maxLoops = 5;

            while (loopCount < maxLoops) {
                loopCount++;
                try {
                    const statusEl = document.createElement('div');
                    statusEl.className = 'ast-msg system';
                    statusEl.innerText = 'Thinking...';
                    const chatLog = document.getElementById('assistant-chat-log');
                    if (chatLog) {
                        chatLog.appendChild(statusEl);
                        chatLog.scrollTop = chatLog.scrollHeight;
                    }

                    const chatBody = {
                        provider: provider,
                        prompt: promptToModel,
                        history: assistantHistory,
                        system: systemPrompt
                    };

                    const res = await authFetch('/api/chat', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(chatBody)
                    });

                    statusEl.remove();

                    if (!res.ok) {
                        const errText = await res.text();
                        appendAssistantMessage('system', 'Error: ' + errText);
                        break;
                    }

                    const data = await res.json();
                    const reply = data.response ? data.response.trim() : '';

                    if (!reply) {
                        appendAssistantMessage('system', 'Empty response from model.');
                        break;
                    }

                    let isToolCall = false;
                    let toolCallObj = null;

                    let jsonText = reply;
                    const jsonMatch = reply.match(/\x60\x60\x60json\s*([\s\S]*?)\s*\x60\x60\x60/) || reply.match(/\x60\x60\x60\s*([\s\S]*?)\s*\x60\x60\x60/);
                    if (jsonMatch) {
                        jsonText = jsonMatch[1].trim();
                    }

                    try {
                        const parsed = JSON.parse(jsonText);
                        if (parsed && typeof parsed === 'object' && parsed.call) {
                            isToolCall = true;
                            toolCallObj = parsed;
                        }
                    } catch (e) {
                        // Not a JSON tool call
                    }

                    if (isToolCall) {
                        assistantHistory.push({ role: 'user', text: promptToModel });
                        assistantHistory.push({ role: 'assistant', text: reply });

                        appendAssistantMessage('agent-action', '[Executing tool]: ' + toolCallObj.call + '\nArguments: ' + JSON.stringify(toolCallObj.arguments), 'code');

                        try {
                            const callRes = await authFetch('/api/call', {
                                method: 'POST',
                                headers: { 'Content-Type': 'application/json' },
                                body: JSON.stringify({ name: toolCallObj.call, arguments: toolCallObj.arguments })
                            });

                            if (!callRes.ok) {
                                const errText = await callRes.text();
                                throw new Error(errText || 'HTTP ' + callRes.status);
                            }

                            const callData = await callRes.json();
                            let resultStr = '';
                            if (callData.error) {
                                resultStr = 'Tool Error: ' + callData.error.message;
                            } else {
                                resultStr = JSON.stringify(callData.result);
                            }

                            promptToModel = 'Tool result: ' + resultStr;
                        } catch (err) {
                            promptToModel = 'Failed to execute tool ' + toolCallObj.call + ': ' + err.message;
                        }
                    } else {
                        assistantHistory.push({ role: 'user', text: promptToModel });
                        assistantHistory.push({ role: 'assistant', text: reply });

                        appendAssistantMessage('assistant', reply);
                        speakText(reply);
                        break;
                    }
                } catch (err) {
                    appendAssistantMessage('system', 'Agent loop error: ' + err.message);
                    break;
                }
            }
        }

        // --- Agent Details Drawer Logic & Metrics Polling ---
        let activeAgentDetailsId = null;
        let agentDetailsTimeout = null;

        async function fetchAgentMetrics(agentId) {
            if (activeAgentDetailsId !== agentId) return;

            const loadingEl = document.getElementById('det-metrics-loading');
            const contentEl = document.getElementById('det-metrics-content');

            try {
                const res = await authFetch('/api/call', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ name: agentId + '__get_metrics', arguments: {} })
                });

                if (!res.ok) throw new Error(await res.text());
                const data = await res.json();
                
                if (data.error) throw new Error(data.error.message);
                if (activeAgentDetailsId !== agentId) return;

                // Parse metrics JSON from RPC result content
                const metricsText = data.result && data.result.content && data.result.content[0] && data.result.content[0].text;
                if (!metricsText) throw new Error('No metrics returned');

                const metrics = JSON.parse(metricsText);

                // Update UI fields
                document.getElementById('det-load-1m').innerText = metrics.load_avg_1m !== undefined ? metrics.load_avg_1m.toFixed(2) : '-';
                document.getElementById('det-load-5m').innerText = metrics.load_avg_5m !== undefined ? metrics.load_avg_5m.toFixed(2) : '-';
                document.getElementById('det-load-15m').innerText = metrics.load_avg_15m !== undefined ? metrics.load_avg_15m.toFixed(2) : '-';

                // CPU
                const cpuVal = metrics.cpu_usage_percent || 0;
                document.getElementById('det-cpu-val').innerText = cpuVal.toFixed(1) + '%';
                const cpuFill = document.getElementById('det-cpu-fill');
                cpuFill.style.width = cpuVal.toFixed(1) + '%';
                updateBarColor(cpuFill, cpuVal);

                // Memory
                const memUsedPct = metrics.mem_used_percent || 0;
                const memUsed = metrics.mem_used_mb || 0;
                const memTotal = metrics.mem_total_mb || 0;
                document.getElementById('det-mem-val').innerText = memUsedPct.toFixed(1) + '% (' + Math.round(memUsed) + ' / ' + Math.round(memTotal) + ' MB)';
                const memFill = document.getElementById('det-mem-fill');
                memFill.style.width = memUsedPct.toFixed(1) + '%';
                updateBarColor(memFill, memUsedPct);

                // Disk
                const diskUsedPct = metrics.disk_used_percent || 0;
                const diskUsed = metrics.disk_used_gb || 0;
                const diskTotal = metrics.disk_total_gb || 0;
                document.getElementById('det-disk-val').innerText = diskUsedPct.toFixed(1) + '% (' + Math.round(diskUsed) + ' / ' + Math.round(diskTotal) + ' GB)';
                const diskFill = document.getElementById('det-disk-fill');
                diskFill.style.width = diskUsedPct.toFixed(1) + '%';
                updateBarColor(diskFill, diskUsedPct);

                loadingEl.style.display = 'none';
                contentEl.style.display = 'block';

            } catch (err) {
                if (activeAgentDetailsId === agentId) {
                    loadingEl.innerText = 'Failed to load metrics: ' + err.message;
                    loadingEl.style.display = 'block';
                    contentEl.style.display = 'none';
                }
            }

            // Schedule next check if drawer is still open on this agent
            if (activeAgentDetailsId === agentId) {
                agentDetailsTimeout = setTimeout(function() { fetchAgentMetrics(agentId); }, 5000);
            }
        }

        function updateBarColor(el, val) {
            el.classList.remove('warning', 'danger');
            if (val >= 90) {
                el.classList.add('danger');
            } else if (val >= 75) {
                el.classList.add('warning');
            }
        }

        function showAgentDetails(agentId) {
            const agent = connectedAgentsDetails[agentId];
            if (!agent) return;

            activeAgentDetailsId = agentId;
            if (agentDetailsTimeout) {
                clearTimeout(agentDetailsTimeout);
                agentDetailsTimeout = null;
            }

            document.getElementById('det-id').innerText = agent.id;
            document.getElementById('det-ip').innerText = agent.ip;
            document.getElementById('det-os').innerText = agent.os_version || 'Loading...';

            const servicesEl = document.getElementById('det-services');
            servicesEl.innerHTML = '';
            if (agent.running_services && agent.running_services.length > 0) {
                agent.running_services.forEach(svc => {
                    const span = document.createElement('span');
                    span.className = 'svc-tag';
                    span.innerText = svc;
                    servicesEl.appendChild(span);
                });
            } else {
                servicesEl.innerHTML = '<span style="font-size:13px; color:var(--text-secondary);">None detected or loading...</span>';
            }

            const portsEl = document.getElementById('det-ports');
            portsEl.innerHTML = '';
            if (agent.open_ports && agent.open_ports.length > 0) {
                agent.open_ports.forEach(port => {
                    const span = document.createElement('span');
                    span.className = 'port-tag';
                    span.innerText = port;
                    portsEl.appendChild(span);
                });
            } else {
                portsEl.innerHTML = '<span style="font-size:13px; color:var(--text-secondary);">None detected or loading...</span>';
            }

            // Reset metrics UI
            const loadingEl = document.getElementById('det-metrics-loading');
            const contentEl = document.getElementById('det-metrics-content');
            loadingEl.innerText = 'Loading system metrics...';
            loadingEl.style.display = 'block';
            contentEl.style.display = 'none';

            document.getElementById('agent-details-drawer').classList.add('open');

            // Trigger fetch
            fetchAgentMetrics(agentId);
        }

        function closeAgentDetails() {
            activeAgentDetailsId = null;
            if (agentDetailsTimeout) {
                clearTimeout(agentDetailsTimeout);
                agentDetailsTimeout = null;
            }
            document.getElementById('agent-details-drawer').classList.remove('open');
        }
    </script>
</body>
</html>`
