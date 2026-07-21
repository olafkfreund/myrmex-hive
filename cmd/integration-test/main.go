package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

type JsonRpcRequest struct {
	JsonRpc string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      interface{}     `json:"id"`
}

type JsonRpcResponse struct {
	JsonRpc string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JsonRpcError   `json:"error,omitempty"`
	ID      interface{}     `json:"id"`
}

type JsonRpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

type SseClient struct {
	sessionID  string
	postURL    string
	pending    map[string]chan JsonRpcResponse
	pendingMu  sync.Mutex
	httpClient *http.Client
	token      string
}

func NewSseClient(sseURL string, token string) (*SseClient, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	cli := &SseClient{
		pending:    make(map[string]chan JsonRpcResponse),
		httpClient: &http.Client{Timeout: 40 * time.Second, Transport: tr},
		token:      token,
	}

	// 1. Connect to SSE
	req, err := http.NewRequest("GET", sseURL, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := cli.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSE: %w", err)
	}

	reader := bufio.NewReader(resp.Body)

	// Read the first event to get the endpoint and session ID
	var currentEvent string
	var currentData string
	for {
		lineBytes, err := reader.ReadBytes('\n')
		if err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("failed to read endpoint event: %w", err)
		}
		line := strings.TrimSpace(string(lineBytes))

		if line == "" {
			// Event separator, dispatch if we have an endpoint
			if currentEvent == "endpoint" {
				// Parse URL
				// data: /message?session_id=session-xxx
				u, err := url.Parse(currentData)
				if err != nil {
					resp.Body.Close()
					return nil, fmt.Errorf("invalid endpoint URL: %w", err)
				}
				cli.sessionID = u.Query().Get("session_id")

				// Resolve full POST URL relative to SSE URL
				base, _ := url.Parse(sseURL)
				resolved := base.ResolveReference(u)
				cli.postURL = resolved.String()
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

	log.Printf("SSE Client connected. Session ID: %s, POST URL: %s", cli.sessionID, cli.postURL)

	// Start reading subsequent events in the background
	go cli.readEvents(resp.Body, reader)

	return cli, nil
}

func (c *SseClient) readEvents(body io.ReadCloser, reader *bufio.Reader) {
	defer body.Close()
	var currentEvent string
	var currentData string

	for {
		lineBytes, err := reader.ReadBytes('\n')
		if err != nil {
			log.Printf("SSE connection closed: %v", err)
			return
		}
		line := strings.TrimSpace(string(lineBytes))

		if line == "" {
			// End of event
			if currentEvent == "message" && currentData != "" {
				var resp JsonRpcResponse
				if err := json.Unmarshal([]byte(currentData), &resp); err == nil {
					idStr := normalizeID(resp.ID)
					c.pendingMu.Lock()
					ch, exists := c.pending[idStr]
					if exists {
						ch <- resp
						delete(c.pending, idStr)
					}
					c.pendingMu.Unlock()
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

func (c *SseClient) Call(req JsonRpcRequest) (*JsonRpcResponse, error) {
	idStr := normalizeID(req.ID)
	ch := make(chan JsonRpcResponse, 1)

	c.pendingMu.Lock()
	c.pending[idStr] = ch
	c.pendingMu.Unlock()

	reqBytes, err := json.Marshal(req)
	if err != nil {
		c.pendingMu.Lock()
		delete(c.pending, idStr)
		c.pendingMu.Unlock()
		return nil, err
	}

	// Send POST message
	postReq, err := http.NewRequest("POST", c.postURL, bytes.NewReader(reqBytes))
	if err != nil {
		c.pendingMu.Lock()
		delete(c.pending, idStr)
		c.pendingMu.Unlock()
		return nil, err
	}
	postReq.Header.Set("Content-Type", "application/json")
	if c.token != "" {
		postReq.Header.Set("Authorization", "Bearer "+c.token)
	}

	resp, err := c.httpClient.Do(postReq)
	if err != nil {
		c.pendingMu.Lock()
		delete(c.pending, idStr)
		c.pendingMu.Unlock()
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		c.pendingMu.Lock()
		delete(c.pending, idStr)
		c.pendingMu.Unlock()
		return nil, fmt.Errorf("gateway returned non-accepted status: %d", resp.StatusCode)
	}

	// Wait for response via SSE
	select {
	case r := <-ch:
		return &r, nil
	case <-time.After(35 * time.Second):
		c.pendingMu.Lock()
		delete(c.pending, idStr)
		c.pendingMu.Unlock()
		return nil, fmt.Errorf("request timed out waiting for SSE response")
	}
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

// expectedAgents is the roster docker-compose.test.yml brings up. The tools
// assertion later checks the same set, so both grow together.
var expectedAgents = []string{"agent-1", "agent-2", "agent-3", "agent-nginx", "agent-db"}

// waitForAgents blocks until every named agent has registered with the Gateway
// or the deadline passes, reading the Gateway's own container logs so it needs
// no auth and works before the SSE client exists.
//
// It does NOT fail on timeout: the tools assertion downstream is the real
// check and reports which agent is missing, which is a far more useful failure
// than "waited too long".
func waitForAgents(agents []string, timeout time.Duration) {
	log.Printf("Waiting up to %s for %d agents to register...", timeout, len(agents))
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "logs", "mcp-gateway-test").CombinedOutput()
		if err == nil {
			missing := []string{}
			for _, a := range agents {
				if !strings.Contains(string(out), "Agent registered: "+a) {
					missing = append(missing, a)
				}
			}
			if len(missing) == 0 {
				log.Printf("All %d agents registered.", len(agents))
				// The Gateway registers an agent when its SSH session is up;
				// give the 'mcp' channel a moment to be serving before asking
				// it for a tool list.
				time.Sleep(1 * time.Second)
				return
			}
			log.Printf("  still waiting on: %s", strings.Join(missing, ", "))
		}
		time.Sleep(2 * time.Second)
	}
	log.Printf("Timed out waiting for agents; continuing so the assertions can report specifics.")
}

func main() {
	log.Println("Starting Docker integration test runner...")

	// 0. Setup test environment
	log.Println("Setting up test environment (configs, keys, logs)...")
	setupCmd := exec.Command("./setup_test_env.sh")
	setupCmd.Stdout = os.Stdout
	setupCmd.Stderr = os.Stderr
	if err := setupCmd.Run(); err != nil {
		log.Fatalf("Failed to run setup_test_env.sh: %v", err)
	}

	// 1. Build and start containers
	log.Println("Starting Docker Compose services (gateway + 3 agents)...")
	upCmd := exec.Command("docker", "compose", "-f", "docker-compose.test.yml", "up", "-d", "--build")
	upCmd.Stdout = os.Stdout
	upCmd.Stderr = os.Stderr
	if err := upCmd.Run(); err != nil {
		log.Fatalf("Failed to start Docker Compose: %v", err)
	}

	// Ensure we shut down compose when exiting (commented out to leave services running for user manual verification)
	/*
		defer func() {
			log.Println("Stopping Docker Compose services...")
			downCmd := exec.Command("docker", "compose", "-f", "docker-compose.test.yml", "down", "-v")
			downCmd.Stdout = os.Stdout
			downCmd.Stderr = os.Stderr
			downCmd.Run()
		}()
	*/

	// 2. Wait for registration.
	//
	// Polled, not a fixed sleep. Five agents dial out independently and the
	// slowest lagged the fastest by seconds on a cold start, so a flat 6s made
	// this fail as "Missing expected tools" — a real-looking failure caused
	// entirely by asserting too early. Poll until every expected agent has
	// registered, then continue immediately.
	waitForAgents(expectedAgents, 90*time.Second)

	// 3. Connect to the Gateway HTTP/SSE server
	// 3. Connect to the Gateway HTTPS/SSE server loading the generated config token
	log.Println("Loading gateway config to retrieve secure auth token...")
	gatewayCfg, err := config.LoadGatewayConfig("test_env/gateway/gateway_config.json")
	if err != nil {
		log.Fatalf("Failed to load gateway config for test: %v", err)
	}

	log.Println("Connecting SSE test client to Gateway https://localhost:8080/sse...")
	client, err := NewSseClient("https://localhost:8080/sse", gatewayCfg.AuthToken)
	if err != nil {
		// Log docker compose logs first to debug
		logsCmd := exec.Command("docker", "compose", "-f", "docker-compose.test.yml", "logs")
		logsCmd.Stdout = os.Stdout
		logsCmd.Stderr = os.Stderr
		logsCmd.Run()
		log.Fatalf("Failed to initialize SSE client: %v", err)
	}

	// 4. Test: list tools
	log.Println("[Test 1] Querying tools/list...")
	listReq := JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/list",
		ID:      1,
	}
	resp, err := client.Call(listReq)
	if err != nil {
		log.Fatalf("Test 1 failed: %v", err)
	}

	if resp.Error != nil {
		log.Fatalf("Test 1 failed with JSON-RPC error: (%d) %s", resp.Error.Code, resp.Error.Message)
	}

	var listResult struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(resp.Result, &listResult); err != nil {
		log.Fatalf("Failed to unmarshal tools list: %v (raw: %s)", err, string(resp.Result))
	}

	log.Printf("Found %d tools exposed by Gateway:", len(listResult.Tools))
	hasAgent1 := false
	hasAgent2 := false
	hasAgent3 := false
	hasAgentNginx := false
	hasAgentDB := false
	hasGateway := false

	for _, t := range listResult.Tools {
		log.Printf(" - %s", t.Name)
		if strings.HasPrefix(t.Name, "agent-1__") {
			hasAgent1 = true
		}
		if strings.HasPrefix(t.Name, "agent-2__") {
			hasAgent2 = true
		}
		if strings.HasPrefix(t.Name, "agent-3__") {
			hasAgent3 = true
		}
		if strings.HasPrefix(t.Name, "agent-nginx__") {
			hasAgentNginx = true
		}
		if strings.HasPrefix(t.Name, "agent-db__") {
			hasAgentDB = true
		}
		if strings.HasPrefix(t.Name, "gateway__") {
			hasGateway = true
		}
	}

	if !hasAgent1 || !hasAgent2 || !hasAgent3 || !hasAgentNginx || !hasAgentDB || !hasGateway {
		log.Fatalf("Fail: Missing expected tools from agent-1, agent-2, agent-3, agent-nginx, agent-db or gateway")
	}
	log.Println("PASS: Tools from all agents registered successfully.")

	// 5. Test: Call metrics on Agent 1
	log.Println("[Test 2] Calling agent-1__get_metrics...")
	callParams := CallToolParams{Name: "agent-1__get_metrics"}
	callParamsBytes, _ := json.Marshal(callParams)
	callReq := JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  callParamsBytes,
		ID:      2,
	}
	resp, err = client.Call(callReq)
	if err != nil {
		log.Fatalf("Test 2 failed: %v", err)
	}
	if resp.Error != nil {
		log.Fatalf("Test 2 failed with JSON-RPC error: %s", resp.Error.Message)
	}
	log.Printf("metrics output: %s", string(resp.Result))
	if !strings.Contains(string(resp.Result), "cpu_usage_percent") {
		log.Fatalf("Fail: Expected CPU usage metrics in result")
	}
	log.Println("PASS: Agent 1 metrics retrieved successfully.")

	// 6. Test: Call approved command execution on Agent 2
	log.Println("[Test 3] Calling agent-2__run_command (free -m)...")
	cmdArgs := struct {
		Name string   `json:"name"`
		Args []string `json:"args"`
	}{Name: "free", Args: []string{"-m"}}
	cmdArgsBytes, _ := json.Marshal(cmdArgs)
	callParams = CallToolParams{Name: "agent-2__run_command", Arguments: cmdArgsBytes}
	callParamsBytes, _ = json.Marshal(callParams)
	callReq = JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  callParamsBytes,
		ID:      3,
	}
	resp, err = client.Call(callReq)
	if err != nil {
		log.Fatalf("Test 3 failed: %v", err)
	}
	if resp.Error != nil {
		log.Fatalf("Test 3 failed with JSON-RPC error: %s", resp.Error.Message)
	}
	log.Printf("command output: %s", string(resp.Result))
	if !strings.Contains(string(resp.Result), "Mem:") {
		log.Fatalf("Fail: Expected free -m command output to contain 'Mem:'")
	}
	log.Println("PASS: Approved command run successfully on Agent 2.")

	// 7. Test: Call unapproved command execution on Agent 1
	log.Println("[Test 4] Calling unapproved command on Agent 1 (rm -rf /)...")
	cmdArgs = struct {
		Name string   `json:"name"`
		Args []string `json:"args"`
	}{Name: "rm", Args: []string{"-rf", "/"}}
	cmdArgsBytes, _ = json.Marshal(cmdArgs)
	callParams = CallToolParams{Name: "agent-1__run_command", Arguments: cmdArgsBytes}
	callParamsBytes, _ = json.Marshal(callParams)
	callReq = JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  callParamsBytes,
		ID:      4,
	}
	resp, err = client.Call(callReq)
	if err != nil {
		log.Fatalf("Test 4 failed: %v", err)
	}
	// We expect the result text to contain "not in the approved allowlist"
	if !strings.Contains(string(resp.Result), "not in the approved allowlist") && (resp.Error == nil || !strings.Contains(resp.Error.Message, "not in the approved allowlist")) {
		log.Fatalf("Fail: Expected command to be rejected, got result: %s", string(resp.Result))
	}
	log.Println("PASS: Unapproved command was blocked successfully by Agent 1.")

	// 8. Test: Call gateway__list_agents
	log.Println("[Test 5] Calling gateway__list_agents...")
	callParams = CallToolParams{Name: "gateway__list_agents"}
	callParamsBytes, _ = json.Marshal(callParams)
	callReq = JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  callParamsBytes,
		ID:      5,
	}
	resp, err = client.Call(callReq)
	if err != nil {
		log.Fatalf("Test 5 failed: %v", err)
	}
	if resp.Error != nil {
		log.Fatalf("Test 5 failed with JSON-RPC error: %s", resp.Error.Message)
	}
	log.Printf("list agents output: %s", string(resp.Result))
	if !strings.Contains(string(resp.Result), "agent-1") || !strings.Contains(string(resp.Result), "agent-2") || !strings.Contains(string(resp.Result), "agent-3") {
		log.Fatalf("Fail: Expected list to contain agent-1, agent-2, and agent-3")
	}
	log.Println("PASS: gateway__list_agents returned all active hive agents.")

	// 9. Test: Call read_logs on Agent 1
	log.Println("[Test 6] Calling agent-1__read_logs...")
	readLogsArgs := struct {
		Lines int `json:"lines"`
	}{Lines: 5}
	readLogsArgsBytes, _ := json.Marshal(readLogsArgs)
	callParams = CallToolParams{Name: "agent-1__read_logs", Arguments: readLogsArgsBytes}
	callParamsBytes, _ = json.Marshal(callParams)
	callReq = JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  callParamsBytes,
		ID:      6,
	}
	resp, err = client.Call(callReq)
	if err != nil {
		log.Fatalf("Test 6 failed: %v", err)
	}
	if resp.Error != nil {
		log.Fatalf("Test 6 failed with JSON-RPC error: %s", resp.Error.Message)
	}
	log.Printf("read_logs output: %s", string(resp.Result))
	if !strings.Contains(string(resp.Result), "Failed to start Nginx") {
		log.Fatalf("Fail: Expected log output to contain 'Failed to start Nginx'")
	}
	log.Println("PASS: Agent 1 read_logs successfully read dummy syslog entries.")

	// 10. Test: Call gateway__humanize_syslog (verifies gateway parameters parse and routes calls to LLM module)
	log.Println("[Test 7] Calling gateway__humanize_syslog...")
	humanizeArgs := struct {
		AgentID string `json:"agent_id"`
		LogLine string `json:"log_line"`
	}{AgentID: "agent-1", LogLine: "sshd[105]: Invalid user admin from 192.168.1.15"}
	humanizeArgsBytes, _ := json.Marshal(humanizeArgs)
	callParams = CallToolParams{Name: "gateway__humanize_syslog", Arguments: humanizeArgsBytes}
	callParamsBytes, _ = json.Marshal(callParams)
	callReq = JsonRpcRequest{
		JsonRpc: "2.0",
		Method:  "tools/call",
		Params:  callParamsBytes,
		ID:      7,
	}
	resp, err = client.Call(callReq)
	if err != nil {
		log.Fatalf("Test 7 failed: %v", err)
	}
	if resp.Error != nil {
		log.Fatalf("Test 7 failed with JSON-RPC error: %s", resp.Error.Message)
	}

	var humanizeResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(resp.Result, &humanizeResult); err != nil {
		log.Fatalf("Failed to unmarshal humanize result: %v (raw: %s)", err, string(resp.Result))
	}

	if len(humanizeResult.Content) == 0 || humanizeResult.Content[0].Text == "" {
		log.Fatalf("Fail: Expected non-empty humanized text response, got: %s", string(resp.Result))
	}
	log.Printf("humanize_syslog response: %s", humanizeResult.Content[0].Text)
	log.Println("PASS: gateway__humanize_syslog successfully humanized syslog line using remote Gemma 4.")

	log.Println("ALL DOCKER INTEGRATION TESTS PASSED SUCCESSFULLY!")
}
