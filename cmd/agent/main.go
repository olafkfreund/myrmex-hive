package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/olafkfreund/mcp-os-agent/pkg/command"
	"github.com/olafkfreund/mcp-os-agent/pkg/config"
	"github.com/olafkfreund/mcp-os-agent/pkg/metrics"
)

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

type RunCommandArgs struct {
	Name string   `json:"name"`
	Args []string `json:"args,omitempty"`
}

func main() {
	configPath := flag.String("config", "agent_config.json", "Path to agent configuration file")
	flag.Parse()

	log.Println("Starting Myrmex Agent...")
	cfg, err := config.LoadAgentConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Support HA/Failover gateway addresses
	addrs := cfg.GatewayAddrs
	if len(addrs) == 0 {
		if cfg.GatewayAddr != "" {
			addrs = []string{cfg.GatewayAddr}
		} else {
			log.Fatal("Error: No gateway_addr or gateway_addrs configured.")
		}
	}

	addrIdx := 0
	for {
		targetAddr := addrs[addrIdx%len(addrs)]
		log.Printf("Agent ID: %s, connecting to Gateway: %s (HA Node %d/%d)", cfg.AgentID, targetAddr, (addrIdx%len(addrs))+1, len(addrs))
		err := connectAndServe(cfg, targetAddr)
		if err != nil {
			log.Printf("Connection error to %s: %v. Retrying next node in 5 seconds...", targetAddr, err)
			addrIdx++
			time.Sleep(5 * time.Second)
		}
	}
}

// buildHostKeyCallback returns an SSH HostKeyCallback that verifies the
// gateway's host key. If GatewayHostKey is configured the key is pinned;
// otherwise a trust-on-first-use (TOFU) policy learns and persists the key on
// first contact and rejects any later mismatch as a possible MITM attack. The
// host key is never ignored.
func buildHostKeyCallback(cfg *config.AgentConfig) (ssh.HostKeyCallback, error) {
	// Pinned host key takes precedence over TOFU.
	if cfg.GatewayHostKey != "" {
		pinned, _, _, _, err := ssh.ParseAuthorizedKey([]byte(cfg.GatewayHostKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse gateway_host_key: %w", err)
		}
		return ssh.FixedHostKey(pinned), nil
	}

	knownPath := cfg.KnownHostKeyPath
	if knownPath == "" {
		knownPath = cfg.PrivateKeyPath + ".gateway_hostkey"
	}

	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		stored, err := os.ReadFile(knownPath)
		if err == nil {
			knownKey, _, _, _, perr := ssh.ParseAuthorizedKey(stored)
			if perr != nil {
				return fmt.Errorf("failed to parse stored gateway host key %s: %w", knownPath, perr)
			}
			if !bytes.Equal(key.Marshal(), knownKey.Marshal()) {
				return fmt.Errorf("gateway host key mismatch for %s: stored key does not match presented key (possible MITM attack)", hostname)
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("failed to read known gateway host key %s: %w", knownPath, err)
		}
		// Trust-on-first-use: persist the presented key and accept.
		if werr := os.WriteFile(knownPath, ssh.MarshalAuthorizedKey(key), 0600); werr != nil {
			return fmt.Errorf("failed to persist gateway host key to %s: %w", knownPath, werr)
		}
		log.Printf("[TOFU] Learned and stored gateway host key for %s at %s (first connection)", hostname, knownPath)
		return nil
	}, nil
}

func connectAndServe(cfg *config.AgentConfig, gatewayAddr string) error {
	// 1. Read SSH private key
	keyBytes, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key %s: %w", cfg.PrivateKeyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %w", err)
	}

	// 2. Establish SSH Client connection with real host-key verification.
	hostKeyCallback, err := buildHostKeyCallback(cfg)
	if err != nil {
		return fmt.Errorf("failed to configure gateway host-key verification: %w", err)
	}
	clientConfig := &ssh.ClientConfig{
		User: cfg.AgentID, // Send agent ID as the SSH username
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
		Timeout:         15 * time.Second,
	}

	conn, err := net.DialTimeout("tcp", gatewayAddr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("failed to dial Gateway: %w", err)
	}
	defer conn.Close()

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, gatewayAddr, clientConfig)
	if err != nil {
		return fmt.Errorf("SSH handshake failed: %w", err)
	}
	defer sshConn.Close()

	// Keep-alive goroutines
	go ssh.DiscardRequests(reqs)
	go func() {
		for newChan := range chans {
			// Reject any incoming channels from gateway; client is the one initiating
			newChan.Reject(ssh.Prohibited, "agent does not accept incoming channels")
		}
	}()

	// 3. Open the "mcp" channel to the Gateway
	channel, channelRequests, err := sshConn.OpenChannel("mcp", nil)
	if err != nil {
		return fmt.Errorf("failed to open 'mcp' channel: %w", err)
	}
	defer channel.Close()

	go ssh.DiscardRequests(channelRequests)

	log.Println("Successfully connected to Gateway and opened 'mcp' channel. Serving MCP requests...")

	// 4. Handle JSON-RPC over the channel
	reader := bufio.NewReader(channel)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				log.Println("Gateway closed the connection.")
				return nil
			}
			return fmt.Errorf("error reading from channel: %w", err)
		}

		var req JsonRpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			log.Printf("Invalid JSON-RPC request: %v", err)
			sendError(channel, nil, -32700, "Parse error")
			continue
		}

		// Handle request concurrently
		go handleRequest(channel, req, cfg)
	}
}

func handleRequest(w io.Writer, req JsonRpcRequest, cfg *config.AgentConfig) {
	switch req.Method {
	case "tools/list":
		handleListTools(w, req)
	case "tools/call":
		handleCallTool(w, req, cfg)
	default:
		sendError(w, req.ID, -32601, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func handleListTools(w io.Writer, req JsonRpcRequest) {
	// List the tools this agent supports
	tools := []map[string]interface{}{
		{
			"name":        "get_metrics",
			"description": "Retrieve system CPU, memory, load average, and disk usage metrics",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "run_command",
			"description": "Run an approved command from the agent allowlist",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"name": map[string]interface{}{
						"type":        "string",
						"description": "The command executable name",
					},
					"args": map[string]interface{}{
						"type": "array",
						"items": map[string]interface{}{
							"type": "string",
						},
						"description": "Arguments to pass to the command",
					},
				},
				"required": []string{"name"},
			},
		},
		{
			"name":        "read_logs",
			"description": "Read recent system log entries",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"lines": map[string]interface{}{
						"type":        "integer",
						"description": "Number of log lines to retrieve (default 50)",
					},
				},
			},
		},
		{
			"name":        "get_system_info",
			"description": "Retrieve agent operating system version, running services, and open TCP ports",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}

	response := JsonRpcResponse{
		JsonRpc: "2.0",
		Result: map[string]interface{}{
			"tools": tools,
		},
		ID: req.ID,
	}

	sendResponse(w, response)
}

func handleCallTool(w io.Writer, req JsonRpcRequest, cfg *config.AgentConfig) {
	var params CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		sendError(w, req.ID, -32602, "Invalid params")
		return
	}

	switch params.Name {
	case "get_system_info":
		info := SystemInfo{
			OSVersion:       getOSVersion(),
			RunningServices: getRunningServices(),
			OpenPorts:       getOpenPorts(),
		}
		infoJSON, _ := json.Marshal(info)
		response := JsonRpcResponse{
			JsonRpc: "2.0",
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": string(infoJSON),
					},
				},
			},
			ID: req.ID,
		}
		sendResponse(w, response)

	case "get_metrics":
		sysMetrics, err := metrics.GetMetrics()
		if err != nil {
			sendError(w, req.ID, -32603, fmt.Sprintf("Failed to get metrics: %v", err))
			return
		}

		metricsJSON, _ := json.Marshal(sysMetrics)
		response := JsonRpcResponse{
			JsonRpc: "2.0",
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": string(metricsJSON),
					},
				},
			},
			ID: req.ID,
		}
		sendResponse(w, response)

	case "run_command":
		var cmdArgs RunCommandArgs
		if err := json.Unmarshal(params.Arguments, &cmdArgs); err != nil {
			sendError(w, req.ID, -32602, "Invalid command arguments")
			return
		}

		output, err := command.ExecuteCommand(cmdArgs.Name, cmdArgs.Args, cfg.AllowedCommands)

		var textContent string
		if err != nil {
			textContent = fmt.Sprintf("Command failed/rejected: %v\nOutput:\n%s", err, output)
		} else {
			textContent = output
		}

		response := JsonRpcResponse{
			JsonRpc: "2.0",
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": textContent,
					},
				},
			},
			ID: req.ID,
		}
		sendResponse(w, response)

	case "read_logs":
		var args struct {
			Lines int `json:"lines"`
		}
		if len(params.Arguments) > 0 {
			_ = json.Unmarshal(params.Arguments, &args)
		}
		if args.Lines <= 0 {
			args.Lines = 50
		}
		if args.Lines > 100 {
			args.Lines = 100
		}

		logContent, err := readSystemLogs(args.Lines)
		if err != nil {
			sendError(w, req.ID, -32603, fmt.Sprintf("Failed to read logs: %v", err))
			return
		}

		response := JsonRpcResponse{
			JsonRpc: "2.0",
			Result: map[string]interface{}{
				"content": []map[string]interface{}{
					{
						"type": "text",
						"text": logContent,
					},
				},
			},
			ID: req.ID,
		}
		sendResponse(w, response)

	default:
		sendError(w, req.ID, -32601, fmt.Sprintf("Tool not found: %s", params.Name))
	}
}

func readSystemLogs(lines int) (string, error) {
	if runtime.GOOS == "windows" {
		psCommand := fmt.Sprintf("Get-EventLog -LogName System -Newest %d | Select-Object TimeGenerated, Source, EntryType, Message | Format-Table -HideTableHeaders | Out-String", lines)
		cmd := exec.Command("powershell", "-NoProfile", "-Command", psCommand)
		output, err := cmd.Output()
		if err != nil {
			return "", err
		}
		return string(output), nil
	}

	paths := []string{"/var/log/syslog", "/var/log/messages", "/var/log/auth.log", "/var/log/system.log"}
	var readErr error
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			content, err := tailFile(p, lines)
			if err == nil {
				return content, nil
			}
			readErr = err
		}
	}
	if readErr != nil {
		return "", readErr
	}
	return "No system log files found or accessible.", nil
}

func tailFile(filePath string, maxLines int) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > maxLines {
			lines = lines[1:]
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return strings.Join(lines, "\n"), nil
}

func sendResponse(w io.Writer, resp JsonRpcResponse) {
	data, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return
	}
	data = append(data, '\n')
	_, _ = w.Write(data)
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

type SystemInfo struct {
	OSVersion       string   `json:"os_version"`
	RunningServices []string `json:"running_services"`
	OpenPorts       []string `json:"open_ports"`
}

func getOSVersion() string {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_OperatingSystem).Caption")
		out, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(out))
		}
		return "Windows Server"
	}
	if runtime.GOOS == "darwin" {
		cmd := exec.Command("sw_vers", "-productName")
		nameOut, _ := cmd.Output()
		cmd = exec.Command("sw_vers", "-productVersion")
		verOut, _ := cmd.Output()
		name := strings.TrimSpace(string(nameOut))
		ver := strings.TrimSpace(string(verOut))
		if name != "" && ver != "" {
			return name + " " + ver
		}
		return "macOS"
	}

	file, err := os.Open("/etc/os-release")
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				val := strings.TrimPrefix(line, "PRETTY_NAME=")
				val = strings.Trim(val, "\"")
				return val
			}
		}
	}
	issueBytes, err := os.ReadFile("/etc/issue")
	if err == nil && len(issueBytes) > 0 {
		return strings.TrimSpace(string(issueBytes))
	}
	return "Linux"
}

func getRunningServices() []string {
	var services []string

	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -ExpandProperty Name")
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" {
					services = append(services, line)
				}
			}
		}
		return services
	}

	if runtime.GOOS == "darwin" {
		cmd := exec.Command("launchctl", "list")
		out, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			scanner.Scan() // skip header
			for scanner.Scan() {
				parts := strings.Fields(scanner.Text())
				if len(parts) >= 3 {
					services = append(services, parts[2])
				}
			}
		}
		if len(services) > 0 {
			return services
		}
	}

	cmd := exec.Command("systemctl", "list-units", "--type=service", "--state=running", "--no-legend", "--no-pager")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) > 0 {
				svc := parts[0]
				svc = strings.TrimSuffix(svc, ".service")
				services = append(services, svc)
			}
		}
		if len(services) > 0 {
			return services
		}
	}

	files, err := os.ReadDir("/proc")
	if err == nil {
		seen := make(map[string]bool)
		for _, f := range files {
			if !f.IsDir() {
				continue
			}
			name := f.Name()
			if name[0] < '0' || name[0] > '9' {
				continue
			}
			commBytes, err := os.ReadFile("/proc/" + name + "/comm")
			if err == nil {
				procName := strings.TrimSpace(string(commBytes))
				if procName != "" && !seen[procName] {
					seen[procName] = true
					services = append(services, procName)
				}
			}
		}
	}
	return services
}

func getOpenPorts() []string {
	var ports []string

	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-NoProfile", "-Command", "Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort")
		out, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line != "" && !contains(ports, line) {
					ports = append(ports, line)
				}
			}
		}
		return ports
	}

	if runtime.GOOS == "darwin" {
		cmd := exec.Command("netstat", "-an")
		out, err := cmd.Output()
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(out)))
			for scanner.Scan() {
				line := scanner.Text()
				if strings.Contains(line, "LISTEN") {
					parts := strings.Fields(line)
					if len(parts) >= 4 {
						localAddr := parts[3]
						idx := strings.LastIndex(localAddr, ".")
						if idx != -1 {
							port := localAddr[idx+1:]
							if port != "" && !contains(ports, port) {
								ports = append(ports, port)
							}
						}
					}
				}
			}
		}
		return ports
	}

	cmd := exec.Command("ss", "-tlnH")
	output, err := cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			parts := strings.Fields(scanner.Text())
			if len(parts) >= 4 {
				localAddr := parts[3]
				idx := strings.LastIndex(localAddr, ":")
				if idx != -1 {
					port := localAddr[idx+1:]
					if port != "" && !contains(ports, port) {
						ports = append(ports, port)
					}
				}
			}
		}
		if len(ports) > 0 {
			return ports
		}
	}

	cmd = exec.Command("netstat", "-tln")
	output, err = cmd.Output()
	if err == nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "LISTEN") {
				parts := strings.Fields(line)
				if len(parts) >= 4 {
					localAddr := parts[3]
					idx := strings.LastIndex(localAddr, ":")
					if idx != -1 {
						port := localAddr[idx+1:]
						if port != "" && !contains(ports, port) {
							ports = append(ports, port)
						}
					}
				}
			}
		}
	}
	return ports
}

func contains(arr []string, s string) bool {
	for _, item := range arr {
		if item == s {
			return true
		}
	}
	return false
}
