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
	"regexp"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/olafkfreund/myrmex-hive/pkg/command"
	"github.com/olafkfreund/myrmex-hive/pkg/config"
	"github.com/olafkfreund/myrmex-hive/pkg/metrics"
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
	Name   string   `json:"name"`
	Args   []string `json:"args,omitempty"`
	DryRun bool     `json:"dry_run,omitempty"`
}

// ServiceControlArgs holds the typed arguments for the service_control tool.
// It is a structured, safer alternative to free-form run_command for
// managing systemd services; it still delegates to command.ExecuteCommand
// so the operator's allowlist remains the enforced security boundary.
type ServiceControlArgs struct {
	Action  string `json:"action"`
	Service string `json:"service"`
}

// serviceNameRegex conservatively restricts service/unit names to avoid
// argument injection; ExecuteCommand always passes args to os/exec directly
// (never a shell), but this keeps inputs to a well-formed systemd unit name.
var serviceNameRegex = regexp.MustCompile(`^[A-Za-z0-9@._-]+$`)

// ContainerPsArgs holds the typed arguments for the container_ps tool.
// It is a structured, read-only wrapper around `docker ps`; it still
// delegates to command.ExecuteCommand so the operator's allowlist remains
// the enforced security boundary (the docker binary must be allowlisted).
type ContainerPsArgs struct {
	All bool `json:"all,omitempty"`
}

// K8sGetArgs holds the typed arguments for the k8s_get tool.
// It is a structured, read-only wrapper around `kubectl get <resource>`;
// it still delegates to command.ExecuteCommand so the operator's allowlist
// remains the enforced security boundary (the kubectl binary must be
// allowlisted).
type K8sGetArgs struct {
	Resource  string `json:"resource"`
	Namespace string `json:"namespace,omitempty"`
}

// k8sResourceRegex conservatively restricts the requested resource type to
// avoid argument injection; ExecuteCommand always passes args to os/exec
// directly (never a shell), but this keeps inputs to well-formed kubectl
// resource names (e.g. "pods", "deployments.apps").
var k8sResourceRegex = regexp.MustCompile(`^[a-z][a-z0-9.-]*$`)

// k8sNamespaceRegex conservatively restricts the requested namespace to
// avoid argument injection; matches well-formed Kubernetes namespace names.
var k8sNamespaceRegex = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// PackageQueryArgs holds the typed arguments for the package_query tool.
// It is a structured, read-only wrapper around OS package manager "list
// installed" commands; it still delegates to command.ExecuteCommand so the
// operator's allowlist remains the enforced security boundary (the package
// manager binary must be allowlisted).
type PackageQueryArgs struct {
	Manager string `json:"manager"`
	Name    string `json:"name,omitempty"`
}

// packageNameRegex conservatively restricts the optional package name filter
// to avoid argument injection; ExecuteCommand always passes args to os/exec
// directly (never a shell), but this keeps inputs to well-formed package
// names.
var packageNameRegex = regexp.MustCompile(`^[A-Za-z0-9._+-]+$`)

// FileReadArgs holds the typed arguments for the file_read tool.
// It is a bounded, read-only wrapper around `cat`; it still delegates to
// command.ExecuteCommand so the operator's allowlist (specifically the
// args_regex configured for the cat entry) remains the actual security gate
// governing which paths are readable. The client-side checks here (absolute
// path, no "..") only reject obviously malformed input early.
type FileReadArgs struct {
	Path string `json:"path"`
}

// maxFileReadBytes bounds the amount of file content returned by file_read
// so a single call can't flood the response with an enormous file.
const maxFileReadBytes = 65536

// Build information, injected at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// toolSchemaVersion identifies the shape of the tool definitions advertised
// via tools/list (name/description/inputSchema for each tool). Bump this
// whenever a tool's schema changes in an incompatible way so the gateway and
// other clients can detect and adapt to the change.
const toolSchemaVersion = "1"

// supportedToolNames is the list of tool names this agent advertises via
// tools/list. Kept in sync with handleListTools and surfaced via
// get_system_info's SupportedTools field for capability discovery.
var supportedToolNames = []string{
	"get_metrics",
	"run_command",
	"read_logs",
	"get_system_info",
	"service_control",
	"container_ps",
	"k8s_get",
	"package_query",
	"file_read",
}

func main() {
	configPath := flag.String("config", "agent_config.json", "Path to agent configuration file")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("agent %s (commit %s, built %s)\n", version, commit, date)
		os.Exit(0)
	}

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
			"name":          "get_metrics",
			"description":   "Retrieve system CPU, memory, load average, and disk usage metrics",
			"schemaVersion": toolSchemaVersion,
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":          "run_command",
			"description":   "Run an approved command from the agent allowlist",
			"schemaVersion": toolSchemaVersion,
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
					"dry_run": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, validate against the allowlist and report what would run without executing it",
					},
				},
				"required": []string{"name"},
			},
		},
		{
			"name":          "read_logs",
			"description":   "Read recent system log entries",
			"schemaVersion": toolSchemaVersion,
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
			"name":          "get_system_info",
			"description":   "Retrieve agent operating system version, running services, and open TCP ports",
			"schemaVersion": toolSchemaVersion,
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":          "service_control",
			"description":   "Typed, structured control of a systemd service — a safer alternative to free-form run_command. Still enforced by the agent's command allowlist.",
			"schemaVersion": toolSchemaVersion,
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"action": map[string]interface{}{
						"type":        "string",
						"description": "The service action to perform. One of: start, stop, restart, status",
						"enum":        []string{"start", "stop", "restart", "status"},
					},
					"service": map[string]interface{}{
						"type":        "string",
						"description": "The service/unit name to control (e.g. nginx, sshd.service)",
					},
				},
				"required": []string{"action", "service"},
			},
		},
		{
			"name":          "container_ps",
			"description":   "List Docker containers on the host (read-only). Enforced by the agent's command allowlist; requires the docker binary to be allowlisted.",
			"schemaVersion": toolSchemaVersion,
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"all": map[string]interface{}{
						"type":        "boolean",
						"description": "If true, include stopped containers (maps to `docker ps -a`)",
					},
				},
			},
		},
		{
			"name":          "k8s_get",
			"description":   "Read-only Kubernetes resource listing via `kubectl get`. Enforced by the agent's command allowlist; requires the kubectl binary to be allowlisted.",
			"schemaVersion": toolSchemaVersion,
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"resource": map[string]interface{}{
						"type":        "string",
						"description": "The resource type to list, e.g. pods, nodes, deployments",
					},
					"namespace": map[string]interface{}{
						"type":        "string",
						"description": "The namespace to query (optional; omit to use kubectl's current-context default)",
					},
				},
				"required": []string{"resource"},
			},
		},
		{
			"name":          "package_query",
			"description":   "Typed, read-only query of installed OS packages via the system package manager (dpkg, rpm, apk, pacman, or dnf). Enforced by the agent's command allowlist; requires the corresponding package manager binary to be allowlisted.",
			"schemaVersion": toolSchemaVersion,
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"manager": map[string]interface{}{
						"type":        "string",
						"description": "The package manager to query. One of: dpkg, rpm, apk, pacman, dnf",
						"enum":        []string{"dpkg", "rpm", "apk", "pacman", "dnf"},
					},
					"name": map[string]interface{}{
						"type":        "string",
						"description": "Optional package name filter",
					},
				},
				"required": []string{"manager"},
			},
		},
		{
			"name":          "file_read",
			"description":   "Bounded, read-only read of a file on the agent host via `cat` (output truncated to 64KB). The agent's command allowlist — specifically the args_regex configured for the cat entry — is the actual security boundary governing which paths may be read; this tool additionally rejects non-absolute paths and path traversal (\"..\") client-side.",
			"schemaVersion": toolSchemaVersion,
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]interface{}{
						"type":        "string",
						"description": "Absolute path of the file to read (must not contain \"..\")",
					},
				},
				"required": []string{"path"},
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
			OSVersion:         getOSVersion(),
			RunningServices:   getRunningServices(),
			OpenPorts:         getOpenPorts(),
			AgentVersion:      version,
			ToolSchemaVersion: toolSchemaVersion,
			SupportedTools:    supportedToolNames,
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

		var output string
		var err error
		if cmdArgs.DryRun {
			// Preview only: validate against the allowlist and report what would
			// run, without executing anything.
			output, err = command.DryRun(cmdArgs.Name, cmdArgs.Args, cfg.AllowedCommands)
		} else {
			output, err = command.ExecuteCommand(cmdArgs.Name, cmdArgs.Args, cfg.AllowedCommands)
		}

		var textContent string
		if err != nil {
			// command.ResultFailurePrefix, not a literal: the Gateway matches on
			// this marker to audit the call as denied/failed rather than
			// successful (#174), so the two must not drift apart.
			textContent = fmt.Sprintf("%s %v\nOutput:\n%s", command.ResultFailurePrefix, err, output)
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

	case "service_control":
		var svcArgs ServiceControlArgs
		if err := json.Unmarshal(params.Arguments, &svcArgs); err != nil {
			sendError(w, req.ID, -32602, "Invalid service_control arguments")
			return
		}

		switch svcArgs.Action {
		case "start", "stop", "restart", "status":
			// allowed
		default:
			sendError(w, req.ID, -32602, fmt.Sprintf("Invalid action %q: must be one of start, stop, restart, status", svcArgs.Action))
			return
		}

		if svcArgs.Service == "" || !serviceNameRegex.MatchString(svcArgs.Service) {
			sendError(w, req.ID, -32602, fmt.Sprintf("Invalid service name %q", svcArgs.Service))
			return
		}

		output, err := command.ExecuteCommand("systemctl", []string{svcArgs.Action, svcArgs.Service}, cfg.AllowedCommands)

		var textContent string
		if err != nil {
			// command.ResultFailurePrefix, not a literal: the Gateway matches on
			// this marker to audit the call as denied/failed rather than
			// successful (#174), so the two must not drift apart.
			textContent = fmt.Sprintf("%s %v\nOutput:\n%s", command.ResultFailurePrefix, err, output)
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

	case "container_ps":
		var psArgs ContainerPsArgs
		if len(params.Arguments) > 0 {
			if err := json.Unmarshal(params.Arguments, &psArgs); err != nil {
				sendError(w, req.ID, -32602, "Invalid container_ps arguments")
				return
			}
		}

		dockerArgs := []string{"ps"}
		if psArgs.All {
			dockerArgs = append(dockerArgs, "-a")
		}

		output, err := command.ExecuteCommand("docker", dockerArgs, cfg.AllowedCommands)

		var textContent string
		if err != nil {
			// command.ResultFailurePrefix, not a literal: the Gateway matches on
			// this marker to audit the call as denied/failed rather than
			// successful (#174), so the two must not drift apart.
			textContent = fmt.Sprintf("%s %v\nOutput:\n%s", command.ResultFailurePrefix, err, output)
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

	case "k8s_get":
		var k8sArgs K8sGetArgs
		if err := json.Unmarshal(params.Arguments, &k8sArgs); err != nil {
			sendError(w, req.ID, -32602, "Invalid k8s_get arguments")
			return
		}

		if k8sArgs.Resource == "" || !k8sResourceRegex.MatchString(k8sArgs.Resource) {
			sendError(w, req.ID, -32602, fmt.Sprintf("Invalid resource %q", k8sArgs.Resource))
			return
		}
		if k8sArgs.Namespace != "" && !k8sNamespaceRegex.MatchString(k8sArgs.Namespace) {
			sendError(w, req.ID, -32602, fmt.Sprintf("Invalid namespace %q", k8sArgs.Namespace))
			return
		}

		kubectlArgs := []string{"get", k8sArgs.Resource}
		if k8sArgs.Namespace != "" {
			kubectlArgs = append(kubectlArgs, "-n", k8sArgs.Namespace)
		}

		output, err := command.ExecuteCommand("kubectl", kubectlArgs, cfg.AllowedCommands)

		var textContent string
		if err != nil {
			// command.ResultFailurePrefix, not a literal: the Gateway matches on
			// this marker to audit the call as denied/failed rather than
			// successful (#174), so the two must not drift apart.
			textContent = fmt.Sprintf("%s %v\nOutput:\n%s", command.ResultFailurePrefix, err, output)
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

	case "package_query":
		var pkgArgs PackageQueryArgs
		if err := json.Unmarshal(params.Arguments, &pkgArgs); err != nil {
			sendError(w, req.ID, -32602, "Invalid package_query arguments")
			return
		}

		var listArgs []string
		switch pkgArgs.Manager {
		case "dpkg":
			listArgs = []string{"-l"}
		case "rpm":
			listArgs = []string{"-qa"}
		case "apk":
			listArgs = []string{"info"}
		case "pacman":
			listArgs = []string{"-Q"}
		case "dnf":
			listArgs = []string{"list", "installed"}
		default:
			sendError(w, req.ID, -32602, fmt.Sprintf("Invalid manager %q: must be one of dpkg, rpm, apk, pacman, dnf", pkgArgs.Manager))
			return
		}

		if pkgArgs.Name != "" {
			if !packageNameRegex.MatchString(pkgArgs.Name) {
				sendError(w, req.ID, -32602, fmt.Sprintf("Invalid package name %q", pkgArgs.Name))
				return
			}
			listArgs = append(listArgs, pkgArgs.Name)
		}

		output, err := command.ExecuteCommand(pkgArgs.Manager, listArgs, cfg.AllowedCommands)

		var textContent string
		if err != nil {
			// command.ResultFailurePrefix, not a literal: the Gateway matches on
			// this marker to audit the call as denied/failed rather than
			// successful (#174), so the two must not drift apart.
			textContent = fmt.Sprintf("%s %v\nOutput:\n%s", command.ResultFailurePrefix, err, output)
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

	case "file_read":
		var fileArgs FileReadArgs
		if err := json.Unmarshal(params.Arguments, &fileArgs); err != nil {
			sendError(w, req.ID, -32602, "Invalid file_read arguments")
			return
		}

		if fileArgs.Path == "" || !strings.HasPrefix(fileArgs.Path, "/") {
			sendError(w, req.ID, -32602, fmt.Sprintf("Invalid path %q: must be an absolute path", fileArgs.Path))
			return
		}
		if strings.Contains(fileArgs.Path, "..") {
			sendError(w, req.ID, -32602, fmt.Sprintf("Invalid path %q: path traversal (\"..\") is not allowed", fileArgs.Path))
			return
		}

		output, err := command.ExecuteCommand("cat", []string{fileArgs.Path}, cfg.AllowedCommands)

		var textContent string
		if err != nil {
			// See the note on ResultFailurePrefix above: the Gateway audits on it.
			textContent = fmt.Sprintf("%s %v\nOutput:\n%s", command.ResultFailurePrefix, err, output)
		} else if len(output) > maxFileReadBytes {
			textContent = output[:maxFileReadBytes] + "\n...[truncated at 64KB]"
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

	// Capability advertisement fields — let the gateway/clients discover
	// which agent build and tool schema version they're talking to, and
	// which tools this agent supports, without a separate handshake.
	AgentVersion      string   `json:"agent_version"`
	ToolSchemaVersion string   `json:"tool_schema_version"`
	SupportedTools    []string `json:"supported_tools"`
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
