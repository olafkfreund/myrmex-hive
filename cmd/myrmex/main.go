package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/olafkfreund/myrmex-hive/pkg/audit"
	"golang.org/x/crypto/ssh"
)

type Config struct {
	URL      string
	Token    string
	Insecure bool
	Output   string
	// Plan requests dry-run mode for "ask": tool calls the assistant chooses
	// are reported but never executed. Only meaningful for handleAsk.
	Plan bool
	// AllAgents / AgentIDs opt "ask" into fleet-wide orchestration: the prompt
	// runs against every connected agent (AllAgents) or a comma-separated
	// subset (AgentIDs), routed through the Gateway's server-side fleet
	// orchestration. Only meaningful for handleAsk.
	AllAgents bool
	AgentIDs  string
}

// Build information, injected at build time via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(0)
	}

	cmd := os.Args[1]
	if cmd == "help" || cmd == "-h" || cmd == "--help" {
		printHelp()
		os.Exit(0)
	}
	if cmd == "version" || cmd == "--version" || cmd == "-v" {
		fmt.Printf("myrmex %s (commit %s, built %s)\n", version, commit, date)
		os.Exit(0)
	}

	// Parse custom flags manually for flexibility.
	cfg, cmdArgs := parseFlags(os.Args[2:])

	// "audit verify" runs entirely against a local log file and host key, so it
	// does not require a Gateway auth token. "enroll", "bootstrap", and
	// "rotate" redeem a one-time join token as their credential instead of a
	// bearer token (an admin --token is only needed if they must mint that
	// join token themselves) — each validates its own auth requirements.
	noBearerRequired := cmd == "audit" || cmd == "enroll" || cmd == "bootstrap" || cmd == "rotate"
	if cfg.Token == "" && !noBearerRequired {
		fmt.Fprintln(os.Stderr, "Error: Secure Gateway Auth Token is required. Use --token flag or set MYRMEX_TOKEN environment variable.")
		os.Exit(1)
	}

	// Setup HTTP Client
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.Insecure},
	}
	client := &http.Client{
		Timeout:   35 * time.Second,
		Transport: tr,
	}

	switch cmd {
	case "status":
		handleStatus(client, cfg)
	case "agents":
		handleAgents(client, cfg)
	case "upstreams":
		handleUpstreams(client, cfg)
	case "tools":
		handleTools(client, cfg)
	case "config":
		handleConfig(client, cfg)
	case "call":
		handleCall(client, cfg, cmdArgs)
	case "ask":
		handleAsk(client, cfg, cmdArgs)
	case "audit":
		handleAudit(cfg, cmdArgs)
	case "enroll-token":
		handleEnrollToken(client, cfg, cmdArgs)
	case "enroll":
		handleEnroll(client, cfg, cmdArgs)
	case "bootstrap":
		handleBootstrap(client, cfg, cmdArgs)
	case "rotate":
		handleRotate(client, cfg, cmdArgs)
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command %q\nRun 'myrmex --help' for details.\n", cmd)
		os.Exit(1)
	}
}

// parseFlags parses global flags out of argv (the arguments that follow the
// subcommand), returning the resolved Config and the remaining command-specific
// args. Boolean switches (--plan/--all) are matched before the generic
// "consume the next token as this flag's value" logic so they never swallow a
// following positional — e.g. the prompt in `ask --plan "..."`.
func parseFlags(argv []string) (Config, []string) {
	cfg := Config{
		URL:      "https://localhost:8080",
		Token:    os.Getenv("MYRMEX_TOKEN"),
		Insecure: false,
		Output:   "text",
	}

	var cmdArgs []string
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		if arg == "--plan" {
			cfg.Plan = true
			continue
		}
		if strings.HasPrefix(arg, "--plan=") {
			cfg.Plan = strings.TrimPrefix(arg, "--plan=") != "false"
			continue
		}
		// --all is a boolean switch (fleet: all agents).
		if arg == "--all" {
			cfg.AllAgents = true
			continue
		}
		// --agents takes a comma-separated value; consume the next token unless
		// given as --agents=... form.
		if arg == "--agents" {
			if i+1 < len(argv) {
				cfg.AgentIDs = argv[i+1]
				i++
			}
			continue
		}
		if strings.HasPrefix(arg, "--agents=") {
			cfg.AgentIDs = strings.TrimPrefix(arg, "--agents=")
			continue
		}
		if strings.HasPrefix(arg, "--") || strings.HasPrefix(arg, "-") {
			parts := strings.SplitN(arg, "=", 2)
			var key, val string
			if len(parts) == 2 {
				key = parts[0]
				val = parts[1]
			} else {
				key = arg
				if i+1 < len(argv) && !strings.HasPrefix(argv[i+1], "-") {
					val = argv[i+1]
					i++
				}
			}

			trimmedKey := strings.TrimLeft(key, "-")
			switch trimmedKey {
			case "url":
				cfg.URL = val
			case "token":
				cfg.Token = val
			case "insecure":
				cfg.Insecure = (val != "false")
			case "output", "o":
				cfg.Output = val
			default:
				// Pass command-specific flags and values to cmdArgs.
				cmdArgs = append(cmdArgs, key)
				if val != "" {
					cmdArgs = append(cmdArgs, val)
				}
			}
		} else {
			cmdArgs = append(cmdArgs, arg)
		}
	}
	return cfg, cmdArgs
}

func printHelp() {
	helpText := `Myrmex Hive Command Line Interface (myrmex)

Usage:
  myrmex [command] [options]

Commands:
  status        Show overall status of connected agents and upstreams
  agents        List details of all connected agents
  upstreams     List configured external/upstream connection servers
  tools         List all registered MCP tools across the Hive
  call          Execute an MCP tool on an agent or upstream
  config        View the current gateway configuration
  ask           Ask the Myrmex AI Assistant to perform a task
  audit verify  Verify a signed, hash-chained gateway audit log
  audit watch   Poll the audit log and alert (exit non-zero) on tamper
  audit export  Export the audit log as JSON or CSV for archival/review
  audit pubkey  Print the gateway host public key for external auditors
  enroll-token  Mint a join token for a new agent-id (admin --token)
  enroll        Redeem a join token to register an agent's public key
  bootstrap     One-command onboarding: generate keypair + enroll + write config
  rotate        Enroll a replacement public key for an existing agent-id

Global Options:
  --url         Gateway API base URL (default: https://localhost:8080)
  --token       Secure Gateway Auth Token (or MYRMEX_TOKEN env var)
  --insecure    Skip TLS verification (default: false)
  --output, -o  Output format: text, json (default: text)
  --plan        With "ask": show what tools would be called, without executing them

Real-Life Scenarios:
  1. Check the general status of all agents:
     myrmex status --token <token>

  2. List the open ports on all connected agents in JSON format:
     myrmex agents --token <token> --output json

  3. Show all available tools:
     myrmex tools --token <token>

  4. Run 'uptime' command on agent-1:
     myrmex call agent-1__run_command --arguments '{"name":"uptime","args":[]}' --token <token>

  5. Ask the AI assistant to inspect memory usage:
     myrmex ask "Check memory usage on agent-nginx and explain it" --token <token>
     myrmex ask --plan "Restart nginx on agent-nginx if it's wedged"   (dry-run: plans, never executes)
     myrmex ask --all "Report disk usage and flag anything over 85%"   (fleet: every connected agent)
     myrmex ask --agents agent-1,agent-2 "How busy are these two?"      (fleet: a subset)

  6. Verify the integrity of the gateway's signed audit log:
     myrmex audit verify --log audit.log --host-key host_key.pub

  7. Watch the audit log continuously and alert if it's ever tampered with:
     myrmex audit watch --log audit.log --host-key host_key.pub --interval 30

  8. Export the audit log to CSV for archival or a compliance reviewer:
     myrmex audit export --log audit.log --format csv --out audit.csv

  9. Print the gateway host public key to hand to an external auditor:
     myrmex audit pubkey --host-key host_key.pub

  10. Onboard a brand-new agent with one command (mints its own join token):
      myrmex bootstrap --agent-id agent-4 --gateway-addr gateway.example.com:2222 --token <admin-token>

  11. Mint a join token yourself, then redeem it on the agent host:
      myrmex enroll-token --agent-id agent-4 --token <admin-token>
      myrmex enroll --join-token <token> --agent-id agent-4 --public-key-file id_ed25519.pub

  12. Rotate an existing agent's key after a suspected compromise:
      myrmex rotate --agent-id agent-4 --public-key-file id_ed25519_new.pub --token <admin-token>

Audit Verify Options:
  --log         Path to the audit log file (default: audit.log)
  --host-key    Path to the gateway's SSH host PUBLIC key in OpenSSH
                authorized-key format, e.g. host_key.pub (required)

Audit Watch Options:
  --log         Path to the audit log file (default: audit.log)
  --host-key    Path to the gateway's SSH host PUBLIC key in OpenSSH
                authorized-key format, e.g. host_key.pub (required)
  --interval    Seconds between checks (default: 30)

  Prints one status line per cycle to stdout. On the FIRST cycle that finds
  a signature or hash-chain failure, prints a single line
  "ALERT: audit log tamper detected at line N (<reason>)" to stderr and
  exits non-zero — it does not keep watching past the first detected
  tamper, so it never spams repeat alerts for the same break. Re-run the
  command to resume watching after investigating.

Audit Export Options:
  --log         Path to the audit log file (default: audit.log)
  --format      Output format: json, csv (default: json)
  --out         Write output to this file instead of stdout (optional)

Audit Pubkey Options:
  --host-key    Path to the gateway's SSH host PUBLIC key in OpenSSH
                authorized-key format, e.g. host_key.pub (required)

Enroll-Token Options:
  --agent-id    Agent ID the token will be bound to (required)
  (Requires an admin --token / MYRMEX_TOKEN.)

Enroll Options:
  --join-token       One-time join token from 'enroll-token' (required)
  --agent-id         Agent ID being enrolled, must match the token (required)
  --public-key-file  Path to the agent's OpenSSH PUBLIC key file (required)
  (No bearer --token is needed: the join token IS the credential.)

Bootstrap Options:
  --agent-id       Agent ID to onboard (required)
  --gateway-addr   Gateway SSH address, host:port (default: localhost:2222)
  --join-token     Existing join token to redeem. If omitted, an admin
                   --token / MYRMEX_TOKEN is used to mint one automatically.
  --key-out        Path to write the new private key (default: ./id_ed25519)
  --config-out     Path to write the generated agent_config.json
                   (default: ./agent_config.json)

  Generates a new Ed25519 keypair, enrolls the public half with the
  Gateway, and writes a ready-to-run agent_config.json. One command from
  nothing to a runnable agent.

Rotate Options:
  --agent-id         Agent ID whose key is being rotated (required)
  --public-key-file  Path to the NEW OpenSSH PUBLIC key file (required)
  --join-token       Existing join token to redeem. If omitted, an admin
                     --token / MYRMEX_TOKEN is used to mint one automatically.
  --revoke-old       After enrolling the new key, also revoke the agent's
                     old keys via /api/agents/revoke. NOTE: revocation
                     removes ALL authorized_keys entries for this agent-id,
                     including the one just enrolled, and drops any live
                     session. Only pass this once the new key is confirmed
                     working, then re-enroll if needed — see
                     docs/ENROLLMENT.md for the recommended sequence.
`
	fmt.Print(helpText)
}

func makeRequest(client *http.Client, cfg Config, method, path string, body io.Reader) ([]byte, error) {
	reqURL := strings.TrimRight(cfg.URL, "/") + path
	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+cfg.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

func handleStatus(client *http.Client, cfg Config) {
	data, err := makeRequest(client, cfg, "GET", "/api/status", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to retrieve status: %v\n", err)
		os.Exit(1)
	}

	if cfg.Output == "json" {
		fmt.Println(string(data))
		return
	}

	var status struct {
		Agents []struct {
			ID        string   `json:"id"`
			IP        string   `json:"ip"`
			OSVersion string   `json:"os_version"`
			Services  []string `json:"running_services"`
		} `json:"agents"`
		Upstreams []struct {
			Name   string `json:"name"`
			URL    string `json:"url"`
			Status string `json:"status"`
		} `json:"upstreams"`
	}

	if err := json.Unmarshal(data, &status); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("=== Connected Edge Agents ===")
	if len(status.Agents) == 0 {
		fmt.Println("No agents connected.")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "AGENT ID\tIP ADDRESS\tOS VERSION\tSERVICES")
		for _, a := range status.Agents {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", a.ID, a.IP, a.OSVersion, strings.Join(a.Services, ", "))
		}
		w.Flush()
	}
	fmt.Println()

	fmt.Println("=== Configure Upstream Servers ===")
	if len(status.Upstreams) == 0 {
		fmt.Println("No upstream servers configured.")
	} else {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "SERVER NAME\tTRANSPORT/URL\tSTATUS")
		for _, u := range status.Upstreams {
			fmt.Fprintf(w, "%s\t%s\t%s\n", u.Name, u.URL, u.Status)
		}
		w.Flush()
	}
}

func handleAgents(client *http.Client, cfg Config) {
	data, err := makeRequest(client, cfg, "GET", "/api/status", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.Output == "json" {
		var status map[string]interface{}
		if err := json.Unmarshal(data, &status); err == nil {
			agentsOnly, _ := json.MarshalIndent(status["agents"], "", "  ")
			fmt.Println(string(agentsOnly))
		}
		return
	}

	var status struct {
		Agents []struct {
			ID        string   `json:"id"`
			IP        string   `json:"ip"`
			OSVersion string   `json:"os_version"`
			Services  []string `json:"running_services"`
			OpenPorts []string `json:"open_ports"`
		} `json:"agents"`
	}

	if err := json.Unmarshal(data, &status); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "AGENT ID\tIP ADDRESS\tOS VERSION\tSERVICES\tPORTS")
	for _, a := range status.Agents {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", a.ID, a.IP, a.OSVersion, strings.Join(a.Services, ", "), strings.Join(a.OpenPorts, ", "))
	}
	w.Flush()
}

func handleUpstreams(client *http.Client, cfg Config) {
	data, err := makeRequest(client, cfg, "GET", "/api/status", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.Output == "json" {
		var status map[string]interface{}
		if err := json.Unmarshal(data, &status); err == nil {
			upstreamsOnly, _ := json.MarshalIndent(status["upstreams"], "", "  ")
			fmt.Println(string(upstreamsOnly))
		}
		return
	}

	var status struct {
		Upstreams []struct {
			Name   string `json:"name"`
			URL    string `json:"url"`
			Status string `json:"status"`
		} `json:"upstreams"`
	}

	if err := json.Unmarshal(data, &status); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SERVER NAME\tTRANSPORT/URL\tSTATUS")
	for _, u := range status.Upstreams {
		fmt.Fprintf(w, "%s\t%s\t%s\n", u.Name, u.URL, u.Status)
	}
	w.Flush()
}

func handleTools(client *http.Client, cfg Config) {
	data, err := makeRequest(client, cfg, "GET", "/api/tools", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.Output == "json" {
		fmt.Println(string(data))
		return
	}

	var resp struct {
		Tools []struct {
			Name        string `json:"name"`
			Description string `json:"description"`
		} `json:"tools"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "TOOL NAME\tDESCRIPTION")
	for _, t := range resp.Tools {
		desc := t.Description
		if len(desc) > 60 {
			desc = desc[:57] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\n", t.Name, desc)
	}
	w.Flush()
}

func handleConfig(client *http.Client, cfg Config) {
	data, err := makeRequest(client, cfg, "GET", "/api/config", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var config map[string]interface{}
	if err := json.Unmarshal(data, &config); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	indent, _ := json.MarshalIndent(config, "", "  ")
	fmt.Println(string(indent))
}

func handleCall(client *http.Client, cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Tool name is required for 'call' command.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex call <tool_name> [--arguments '{\"arg1\":\"val1\"}']")
		os.Exit(1)
	}

	toolName := args[0]
	var rawArgs string

	for i := 1; i < len(args); i++ {
		if args[i] == "--arguments" || args[i] == "-a" {
			if i+1 < len(args) {
				rawArgs = args[i+1]
				i++
			}
		}
	}

	if rawArgs == "" {
		rawArgs = "{}"
	}

	var jsonArgs json.RawMessage
	if err := json.Unmarshal([]byte(rawArgs), &jsonArgs); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Invalid JSON arguments: %v\n", err)
		os.Exit(1)
	}

	reqBody, _ := json.Marshal(map[string]interface{}{
		"name":      toolName,
		"arguments": jsonArgs,
	})

	data, err := makeRequest(client, cfg, "POST", "/api/call", bytes.NewReader(reqBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var rpcResp struct {
		Result interface{} `json:"result"`
		Error  interface{} `json:"error"`
	}

	if err := json.Unmarshal(data, &rpcResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if rpcResp.Error != nil {
		errBytes, _ := json.MarshalIndent(rpcResp.Error, "", "  ")
		fmt.Fprintf(os.Stderr, "Tool Execution Error:\n%s\n", string(errBytes))
		os.Exit(1)
	}

	if cfg.Output == "json" {
		// Attempt to extract nested JSON payload if it exists
		var mcpRes struct {
			Content []struct {
				Type string          `json:"type"`
				Text json.RawMessage `json:"text"`
			} `json:"content"`
		}
		resultJSON, _ := json.Marshal(rpcResp.Result)
		if err := json.Unmarshal(resultJSON, &mcpRes); err == nil && len(mcpRes.Content) > 0 {
			var extracted interface{}
			if err := json.Unmarshal(mcpRes.Content[0].Text, &extracted); err == nil {
				if str, ok := extracted.(string); ok {
					var nested interface{}
					if err := json.Unmarshal([]byte(str), &nested); err == nil {
						indent, _ := json.MarshalIndent(nested, "", "  ")
						fmt.Println(string(indent))
						return
					}
				}
				indent, _ := json.MarshalIndent(extracted, "", "  ")
				fmt.Println(string(indent))
				return
			}
		}

		resultBytes, _ := json.MarshalIndent(rpcResp.Result, "", "  ")
		fmt.Println(string(resultBytes))
		return
	}

	resultBytes, _ := json.Marshal(rpcResp.Result)
	printReadableText(string(resultBytes))
	fmt.Println()
}

func handleAsk(client *http.Client, cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Prompt message is required for 'ask' command.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex ask \"How is my system CPU usage?\"")
		os.Exit(1)
	}

	prompt := args[0]

	// Fleet mode (--all / --agents) reuses the Gateway's server-side fleet
	// orchestration via the gateway__ask_gemma tool instead of the client-side
	// loop below, so the per-agent aggregation lives in exactly one place.
	if cfg.AllAgents || cfg.AgentIDs != "" {
		handleFleetAsk(client, cfg, prompt)
		return
	}

	// 1. Get the list of all tools to provide context to the model
	toolsData, err := makeRequest(client, cfg, "GET", "/api/tools", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Failed to retrieve tools list: %v. Continuing without tools context.\n", err)
	}

	var toolsResp struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	var toolNames []string
	if err == nil {
		if err := json.Unmarshal(toolsData, &toolsResp); err == nil {
			for _, t := range toolsResp.Tools {
				toolNames = append(toolNames, t.Name)
			}
		}
	}

	// 2. Query status to get active agents and upstreams count
	statusData, err := makeRequest(client, cfg, "GET", "/api/status", nil)
	var countAgents int
	var countUpstreams int
	if err == nil {
		var status struct {
			Agents    []interface{} `json:"agents"`
			Upstreams []interface{} `json:"upstreams"`
		}
		if err := json.Unmarshal(statusData, &status); err == nil {
			countAgents = len(status.Agents)
			countUpstreams = len(status.Upstreams)
		}
	}

	systemPrompt := fmt.Sprintf(
		"You are the Myrmex Assistant. You can monitor status and run approved commands using tools."+
			" Context: Connected Edge Agents count = %d; Registered Upstream Servers count = %d."+
			" Available tools: %s."+
			" If you need to perform an action (e.g. check status, run command, read logs), respond with a SINGLE JSON command block:"+
			" {\"call\": \"tool_name\", \"arguments\": {...}}"+
			" Do not include other text when calling a tool. If you do not need any tools to answer, respond normally with plain text.",
		countAgents, countUpstreams, mustMarshalJSON(toolNames),
	)

	history := []map[string]string{}
	promptToModel := prompt
	loopCount := 0
	maxLoops := 5

	var finalResponse string
	var plannedCalls []string

	for loopCount < maxLoops {
		loopCount++

		reqBody, _ := json.Marshal(map[string]interface{}{
			"provider": "antigravity",
			"prompt":   promptToModel,
			"history":  history,
			"system":   systemPrompt,
		})

		data, err := makeRequest(client, cfg, "POST", "/api/chat", bytes.NewReader(reqBody))
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error calling assistant: %v\n", err)
			os.Exit(1)
		}

		var chatResp struct {
			Response string `json:"response"`
		}
		if err := json.Unmarshal(data, &chatResp); err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing assistant response: %v\n", err)
			os.Exit(1)
		}

		reply := strings.TrimSpace(chatResp.Response)
		if reply == "" {
			fmt.Fprintln(os.Stderr, "Error: Empty response from model.")
			os.Exit(1)
		}

		// Try to parse tool call from markdown or raw string
		var isToolCall bool
		var toolCallObj struct {
			Call      string          `json:"call"`
			Arguments json.RawMessage `json:"arguments"`
		}

		jsonText := reply
		if strings.Contains(reply, "```") {
			start := strings.Index(reply, "```")
			end := strings.LastIndex(reply, "```")
			if start != -1 && end != -1 && start < end {
				content := reply[start+3 : end]
				if strings.HasPrefix(strings.TrimSpace(content), "json") {
					jsonText = strings.TrimSpace(content)[4:]
				} else {
					jsonText = strings.TrimSpace(content)
				}
			}
		}

		if err := json.Unmarshal([]byte(jsonText), &toolCallObj); err == nil && toolCallObj.Call != "" {
			isToolCall = true
		}

		if isToolCall {
			// Add to history
			history = append(history, map[string]string{"role": "user", "text": promptToModel})
			history = append(history, map[string]string{"role": "assistant", "text": reply})

			var toolResult string
			if cfg.Plan {
				// Plan mode: the assistant is still driven through the loop
				// so it can plan multiple steps, but nothing is dispatched
				// to /api/call — never touches an agent.
				if cfg.Output != "json" {
					fmt.Printf("[Myrmex Plan]: would execute tool %q with arguments: %s\n", toolCallObj.Call, string(toolCallObj.Arguments))
				}
				plannedCalls = append(plannedCalls, fmt.Sprintf("%s(%s)", toolCallObj.Call, string(toolCallObj.Arguments)))
				toolResult = "(dry-run: not executed)"
			} else {
				if cfg.Output != "json" {
					fmt.Printf("[Myrmex Agent Action]: Executing tool %q with arguments: %s\n", toolCallObj.Call, string(toolCallObj.Arguments))
				}

				// Execute tool call via /api/call
				callBody, _ := json.Marshal(map[string]interface{}{
					"name":      toolCallObj.Call,
					"arguments": toolCallObj.Arguments,
				})

				callData, err := makeRequest(client, cfg, "POST", "/api/call", bytes.NewReader(callBody))
				if err != nil {
					toolResult = fmt.Sprintf("Error calling tool: %v", err)
				} else {
					var rpcResp struct {
						Result json.RawMessage `json:"result"`
						Error  *struct {
							Message string `json:"message"`
						} `json:"error"`
					}
					if err := json.Unmarshal(callData, &rpcResp); err != nil {
						toolResult = fmt.Sprintf("Error parsing tool response: %v", err)
					} else if rpcResp.Error != nil {
						toolResult = fmt.Sprintf("Tool error: %s", rpcResp.Error.Message)
					} else {
						toolResult = string(rpcResp.Result)
					}
				}

				if cfg.Output != "json" {
					fmt.Printf("[Myrmex Tool Result]:\n")
					printReadableText(toolResult)
					fmt.Println()
				}
			}

			// Feed the result back to the model in the next step of the loop
			promptToModel = fmt.Sprintf("Tool %s returned result: %s", toolCallObj.Call, toolResult)
		} else {
			finalResponse = reply
			break
		}
	}

	if cfg.Plan && len(plannedCalls) > 0 {
		finalResponse = fmt.Sprintf("PLAN (dry-run — no tools were executed):\n- %s\n\n%s",
			strings.Join(plannedCalls, "\n- "), finalResponse)
	}

	if cfg.Output == "json" {
		outBytes, _ := json.MarshalIndent(map[string]string{"response": finalResponse}, "", "  ")
		fmt.Println(string(outBytes))
		return
	}

	fmt.Println(renderMarkdown(finalResponse))
}

// fleetAskArguments builds the arguments object for the gateway__ask_gemma tool
// when "ask" runs in fleet mode. AllAgents wins over AgentIDs; a comma-separated
// AgentIDs list is split and trimmed. Plan carries the dry-run flag through.
func fleetAskArguments(cfg Config, prompt string) map[string]interface{} {
	args := map[string]interface{}{"prompt": prompt}
	if cfg.AllAgents {
		args["all_agents"] = true
	} else if cfg.AgentIDs != "" {
		var ids []string
		for _, id := range strings.Split(cfg.AgentIDs, ",") {
			if id = strings.TrimSpace(id); id != "" {
				ids = append(ids, id)
			}
		}
		args["agent_ids"] = ids
	}
	if cfg.Plan {
		args["plan"] = true
	}
	return args
}

// handleFleetAsk runs a fleet-wide "ask" by invoking the gateway__ask_gemma tool
// over /api/call, then renders the aggregated per-agent summary the Gateway
// returns.
func handleFleetAsk(client *http.Client, cfg Config, prompt string) {
	callBody, _ := json.Marshal(map[string]interface{}{
		"name":      "gateway__ask_gemma",
		"arguments": fleetAskArguments(cfg, prompt),
	})

	data, err := makeRequest(client, cfg, "POST", "/api/call", bytes.NewReader(callBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error calling assistant: %v\n", err)
		os.Exit(1)
	}

	var rpcResp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &rpcResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error parsing assistant response: %v\n", err)
		os.Exit(1)
	}
	if rpcResp.Error != nil {
		fmt.Fprintf(os.Stderr, "Assistant error: %s\n", rpcResp.Error.Message)
		os.Exit(1)
	}

	text := extractContentText(rpcResp.Result)
	if cfg.Output == "json" {
		outBytes, _ := json.MarshalIndent(map[string]string{"response": text}, "", "  ")
		fmt.Println(string(outBytes))
		return
	}
	fmt.Println(renderMarkdown(text))
}

// extractContentText pulls the first text content block out of an MCP tool
// result ({"content":[{"type":"text","text":"..."}]}), falling back to the raw
// JSON when the shape is unexpected so nothing is silently dropped.
func extractContentText(result json.RawMessage) string {
	var shaped struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(result, &shaped); err == nil && len(shaped.Content) > 0 {
		return shaped.Content[0].Text
	}
	return string(result)
}

// handleAudit dispatches "audit" subcommands: "verify" checks integrity,
// "watch" polls the log on an interval and alerts on tamper, "export"
// re-emits the log as JSON/CSV, and "pubkey" prints the gateway's host
// public key for independent verification.
func handleAudit(cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Missing 'audit' subcommand.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex audit <verify|watch|export|pubkey> [options]")
		os.Exit(1)
	}

	switch args[0] {
	case "verify":
		handleAuditVerify(cfg, args[1:])
	case "watch":
		handleAuditWatch(args[1:])
	case "export":
		handleAuditExport(cfg, args[1:])
	case "pubkey":
		handleAuditPubkey(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown 'audit' subcommand %q.\n", args[0])
		fmt.Fprintln(os.Stderr, "Usage: myrmex audit <verify|watch|export|pubkey> [options]")
		os.Exit(1)
	}
}

// handleAuditVerify validates a gateway audit log: every entry's SSH
// signature over its own fields, and the PrevSig -> Signature hash chain
// linking each entry to the one before it.
func handleAuditVerify(cfg Config, args []string) {
	logPath := "audit.log"
	hostKeyPath := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--log":
			if i+1 < len(args) {
				logPath = args[i+1]
				i++
			}
		case "--host-key":
			if i+1 < len(args) {
				hostKeyPath = args[i+1]
				i++
			}
		}
	}

	if hostKeyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --host-key <path> is required for 'audit verify'.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex audit verify --log <path> --host-key <path>")
		os.Exit(1)
	}

	result, err := audit.VerifyFile(logPath, hostKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.Output == "json" {
		out := map[string]interface{}{
			"log":                logPath,
			"host_key":           hostKeyPath,
			"total_entries":      result.Total,
			"valid_entries":      result.Valid,
			"signature_failures": result.SigFailures,
			"chain_failures":     result.ChainFailures,
			"entries":            result.Results,
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
	} else {
		fmt.Printf("Verifying audit log %q against host key %q\n\n", logPath, hostKeyPath)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "LINE\tTIMESTAMP\tACTION\tSIGNATURE\tCHAIN\tNOTE")
		for _, r := range result.Results {
			sigStatus := "PASS"
			if !r.SigValid {
				sigStatus = "FAIL"
			}
			chainStatus := "PASS"
			if !r.ChainValid {
				chainStatus = "FAIL"
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", r.Line, r.Timestamp, r.Action, sigStatus, chainStatus, r.Error)
		}
		w.Flush()

		fmt.Println()
		fmt.Printf("Total entries: %d, Valid: %d, Signature failures: %d, Chain breaks: %d\n",
			result.Total, result.Valid, result.SigFailures, result.ChainFailures)
	}

	if result.SigFailures > 0 || result.ChainFailures > 0 {
		if cfg.Output != "json" {
			fmt.Println("Result: AUDIT LOG VERIFICATION FAILED")
		}
		os.Exit(1)
	}

	if cfg.Output != "json" {
		fmt.Println("Result: AUDIT LOG VERIFICATION PASSED")
	}
}

// handleAuditWatch periodically re-verifies the audit log's signature and
// hash chain, printing a one-line status each cycle.
//
// Design (kept intentionally simple): this is a stateless poller, not a
// diff-based one. It re-verifies the *entire* log from the first line on
// every cycle. The first time a cycle finds any signature or chain failure,
// it prints a single "ALERT: audit log tamper detected at line N (<reason>)"
// line to stderr and exits non-zero immediately — it does not keep
// watching afterward. This means it never re-alerts for the same tamper
// (there is only ever one alert, on first detection), and it makes the
// process exit code a reliable one-shot signal for a supervisor/monitor
// (systemd, `myrmex audit watch ... || page-oncall`, etc.) to act on. To
// resume watching after investigating/rotating the log, just re-run the
// command.
func handleAuditWatch(args []string) {
	logPath := "audit.log"
	hostKeyPath := ""
	interval := 30

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--log":
			if i+1 < len(args) {
				logPath = args[i+1]
				i++
			}
		case "--host-key":
			if i+1 < len(args) {
				hostKeyPath = args[i+1]
				i++
			}
		case "--interval":
			if i+1 < len(args) {
				if v, err := strconv.Atoi(args[i+1]); err == nil && v > 0 {
					interval = v
				}
				i++
			}
		}
	}

	if hostKeyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --host-key <path> is required for 'audit watch'.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex audit watch --log <path> --host-key <path> [--interval <seconds>]")
		os.Exit(1)
	}

	fmt.Printf("Watching audit log %q for tampering (host key %q, checking every %ds)...\n", logPath, hostKeyPath, interval)

	check := func() {
		result, err := audit.VerifyFile(logPath, hostKeyPath)
		now := time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			fmt.Printf("[%s] check error: %v\n", now, err)
			return
		}

		if result.SigFailures > 0 || result.ChainFailures > 0 {
			fmt.Printf("[%s] entries=%d valid=%d signature_failures=%d chain_failures=%d status=FAILED\n",
				now, result.Total, result.Valid, result.SigFailures, result.ChainFailures)
			fmt.Fprintf(os.Stderr, "ALERT: audit log tamper detected at line %d (%s)\n",
				result.FirstBadLine, result.FirstBadReason)
			os.Exit(1)
		}

		fmt.Printf("[%s] entries=%d valid=%d status=OK\n", now, result.Total, result.Valid)
	}

	// Check immediately on start, then every tick thereafter.
	check()

	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		check()
	}
}

// handleAuditExport reads a gateway audit log and re-emits it as either a JSON
// array (default) or CSV. It is a local, read-only operation and requires no
// Gateway auth token. Output goes to --out if given, otherwise stdout.
func handleAuditExport(cfg Config, args []string) {
	logPath := "audit.log"
	format := "json"
	outPath := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--log":
			if i+1 < len(args) {
				logPath = args[i+1]
				i++
			}
		case "--format":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		case "--out":
			if i+1 < len(args) {
				outPath = args[i+1]
				i++
			}
		}
	}

	if format != "json" && format != "csv" {
		fmt.Fprintf(os.Stderr, "Error: Unknown export format %q (expected 'json' or 'csv').\n", format)
		os.Exit(1)
	}

	f, err := os.Open(logPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to open audit log %q: %v\n", logPath, err)
		os.Exit(1)
	}
	defer f.Close()

	var entries []audit.Entry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry audit.Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Invalid JSON on line %d of %q: %v\n", lineNum, logPath, err)
			os.Exit(1)
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read audit log %q: %v\n", logPath, err)
		os.Exit(1)
	}

	// Select the output writer: a file when --out is given, else stdout.
	var out io.Writer = os.Stdout
	if outPath != "" {
		of, err := os.Create(outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to create output file %q: %v\n", outPath, err)
			os.Exit(1)
		}
		defer of.Close()
		out = of
	}

	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if entries == nil {
			entries = []audit.Entry{}
		}
		if err := enc.Encode(entries); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to encode JSON: %v\n", err)
			os.Exit(1)
		}
	case "csv":
		w := csv.NewWriter(out)
		header := []string{"timestamp", "token_id", "role", "action", "agent_id", "command", "status", "details", "signature"}
		if err := w.Write(header); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to write CSV header: %v\n", err)
			os.Exit(1)
		}
		for _, e := range entries {
			row := []string{e.Timestamp, e.TokenID, e.Role, e.Action, e.AgentID, e.Command, e.Status, e.Details, e.Signature}
			if err := w.Write(row); err != nil {
				fmt.Fprintf(os.Stderr, "Error: Failed to write CSV row: %v\n", err)
				os.Exit(1)
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to flush CSV: %v\n", err)
			os.Exit(1)
		}
	}

	if outPath != "" {
		fmt.Fprintf(os.Stderr, "Exported %d audit entries to %q as %s.\n", len(entries), outPath, format)
	}
}

// handleAuditPubkey reads the gateway host PUBLIC key file and prints it in
// OpenSSH authorized-key format so an external auditor can be handed the exact
// key needed to verify audit-log signatures independently. Local, read-only.
func handleAuditPubkey(args []string) {
	hostKeyPath := ""
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--host-key":
			if i+1 < len(args) {
				hostKeyPath = args[i+1]
				i++
			}
		}
	}

	if hostKeyPath == "" {
		fmt.Fprintln(os.Stderr, "Error: --host-key <path> is required for 'audit pubkey'.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex audit pubkey --host-key <path>")
		os.Exit(1)
	}

	keyBytes, err := os.ReadFile(hostKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read host key %q: %v\n", hostKeyPath, err)
		os.Exit(1)
	}

	// Validate that the file really is an OpenSSH authorized-key so we never
	// hand an auditor a malformed or private key by mistake.
	pub, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %q is not a valid OpenSSH public key: %v\n", hostKeyPath, err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Gateway host public key (%s) — give this to auditors to verify audit-log signatures with 'myrmex audit verify':\n", pub.Type())
	fmt.Println(strings.TrimSpace(string(keyBytes)))
}

// --- Agent enrollment, bootstrap, and rotation (Lifecycle epics #61, #49) ---
//
// These commands drive the gateway's join-token enrollment endpoints
// (POST /api/enroll/token, POST /api/enroll) and its revocation endpoint
// (POST /api/agents/revoke). See docs/ENROLLMENT.md for the full lifecycle
// this implements: mint token -> enroll -> connect -> rotate/revoke.

// makeUnauthRequest is like makeRequest but omits the Authorization header.
// It exists because POST /api/enroll is deliberately unauthenticated on the
// gateway side — the join token itself is the one-time credential — so
// sending a (possibly empty or stale) bearer token would be misleading.
func makeUnauthRequest(client *http.Client, cfg Config, method, path string, body io.Reader) ([]byte, error) {
	reqURL := strings.TrimRight(cfg.URL, "/") + path
	req, err := http.NewRequest(method, reqURL, body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}

// mintJoinToken calls the admin-only POST /api/enroll/token and returns the
// minted join token and its expiry timestamp.
func mintJoinToken(client *http.Client, cfg Config, agentID string) (joinToken, expiresAt string, err error) {
	reqBody, _ := json.Marshal(map[string]string{"agent_id": agentID})
	data, err := makeRequest(client, cfg, "POST", "/api/enroll/token", bytes.NewReader(reqBody))
	if err != nil {
		return "", "", err
	}

	var resp struct {
		JoinToken string `json:"join_token"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", "", fmt.Errorf("parsing enroll-token response: %w", err)
	}
	return resp.JoinToken, resp.ExpiresAt, nil
}

// enrollPublicKey redeems a join token via the unauthenticated POST
// /api/enroll, registering publicKey (an OpenSSH authorized-key line) under
// agentID.
func enrollPublicKey(client *http.Client, cfg Config, joinToken, agentID, publicKey string) (map[string]interface{}, error) {
	reqBody, _ := json.Marshal(map[string]string{
		"join_token": joinToken,
		"agent_id":   agentID,
		"public_key": strings.TrimSpace(publicKey),
	})

	data, err := makeUnauthRequest(client, cfg, "POST", "/api/enroll", bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing enroll response: %w", err)
	}
	return result, nil
}

// handleEnrollToken mints a join token for a new agent-id. Admin --token
// required.
func handleEnrollToken(client *http.Client, cfg Config, args []string) {
	agentID := ""
	for i := 0; i < len(args); i++ {
		if args[i] == "--agent-id" && i+1 < len(args) {
			agentID = args[i+1]
			i++
		}
	}

	if agentID == "" {
		fmt.Fprintln(os.Stderr, "Error: --agent-id <id> is required for 'enroll-token'.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex enroll-token --agent-id <id> --token <admin-token>")
		os.Exit(1)
	}

	token, expiresAt, err := mintJoinToken(client, cfg, agentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.Output == "json" {
		b, _ := json.MarshalIndent(map[string]string{
			"join_token": token,
			"agent_id":   agentID,
			"expires_at": expiresAt,
		}, "", "  ")
		fmt.Println(string(b))
		return
	}

	fmt.Printf("Join token for agent %q (expires %s):\n%s\n", agentID, expiresAt, token)
}

// handleEnroll redeems an existing join token, registering the given public
// key file with the gateway. No bearer --token is required — the join token
// is the credential.
func handleEnroll(client *http.Client, cfg Config, args []string) {
	joinToken := ""
	agentID := ""
	pubKeyFile := ""

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--join-token":
			if i+1 < len(args) {
				joinToken = args[i+1]
				i++
			}
		case "--agent-id":
			if i+1 < len(args) {
				agentID = args[i+1]
				i++
			}
		case "--public-key-file":
			if i+1 < len(args) {
				pubKeyFile = args[i+1]
				i++
			}
		}
	}

	if joinToken == "" || agentID == "" || pubKeyFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --join-token, --agent-id, and --public-key-file are all required for 'enroll'.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex enroll --join-token <token> --agent-id <id> --public-key-file <path>")
		os.Exit(1)
	}

	pubKeyBytes, err := os.ReadFile(pubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read public key file %q: %v\n", pubKeyFile, err)
		os.Exit(1)
	}

	result, err := enrollPublicKey(client, cfg, joinToken, agentID, string(pubKeyBytes))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if cfg.Output == "json" {
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
		return
	}

	fmt.Printf("Agent %q enrolled successfully.\n", agentID)
}

// generateAgentKeypair creates a new Ed25519 keypair for an agent, returning
// its OpenSSH authorized-key line (comment set to agentID) and its OpenSSH
// PEM-encoded private key bytes.
func generateAgentKeypair(agentID string) (authorizedKeyLine string, privatePEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("generating ed25519 keypair: %w", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("converting public key: %w", err)
	}
	authorizedKeyLine = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " " + agentID

	pemBlock, err := ssh.MarshalPrivateKey(priv, agentID)
	if err != nil {
		return "", nil, fmt.Errorf("marshaling private key: %w", err)
	}
	privatePEM = pem.EncodeToMemory(pemBlock)

	return authorizedKeyLine, privatePEM, nil
}

// handleBootstrap is one-command onboarding (#61): it generates a new
// Ed25519 keypair, enrolls the public half with the gateway (minting a join
// token first if one wasn't supplied), and writes a ready-to-run
// agent_config.json alongside the private key.
func handleBootstrap(client *http.Client, cfg Config, args []string) {
	agentID := ""
	gatewayAddr := "localhost:2222"
	joinToken := ""
	keyOut := "id_ed25519"
	configOut := "agent_config.json"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--agent-id":
			if i+1 < len(args) {
				agentID = args[i+1]
				i++
			}
		case "--gateway-addr":
			if i+1 < len(args) {
				gatewayAddr = args[i+1]
				i++
			}
		case "--join-token":
			if i+1 < len(args) {
				joinToken = args[i+1]
				i++
			}
		case "--key-out":
			if i+1 < len(args) {
				keyOut = args[i+1]
				i++
			}
		case "--config-out":
			if i+1 < len(args) {
				configOut = args[i+1]
				i++
			}
		}
	}

	if agentID == "" {
		fmt.Fprintln(os.Stderr, "Error: --agent-id <id> is required for 'bootstrap'.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex bootstrap --agent-id <id> [--gateway-addr host:2222] [--join-token T] [--key-out PATH] [--config-out PATH]")
		os.Exit(1)
	}

	if joinToken == "" {
		if cfg.Token == "" {
			fmt.Fprintln(os.Stderr, "Error: 'bootstrap' needs either --join-token, or an admin --token/MYRMEX_TOKEN to mint one.")
			os.Exit(1)
		}
		var expiresAt string
		var err error
		joinToken, expiresAt, err = mintJoinToken(client, cfg, agentID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to mint join token: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Minted join token for %q (expires %s).\n", agentID, expiresAt)
	}

	authorizedKeyLine, privatePEM, err := generateAgentKeypair(agentID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if err := os.WriteFile(keyOut, privatePEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to write private key to %q: %v\n", keyOut, err)
		os.Exit(1)
	}
	pubKeyOutPath := keyOut + ".pub"
	if err := os.WriteFile(pubKeyOutPath, []byte(authorizedKeyLine+"\n"), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to write public key to %q: %v\n", pubKeyOutPath, err)
		os.Exit(1)
	}

	if _, err := enrollPublicKey(client, cfg, joinToken, agentID, authorizedKeyLine); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to enroll public key with gateway: %v\n", err)
		os.Exit(1)
	}

	knownHostKeyPath := keyOut + ".gateway_hostkey"
	agentConfig := map[string]interface{}{
		"agent_id":            agentID,
		"gateway_addr":        gatewayAddr,
		"private_key_path":    keyOut,
		"known_host_key_path": knownHostKeyPath,
		"allowed_commands":    []interface{}{},
	}
	configBytes, _ := json.MarshalIndent(agentConfig, "", "  ")
	if err := os.WriteFile(configOut, configBytes, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to write agent config to %q: %v\n", configOut, err)
		os.Exit(1)
	}

	if cfg.Output == "json" {
		b, _ := json.MarshalIndent(map[string]string{
			"agent_id":    agentID,
			"key_path":    keyOut,
			"pubkey_path": pubKeyOutPath,
			"config_path": configOut,
		}, "", "  ")
		fmt.Println(string(b))
		return
	}

	fmt.Printf("Agent %q bootstrapped successfully.\n\n", agentID)
	fmt.Printf("  Private key: %s (0600)\n", keyOut)
	fmt.Printf("  Public key:  %s\n", pubKeyOutPath)
	fmt.Printf("  Config:      %s\n", configOut)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Printf("  1. Copy %s and %s to the target host.\n", keyOut, configOut)
	fmt.Printf("  2. Edit allowed_commands in %s to grant this agent commands.\n", configOut)
	fmt.Printf("  3. Run: agent --config %s\n", configOut)
	fmt.Println("     (The agent trust-on-first-use pins the gateway host key to")
	fmt.Printf("     %s on its first successful connect.)\n", knownHostKeyPath)
}

// handleRotate enrolls a replacement public key for an existing agent-id
// (#49). It mints a join token if one wasn't supplied, then redeems it via
// enrollPublicKey exactly like a fresh enrollment — the gateway's
// authorized_keys format allows multiple keys per agent-id, so the new key
// works immediately alongside the old one. If --revoke-old is set, it then
// calls POST /api/agents/revoke, which removes ALL keys (old AND the one
// just enrolled) for this agent-id and drops any live session; see
// docs/ENROLLMENT.md for the recommended re-enroll-after-revoke sequence.
func handleRotate(client *http.Client, cfg Config, args []string) {
	agentID := ""
	pubKeyFile := ""
	joinToken := ""
	revokeOld := false

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--agent-id":
			if i+1 < len(args) {
				agentID = args[i+1]
				i++
			}
		case "--public-key-file":
			if i+1 < len(args) {
				pubKeyFile = args[i+1]
				i++
			}
		case "--join-token":
			if i+1 < len(args) {
				joinToken = args[i+1]
				i++
			}
		case "--revoke-old":
			if i+1 < len(args) && (args[i+1] == "true" || args[i+1] == "false") {
				revokeOld = args[i+1] == "true"
				i++
			} else {
				revokeOld = true
			}
		}
	}

	if agentID == "" || pubKeyFile == "" {
		fmt.Fprintln(os.Stderr, "Error: --agent-id and --public-key-file are required for 'rotate'.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex rotate --agent-id <id> --public-key-file <path> [--join-token T] [--revoke-old]")
		os.Exit(1)
	}

	if joinToken == "" {
		if cfg.Token == "" {
			fmt.Fprintln(os.Stderr, "Error: 'rotate' needs either --join-token, or an admin --token/MYRMEX_TOKEN to mint one.")
			os.Exit(1)
		}
		var expiresAt string
		var err error
		joinToken, expiresAt, err = mintJoinToken(client, cfg, agentID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: Failed to mint join token: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Minted join token for %q (expires %s).\n", agentID, expiresAt)
	}

	pubKeyBytes, err := os.ReadFile(pubKeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to read public key file %q: %v\n", pubKeyFile, err)
		os.Exit(1)
	}

	if _, err := enrollPublicKey(client, cfg, joinToken, agentID, string(pubKeyBytes)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: Failed to enroll new public key: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "New public key enrolled for agent %q.\n", agentID)

	if !revokeOld {
		if cfg.Output == "json" {
			b, _ := json.MarshalIndent(map[string]interface{}{
				"agent_id":         agentID,
				"new_key_enrolled": true,
				"revoked":          false,
			}, "", "  ")
			fmt.Println(string(b))
		} else {
			fmt.Println("Rotation complete: new key is live alongside any existing keys for this agent.")
			fmt.Println("(Old keys were NOT revoked; pass --revoke-old to remove them, or run")
			fmt.Println(" 'myrmex agents revoke' manually once the new key is confirmed working.)")
		}
		return
	}

	if cfg.Token == "" {
		fmt.Fprintln(os.Stderr, "Error: --revoke-old requires an admin --token/MYRMEX_TOKEN to call /api/agents/revoke.")
		os.Exit(1)
	}

	revokeBody, _ := json.Marshal(map[string]string{"agent_id": agentID})
	revokeData, err := makeRequest(client, cfg, "POST", "/api/agents/revoke", bytes.NewReader(revokeBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: New key enrolled, but revoking old keys failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "The agent now has BOTH old and new keys authorized. Retry revocation manually,")
		fmt.Fprintln(os.Stderr, "then re-run 'myrmex rotate' (or 'myrmex enroll') to re-add the new key.")
		os.Exit(1)
	}

	if cfg.Output == "json" {
		fmt.Println(string(revokeData))
		return
	}

	var revokeResp struct {
		Revoked        bool `json:"revoked"`
		KeysRemoved    int  `json:"keys_removed"`
		SessionDropped bool `json:"session_dropped"`
	}
	if err := json.Unmarshal(revokeData, &revokeResp); err == nil {
		fmt.Printf("All keys for agent %q revoked (removed %d entries, session_dropped=%v).\n",
			agentID, revokeResp.KeysRemoved, revokeResp.SessionDropped)
	}
	fmt.Println()
	fmt.Println("IMPORTANT: --revoke-old removes ALL authorized_keys entries for this")
	fmt.Println("agent-id, including the key just enrolled above. Re-enroll the new key now:")
	fmt.Printf("  myrmex enroll-token --agent-id %s --token <admin-token>\n", agentID)
	fmt.Printf("  myrmex enroll --join-token <token> --agent-id %s --public-key-file %s\n", agentID, pubKeyFile)
}

func mustMarshalJSON(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func printReadableText(text string) {
	// Check if it's an MCP result structure (e.g. {"content": [{"type": "text", "text": "..."}]})
	type mcpResult struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}

	var mcpRes mcpResult
	if err := json.Unmarshal([]byte(text), &mcpRes); err == nil && len(mcpRes.Content) > 0 {
		for _, item := range mcpRes.Content {
			if item.Type == "text" {
				printReadableText(item.Text)
			}
		}
		return
	}

	var js map[string]interface{}
	if err := json.Unmarshal([]byte(text), &js); err == nil {
		indent, _ := json.MarshalIndent(js, "", "  ")
		fmt.Println(string(indent))
		return
	}

	var jsArray []interface{}
	if err := json.Unmarshal([]byte(text), &jsArray); err == nil {
		indent, _ := json.MarshalIndent(jsArray, "", "  ")
		fmt.Println(string(indent))
		return
	}

	// Render as markdown if it has markdown indicators, otherwise print as-is
	if strings.Contains(text, "**") || strings.Contains(text, "###") || strings.Contains(text, "```") || strings.Contains(text, "`") {
		fmt.Print(renderMarkdown(text))
	} else {
		fmt.Print(text)
	}
}

func renderMarkdown(input string) string {
	lines := strings.Split(input, "\n")
	var result []string
	inCodeBlock := false

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Code blocks
		if strings.HasPrefix(trimmed, "```") {
			inCodeBlock = !inCodeBlock
			if inCodeBlock {
				result = append(result, "  \x1b[90m┌────────────────────────────────────────────────────────────\x1b[0m")
			} else {
				result = append(result, "  \x1b[90m└────────────────────────────────────────────────────────────\x1b[0m")
			}
			continue
		}

		if inCodeBlock {
			// Inside code block: indent and color cyan/gray
			result = append(result, "  \x1b[90m│\x1b[0m  \x1b[36m"+line+"\x1b[0m")
			continue
		}

		// Headers
		if strings.HasPrefix(trimmed, "# ") {
			title := strings.TrimPrefix(trimmed, "# ")
			result = append(result, "\n\x1b[1m\x1b[35m"+strings.ToUpper(title)+"\x1b[0m\n"+strings.Repeat("=", len(title)))
			continue
		} else if strings.HasPrefix(trimmed, "## ") {
			title := strings.TrimPrefix(trimmed, "## ")
			result = append(result, "\n\x1b[1m\x1b[34m"+title+"\x1b[0m\n"+strings.Repeat("-", len(title)))
			continue
		} else if strings.HasPrefix(trimmed, "### ") {
			title := strings.TrimPrefix(trimmed, "### ")
			result = append(result, "\n\x1b[1m\x1b[32m"+title+"\x1b[0m")
			continue
		} else if strings.HasPrefix(trimmed, "#### ") {
			title := strings.TrimPrefix(trimmed, "#### ")
			result = append(result, "\n\x1b[1m"+title+"\x1b[0m")
			continue
		}

		// List items
		if strings.HasPrefix(trimmed, "* ") || strings.HasPrefix(trimmed, "- ") || strings.HasPrefix(trimmed, "+ ") {
			var content string
			if strings.HasPrefix(trimmed, "* ") {
				content = strings.TrimPrefix(trimmed, "* ")
			} else if strings.HasPrefix(trimmed, "- ") {
				content = strings.TrimPrefix(trimmed, "- ")
			} else {
				content = strings.TrimPrefix(trimmed, "+ ")
			}
			content = formatInlineMarkdown(content)
			result = append(result, "  • "+content)
			continue
		}

		// Ordered list items
		if len(trimmed) > 2 && trimmed[0] >= '0' && trimmed[0] <= '9' {
			dotIdx := strings.Index(trimmed, ". ")
			if dotIdx > 0 && dotIdx < 5 {
				prefix := trimmed[:dotIdx]
				content := formatInlineMarkdown(trimmed[dotIdx+2:])
				result = append(result, "  "+prefix+". "+content)
				continue
			}
		}

		// Regular line
		result = append(result, formatInlineMarkdown(line))
	}

	return strings.Join(result, "\n")
}

func formatInlineMarkdown(text string) string {
	// Bold: **text** -> \x1b[1mtext\x1b[0m
	text = replacePattern(text, "**", "\x1b[1m", "\x1b[0m")
	// Inline code: `code` -> \x1b[33mcode\x1b[0m
	text = replacePattern(text, "`", "\x1b[33m", "\x1b[0m")
	return text
}

func replacePattern(text, pattern, startTag, endTag string) string {
	for {
		startIdx := strings.Index(text, pattern)
		if startIdx == -1 {
			break
		}
		remaining := text[startIdx+len(pattern):]
		endIdx := strings.Index(remaining, pattern)
		if endIdx == -1 {
			break
		}

		before := text[:startIdx]
		matched := remaining[:endIdx]
		after := remaining[endIdx+len(pattern):]
		text = before + startTag + matched + endTag + after
	}
	return text
}
