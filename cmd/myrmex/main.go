package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/crypto/ssh"
)

type Config struct {
	URL      string
	Token    string
	Insecure bool
	Output   string
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

	// Parse custom flags manually for flexibility
	cfg := Config{
		URL:      "https://localhost:8080",
		Token:    os.Getenv("MYRMEX_TOKEN"),
		Insecure: false,
		Output:   "text",
	}

	var cmdArgs []string
	for i := 2; i < len(os.Args); i++ {
		arg := os.Args[i]
		if strings.HasPrefix(arg, "--") || strings.HasPrefix(arg, "-") {
			parts := strings.SplitN(arg, "=", 2)
			var key, val string
			if len(parts) == 2 {
				key = parts[0]
				val = parts[1]
			} else {
				key = arg
				if i+1 < len(os.Args) && !strings.HasPrefix(os.Args[i+1], "-") {
					val = os.Args[i+1]
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
				// Pass command-specific flags and values to cmdArgs
				cmdArgs = append(cmdArgs, key)
				if val != "" {
					cmdArgs = append(cmdArgs, val)
				}
			}
		} else {
			cmdArgs = append(cmdArgs, arg)
		}
	}

	// "audit verify" runs entirely against a local log file and host key, so it
	// does not require a Gateway auth token.
	if cfg.Token == "" && cmd != "audit" {
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
	default:
		fmt.Fprintf(os.Stderr, "Error: Unknown command %q\nRun 'myrmex --help' for details.\n", cmd)
		os.Exit(1)
	}
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

Global Options:
  --url         Gateway API base URL (default: https://localhost:8080)
  --token       Secure Gateway Auth Token (or MYRMEX_TOKEN env var)
  --insecure    Skip TLS verification (default: false)
  --output, -o  Output format: text, json (default: text)

Real-Life Scenarios:
  1. Check the general status of all agents:
     myrmex status --token <token>

  2. List the open ports on all connected agents in JSON format:
     myrmex agents --token <token> --output json

  3. Show all available tools:
     myrmex tools --token <token>

  4. Run 'uptime' command on agent-1:
     myrmex call agent-1__run_command --arguments '{"cmd":"uptime"}' --token <token>

  5. Ask the AI assistant to inspect memory usage:
     myrmex ask "Check memory usage on agent-nginx and explain it" --token <token>

  6. Verify the integrity of the gateway's signed audit log:
     myrmex audit verify --log audit.log --host-key host_key.pub

  7. Watch the audit log continuously and alert if it's ever tampered with:
     myrmex audit watch --log audit.log --host-key host_key.pub --interval 30

  8. Export the audit log to CSV for archival or a compliance reviewer:
     myrmex audit export --log audit.log --format csv --out audit.csv

  9. Print the gateway host public key to hand to an external auditor:
     myrmex audit pubkey --host-key host_key.pub

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
			if cfg.Output != "json" {
				fmt.Printf("[Myrmex Agent Action]: Executing tool %q with arguments: %s\n", toolCallObj.Call, string(toolCallObj.Arguments))
			}

			// Add to history
			history = append(history, map[string]string{"role": "user", "text": promptToModel})
			history = append(history, map[string]string{"role": "assistant", "text": reply})

			// Execute tool call via /api/call
			callBody, _ := json.Marshal(map[string]interface{}{
				"name":      toolCallObj.Call,
				"arguments": toolCallObj.Arguments,
			})

			callData, err := makeRequest(client, cfg, "POST", "/api/call", bytes.NewReader(callBody))
			var toolResult string
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

			// Feed the result back to the model in the next step of the loop
			promptToModel = fmt.Sprintf("Tool %s returned result: %s", toolCallObj.Call, toolResult)
		} else {
			finalResponse = reply
			break
		}
	}

	if cfg.Output == "json" {
		outBytes, _ := json.MarshalIndent(map[string]string{"response": finalResponse}, "", "  ")
		fmt.Println(string(outBytes))
		return
	}

	fmt.Println(renderMarkdown(finalResponse))
}

// auditEntry mirrors the gateway's AuditEntry JSON shape (cmd/gateway/main.go).
type auditEntry struct {
	Timestamp string `json:"timestamp"`
	TokenID   string `json:"token_id"`
	Role      string `json:"role"`
	Action    string `json:"action"`
	AgentID   string `json:"agent_id,omitempty"`
	Command   string `json:"command,omitempty"`
	Status    string `json:"status"`
	Details   string `json:"details"`
	PrevSig   string `json:"prev_sig,omitempty"`
	Signature string `json:"signature,omitempty"`
}

type auditLineResult struct {
	Line       int    `json:"line"`
	Timestamp  string `json:"timestamp"`
	Action     string `json:"action"`
	SigValid   bool   `json:"signature_valid"`
	ChainValid bool   `json:"chain_valid"`
	Error      string `json:"error,omitempty"`
}

// auditVerifyResult is the outcome of one full pass over an audit log,
// shared by "audit verify" (which prints it once) and "audit watch" (which
// prints a condensed line every polling cycle).
type auditVerifyResult struct {
	Results       []auditLineResult
	Total         int
	Valid         int
	SigFailures   int
	ChainFailures int
	// FirstBadLine is the 1-based line number of the first entry with a
	// signature or chain failure, or 0 if every entry verified cleanly.
	FirstBadLine int
	// FirstBadReason is the auditLineResult.Error text for FirstBadLine.
	FirstBadReason string
}

// verifyAuditLog re-verifies every entry in a gateway audit log: each
// entry's own SSH signature over its fields, and the PrevSig -> Signature
// hash chain linking it to the entry before it. It performs no printing —
// callers (handleAuditVerify, handleAuditWatch) render the result however
// they need. A returned error means the log/key could not even be read or
// parsed, distinct from tamper being found (which is reported in the
// returned auditVerifyResult).
func verifyAuditLog(logPath, hostKeyPath string) (auditVerifyResult, error) {
	var out auditVerifyResult

	keyBytes, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return out, fmt.Errorf("Failed to read host key %q: %v", hostKeyPath, err)
	}

	pub, _, _, _, err := ssh.ParseAuthorizedKey(keyBytes)
	if err != nil {
		return out, fmt.Errorf("Failed to parse host public key %q: %v", hostKeyPath, err)
	}

	f, err := os.Open(logPath)
	if err != nil {
		return out, fmt.Errorf("Failed to open audit log %q: %v", logPath, err)
	}
	defer f.Close()

	var prevSig string
	lineNum := 0

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		out.Total++

		res := auditLineResult{Line: lineNum}

		var entry auditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			res.Error = fmt.Sprintf("invalid JSON: %v", err)
			out.SigFailures++
			out.ChainFailures++
			if out.FirstBadLine == 0 {
				out.FirstBadLine = lineNum
				out.FirstBadReason = res.Error
			}
			out.Results = append(out.Results, res)
			// Leave prevSig untouched: we cannot trust anything derived from
			// this line, but subsequent entries may still chain correctly
			// from the last entry we could parse.
			continue
		}

		res.Timestamp = entry.Timestamp
		res.Action = entry.Action

		if entry.PrevSig == prevSig {
			res.ChainValid = true
		} else {
			out.ChainFailures++
			res.Error = fmt.Sprintf("chain break: prev_sig %q does not match previous entry's signature %q", entry.PrevSig, prevSig)
		}

		payload := strings.Join([]string{
			entry.Timestamp, entry.TokenID, entry.Role, entry.Action,
			entry.AgentID, entry.Command, entry.Status, entry.Details, entry.PrevSig,
		}, "|")

		blob, err := hex.DecodeString(entry.Signature)
		if err != nil {
			out.SigFailures++
			if res.Error != "" {
				res.Error += "; "
			}
			res.Error += fmt.Sprintf("invalid signature encoding: %v", err)
		} else {
			sig := &ssh.Signature{Format: pub.Type(), Blob: blob}
			if err := pub.Verify([]byte(payload), sig); err != nil {
				out.SigFailures++
				if res.Error != "" {
					res.Error += "; "
				}
				res.Error += fmt.Sprintf("signature verification failed: %v", err)
			} else {
				res.SigValid = true
			}
		}

		if (!res.SigValid || !res.ChainValid) && out.FirstBadLine == 0 {
			out.FirstBadLine = lineNum
			out.FirstBadReason = res.Error
		}

		out.Results = append(out.Results, res)
		prevSig = entry.Signature
	}

	if err := scanner.Err(); err != nil {
		return out, fmt.Errorf("Failed to read audit log %q: %v", logPath, err)
	}

	for _, r := range out.Results {
		if r.SigValid && r.ChainValid {
			out.Valid++
		}
	}

	return out, nil
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

	result, err := verifyAuditLog(logPath, hostKeyPath)
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
		result, err := verifyAuditLog(logPath, hostKeyPath)
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

	var entries []auditEntry
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry auditEntry
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
			entries = []auditEntry{}
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
