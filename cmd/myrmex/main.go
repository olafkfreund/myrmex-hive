package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

type Config struct {
	URL      string
	Token    string
	Insecure bool
	Output   string
}

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

	// Parse custom flags manually for flexibility
	cfg := Config{
		URL:      "https://localhost:8080",
		Token:    os.Getenv("MYRMEX_TOKEN"),
		Insecure: true,
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

			key = strings.TrimLeft(key, "-")
			switch key {
			case "url":
				cfg.URL = val
			case "token":
				cfg.Token = val
			case "insecure":
				cfg.Insecure = (val != "false")
			case "output", "o":
				cfg.Output = val
			}
		} else {
			cmdArgs = append(cmdArgs, arg)
		}
	}

	if cfg.Token == "" {
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

Global Options:
  --url         Gateway API base URL (default: https://localhost:8080)
  --token       Secure Gateway Auth Token (or MYRMEX_TOKEN env var)
  --insecure    Skip TLS verification (default: true)
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

	resultBytes, _ := json.MarshalIndent(rpcResp.Result, "", "  ")
	fmt.Println(string(resultBytes))
}

func handleAsk(client *http.Client, cfg Config, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "Error: Prompt message is required for 'ask' command.")
		fmt.Fprintln(os.Stderr, "Usage: myrmex ask \"How is my system CPU usage?\"")
		os.Exit(1)
	}

	prompt := args[0]

	reqBody, _ := json.Marshal(map[string]interface{}{
		"provider": "antigravity",
		"prompt":   prompt,
	})

	data, err := makeRequest(client, cfg, "POST", "/api/chat", bytes.NewReader(reqBody))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	var chatResp struct {
		Response string `json:"response"`
	}

	if err := json.Unmarshal(data, &chatResp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(chatResp.Response)
}
