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
