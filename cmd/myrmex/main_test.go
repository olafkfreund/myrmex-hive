package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

// cmd/myrmex had zero tests. These cover the flag parser (where a boolean
// switch must never swallow the prompt that follows it) and the fleet-ask
// request shaping added for `myrmex ask --all/--agents`.

func TestParseFlags(t *testing.T) {
	// Isolate from a developer's real MYRMEX_TOKEN in the environment.
	t.Setenv("MYRMEX_TOKEN", "")

	tests := []struct {
		name        string
		argv        []string
		wantPlan    bool
		wantAll     bool
		wantAgents  string
		wantOutput  string
		wantToken   string
		wantCmdArgs []string
	}{
		{
			name:        "--plan does not swallow the prompt",
			argv:        []string{"--plan", "restart nginx"},
			wantPlan:    true,
			wantCmdArgs: []string{"restart nginx"},
		},
		{
			name:        "--all does not swallow the prompt",
			argv:        []string{"--all", "how busy is the fleet?"},
			wantAll:     true,
			wantCmdArgs: []string{"how busy is the fleet?"},
		},
		{
			name:        "--agents takes a value, prompt survives",
			argv:        []string{"--agents", "web-1,web-2", "status check"},
			wantAgents:  "web-1,web-2",
			wantCmdArgs: []string{"status check"},
		},
		{
			name:        "--agents=list form",
			argv:        []string{"--agents=web-1,web-2", "status"},
			wantAgents:  "web-1,web-2",
			wantCmdArgs: []string{"status"},
		},
		{
			name:        "--plan=false disables",
			argv:        []string{"--plan=false", "x"},
			wantPlan:    false,
			wantCmdArgs: []string{"x"},
		},
		{
			name:        "global flags parsed, alias -o",
			argv:        []string{"--token", "abc", "-o", "json", "agent-1__get_metrics"},
			wantToken:   "abc",
			wantOutput:  "json",
			wantCmdArgs: []string{"agent-1__get_metrics"},
		},
		{
			name:        "unknown command flag passes through to cmdArgs",
			argv:        []string{"--arguments", `{"cmd":"uptime"}`, "agent-1__run_command"},
			wantCmdArgs: []string{"--arguments", `{"cmd":"uptime"}`, "agent-1__run_command"},
			wantOutput:  "text",
		},
		{
			name:        "combined fleet + plan, prompt intact",
			argv:        []string{"--all", "--plan", "disk usage"},
			wantAll:     true,
			wantPlan:    true,
			wantCmdArgs: []string{"disk usage"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, cmdArgs := parseFlags(tc.argv)
			if cfg.Plan != tc.wantPlan {
				t.Errorf("Plan = %v, want %v", cfg.Plan, tc.wantPlan)
			}
			if cfg.AllAgents != tc.wantAll {
				t.Errorf("AllAgents = %v, want %v", cfg.AllAgents, tc.wantAll)
			}
			if cfg.AgentIDs != tc.wantAgents {
				t.Errorf("AgentIDs = %q, want %q", cfg.AgentIDs, tc.wantAgents)
			}
			if tc.wantOutput != "" && cfg.Output != tc.wantOutput {
				t.Errorf("Output = %q, want %q", cfg.Output, tc.wantOutput)
			}
			if tc.wantToken != "" && cfg.Token != tc.wantToken {
				t.Errorf("Token = %q, want %q", cfg.Token, tc.wantToken)
			}
			if !reflect.DeepEqual(cmdArgs, tc.wantCmdArgs) {
				t.Errorf("cmdArgs = %#v, want %#v", cmdArgs, tc.wantCmdArgs)
			}
		})
	}
}

func TestFleetAskArguments(t *testing.T) {
	t.Run("all_agents wins over agent_ids", func(t *testing.T) {
		args := fleetAskArguments(Config{AllAgents: true, AgentIDs: "a,b"}, "p")
		if args["all_agents"] != true {
			t.Errorf("expected all_agents=true, got %v", args["all_agents"])
		}
		if _, ok := args["agent_ids"]; ok {
			t.Errorf("agent_ids should not be set when AllAgents is true")
		}
		if args["prompt"] != "p" {
			t.Errorf("prompt not carried: %v", args["prompt"])
		}
	})

	t.Run("agent_ids split and trimmed", func(t *testing.T) {
		args := fleetAskArguments(Config{AgentIDs: " web-1 , web-2 ,"}, "p")
		got, _ := args["agent_ids"].([]string)
		want := []string{"web-1", "web-2"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("agent_ids = %#v, want %#v", got, want)
		}
	})

	t.Run("plan flag carried through", func(t *testing.T) {
		args := fleetAskArguments(Config{AllAgents: true, Plan: true}, "p")
		if args["plan"] != true {
			t.Errorf("expected plan=true, got %v", args["plan"])
		}
	})

	t.Run("no plan key when not set", func(t *testing.T) {
		args := fleetAskArguments(Config{AllAgents: true}, "p")
		if _, ok := args["plan"]; ok {
			t.Errorf("plan key should be absent when Plan is false")
		}
	})
}

func TestExtractContentText(t *testing.T) {
	t.Run("pulls first text block", func(t *testing.T) {
		raw := json.RawMessage(`{"content":[{"type":"text","text":"== web-1 (ok) ==\nfine"}]}`)
		if got := extractContentText(raw); got != "== web-1 (ok) ==\nfine" {
			t.Errorf("got %q", got)
		}
	})
	t.Run("falls back to raw JSON on unexpected shape", func(t *testing.T) {
		raw := json.RawMessage(`{"unexpected":true}`)
		if got := extractContentText(raw); got != `{"unexpected":true}` {
			t.Errorf("expected raw fallback, got %q", got)
		}
	})
}

// handleFleetAsk must route to the gateway__ask_gemma tool over /api/call with
// the fleet selector — this is the whole point of the CLI parity fix.
func TestHandleFleetAskSendsGatewayAskGemma(t *testing.T) {
	var gotPath string
	var gotBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"result":{"content":[{"type":"text","text":"== web-1 (ok) ==\nall good"}]}}`)
	}))
	defer srv.Close()

	// handleFleetAsk writes the rendered summary to stdout; discard it.
	restore := swallowStdout(t)
	defer restore()

	cfg := Config{URL: srv.URL, Token: "t", Output: "text", AllAgents: true}
	handleFleetAsk(srv.Client(), cfg, "report disk usage")

	if gotPath != "/api/call" {
		t.Errorf("path = %q, want /api/call", gotPath)
	}
	if gotBody["name"] != "gateway__ask_gemma" {
		t.Errorf("tool name = %v, want gateway__ask_gemma", gotBody["name"])
	}
	args, _ := gotBody["arguments"].(map[string]interface{})
	if args == nil || args["all_agents"] != true || args["prompt"] != "report disk usage" {
		t.Errorf("arguments not shaped for fleet: %#v", gotBody["arguments"])
	}
}

// swallowStdout redirects os.Stdout to a discard pipe for the duration of a
// test and returns a restore func.
func swallowStdout(t *testing.T) func() {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	go func() { io.Copy(io.Discard, r) }()
	return func() {
		w.Close()
		os.Stdout = orig
	}
}
