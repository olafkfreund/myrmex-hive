package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// registerFakeAgent wires a fakeAgentChannel into the global agents registry
// under agentID (bypassing NewAgentClient's querySystemInfo goroutine, same
// as runOrchestration in orchestration_eval_test.go), and unregisters it on
// test cleanup.
func registerFakeAgent(t *testing.T, agentID string, ch *fakeAgentChannel) *AgentClient {
	t.Helper()
	cli := &AgentClient{
		agentID:  agentID,
		channel:  ch,
		pending:  make(map[string]chan JsonRpcResponse),
		stopPoll: make(chan struct{}),
	}
	go cli.readLoop()

	agentsMu.Lock()
	agents[agentID] = cli
	agentsMu.Unlock()
	t.Cleanup(func() {
		agentsMu.Lock()
		delete(agents, agentID)
		agentsMu.Unlock()
	})
	return cli
}

// TestFleetOrchestrationConsultsEveryAgentAndAggregates drives
// executeFleetGemmaOrchestration across two fake agents and asserts both were
// actually consulted (their tools were called) and the aggregated response
// names both agents with their individual summaries.
func TestFleetOrchestrationConsultsEveryAgentAndAggregates(t *testing.T) {
	// Each agent's orchestration is one decision (call get_metrics) then done;
	// the scripted engine is shared/global, so it just needs 4 outputs total
	// (2 per agent) in the order the fleet loop drives them.
	engine := &scriptedEngine{outputs: []string{
		`{"tool_name":"get_metrics","arguments":{}}`,
		`{"done":true,"summary":"web-1 is fine"}`,
		`{"tool_name":"get_metrics","arguments":{}}`,
		`{"done":true,"summary":"web-2 is fine"}`,
	}}
	prevEngine := llmEngine
	llmEngine = engine
	t.Cleanup(func() { llmEngine = prevEngine })

	currentConfigMu.Lock()
	prevCfg := currentConfig
	currentConfig = &config.GatewayConfig{MaxOrchestrationSteps: 3}
	currentConfigMu.Unlock()
	t.Cleanup(func() {
		currentConfigMu.Lock()
		currentConfig = prevCfg
		currentConfigMu.Unlock()
	})

	ch1 := newFakeAgent(t, agentRespond([]string{"get_metrics"}, map[string]string{"get_metrics": "cpu: 5%"}))
	ch2 := newFakeAgent(t, agentRespond([]string{"get_metrics"}, map[string]string{"get_metrics": "cpu: 9%"}))
	registerFakeAgent(t, "web-1", ch1)
	registerFakeAgent(t, "web-2", ch2)

	var got JsonRpcResponse
	send := func(resp JsonRpcResponse) { got = resp }

	executeFleetGemmaOrchestration(context.Background(), []string{"web-1", "web-2"}, "how busy is the fleet?", false, "req-fleet", send)

	if len(ch1.executedTools()) != 1 || ch1.executedTools()[0] != "get_metrics" {
		t.Errorf("web-1 was not consulted: executed %v", ch1.executedTools())
	}
	if len(ch2.executedTools()) != 1 || ch2.executedTools()[0] != "get_metrics" {
		t.Errorf("web-2 was not consulted: executed %v", ch2.executedTools())
	}

	resultBytes, _ := json.Marshal(got.Result)
	aggregate := string(resultBytes)
	for _, want := range []string{"web-1", "web-1 is fine", "web-2", "web-2 is fine"} {
		if !strings.Contains(aggregate, want) {
			t.Errorf("aggregate result missing %q: %s", want, aggregate)
		}
	}
}

// TestFleetOrchestrationSkipsDisconnectedAgent asserts an agent that isn't
// connected is reported as failed in the aggregate rather than blocking the
// rest of the fleet or panicking.
func TestFleetOrchestrationSkipsDisconnectedAgent(t *testing.T) {
	engine := &scriptedEngine{outputs: []string{
		`{"done":true,"summary":"web-1 is fine"}`,
	}}
	prevEngine := llmEngine
	llmEngine = engine
	t.Cleanup(func() { llmEngine = prevEngine })

	currentConfigMu.Lock()
	prevCfg := currentConfig
	currentConfig = &config.GatewayConfig{MaxOrchestrationSteps: 3}
	currentConfigMu.Unlock()
	t.Cleanup(func() {
		currentConfigMu.Lock()
		currentConfig = prevCfg
		currentConfigMu.Unlock()
	})

	ch1 := newFakeAgent(t, agentRespond([]string{"get_metrics"}, nil))
	registerFakeAgent(t, "web-1", ch1)

	var got JsonRpcResponse
	send := func(resp JsonRpcResponse) { got = resp }

	executeFleetGemmaOrchestration(context.Background(), []string{"web-1", "ghost-agent"}, "status check", false, "req-fleet-2", send)

	resultBytes, _ := json.Marshal(got.Result)
	aggregate := string(resultBytes)
	if !strings.Contains(aggregate, "web-1 is fine") {
		t.Errorf("connected agent's summary missing: %s", aggregate)
	}
	if !strings.Contains(aggregate, "ghost-agent") || !strings.Contains(aggregate, "not connected") {
		t.Errorf("disconnected agent should be reported as not connected: %s", aggregate)
	}
}
