package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// registerFakeAgent (shared with fleet_orchestration_test.go) registers a
// directly-constructed AgentClient in the global registry, visible to getAgent.

// A single scheduled-task tick: agent connected, LLM immediately done, and
// the resulting summary must reach notifyAlert's webhook delivery - the
// whole point of #6 (route a recurring orchestration's result through
// existing alerting).
func TestRunScheduledTaskEmitsAlert(t *testing.T) {
	fastBackoff(t)

	type received struct {
		AgentID   string `json:"agent_id"`
		Dimension string `json:"dimension"`
		Status    string `json:"status"`
		Message   string `json:"message"`
	}
	ch := make(chan received, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev received
		_ = json.NewDecoder(r.Body).Decode(&ev)
		ch <- ev
	}))
	defer srv.Close()

	withAlertConfig(t, &config.GatewayConfig{AlertWebhookURL: srv.URL})

	prevEngine := llmEngine
	llmEngine = &scriptedEngine{outputs: []string{
		`{"done":true,"summary":"CPU usage is 12%, all healthy"}`,
	}}
	t.Cleanup(func() { llmEngine = prevEngine })

	agentCh := newFakeAgent(t, agentRespond([]string{"get_metrics"}, nil))
	registerFakeAgent(t, "web-1", agentCh)

	task := config.ScheduledTask{Name: "healthcheck", AgentID: "web-1", Prompt: "check health", IntervalSeconds: 60}
	runScheduledTask(context.Background(), task)

	select {
	case ev := <-ch:
		if ev.AgentID != "web-1" || ev.Dimension != "scheduled:healthcheck" || ev.Status != "firing" {
			t.Errorf("unexpected alert fields: %+v", ev)
		}
		if ev.Message != "CPU usage is 12%, all healthy" {
			t.Errorf("Message = %q, want the orchestration summary", ev.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was never called")
	}
}

// An agent that isn't connected must be skipped without panicking or calling
// the LLM/alerting path at all.
func TestRunScheduledTaskSkipsWhenAgentNotConnected(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer srv.Close()
	withAlertConfig(t, &config.GatewayConfig{AlertWebhookURL: srv.URL})

	prevEngine := llmEngine
	llmEngine = &scriptedEngine{outputs: []string{`{"done":true,"summary":"unreachable"}`}}
	t.Cleanup(func() { llmEngine = prevEngine })

	task := config.ScheduledTask{Name: "healthcheck", AgentID: "not-connected", Prompt: "check health", IntervalSeconds: 60}
	runScheduledTask(context.Background(), task)

	time.Sleep(30 * time.Millisecond)
	if hits != 0 {
		t.Errorf("webhook called %d time(s) for a disconnected agent, want 0", hits)
	}
}
