package main

import (
	"github.com/olafkfreund/myrmex-hive/pkg/config"
	"strings"
	"testing"
	"time"
)

// resetMetrics clears the package-level counters so tests don't leak into each
// other.
func resetMetrics() {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	toolCalls = map[toolCallKey]uint64{}
	toolLatency = map[toolKey]*histogram{}
	peerForwards = map[string]uint64{}
}

func TestHistogramObserveIsCumulative(t *testing.T) {
	var h histogram
	// latencyBuckets: 0.05 0.1 0.25 0.5 1 2.5 5 10 30
	h.observe(0.3)
	h.observe(0.03)

	// 0.03 lands in every bucket; 0.3 only in those >= 0.5.
	want := []uint64{1, 1, 1, 2, 2, 2, 2, 2, 2}
	for i, w := range want {
		if h.counts[i] != w {
			t.Errorf("bucket le=%g: got %d, want %d", latencyBuckets[i], h.counts[i], w)
		}
	}
	if h.count != 2 {
		t.Errorf("count: got %d, want 2", h.count)
	}
	if h.sum < 0.32 || h.sum > 0.34 {
		t.Errorf("sum: got %g, want ~0.33", h.sum)
	}
}

func TestHistogramValueAboveTopBucketOnlyCountedInInf(t *testing.T) {
	var h histogram
	h.observe(35) // beyond the 30s top bucket: a timed-out call
	for i := range latencyBuckets {
		if h.counts[i] != 0 {
			t.Errorf("bucket le=%g: got %d, want 0", latencyBuckets[i], h.counts[i])
		}
	}
	// +Inf is rendered from count, so the observation is still visible there.
	if h.count != 1 {
		t.Errorf("count: got %d, want 1", h.count)
	}
}

func TestInstrumentToolCallClassifiesAndCountsOnce(t *testing.T) {
	tests := []struct {
		name       string
		resp       JsonRpcResponse
		wantStatus string
	}{
		{"success", JsonRpcResponse{JsonRpc: "2.0"}, "success"},
		{"error", JsonRpcResponse{JsonRpc: "2.0", Error: JsonRpcError{Code: -32603, Message: "boom"}}, "error"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resetMetrics()
			var sent int
			send := instrumentToolCall(func(JsonRpcResponse) { sent++ }, "web-1", "run_command")
			send(tc.resp)

			metricsMu.Lock()
			defer metricsMu.Unlock()
			got := toolCalls[toolCallKey{agent: "web-1", tool: "run_command", status: tc.wantStatus}]
			if got != 1 {
				t.Errorf("counter for status %q: got %d, want 1 (counters: %v)", tc.wantStatus, got, toolCalls)
			}
			if sent != 1 {
				t.Errorf("underlying send called %d times, want 1", sent)
			}
		})
	}

	// A path that sends twice must still only count once, or a retry would
	// silently inflate the counter.
	t.Run("double send counts once", func(t *testing.T) {
		resetMetrics()
		send := instrumentToolCall(func(JsonRpcResponse) {}, "web-1", "run_command")
		send(JsonRpcResponse{JsonRpc: "2.0"})
		send(JsonRpcResponse{JsonRpc: "2.0"})

		metricsMu.Lock()
		defer metricsMu.Unlock()
		if got := toolCalls[toolCallKey{agent: "web-1", tool: "run_command", status: "success"}]; got != 1 {
			t.Errorf("got %d, want 1", got)
		}
	})
}

func TestEscapeLabelValue(t *testing.T) {
	// Agent IDs and tool names are operator-supplied; an unescaped quote would
	// produce an unparseable scrape.
	got := escapeLabelValue(`a"b\c` + "\n" + `d`)
	want := `a\"b\\c\nd`
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestRenderMetricsExposition(t *testing.T) {
	resetMetrics()
	recordToolCall("web-1", "run_command", "success", 120*time.Millisecond)
	recordToolCall("web-1", "run_command", "error", 2*time.Second)
	recordPeerForward("success")

	var sb strings.Builder
	renderMetrics(&sb)
	out := sb.String()

	for _, want := range []string{
		`# TYPE myrmex_agents_connected gauge`,
		`myrmex_agents_connected 0`,
		`# TYPE myrmex_tool_calls_total counter`,
		`myrmex_tool_calls_total{agent="web-1",tool="run_command",status="success"} 1`,
		`myrmex_tool_calls_total{agent="web-1",tool="run_command",status="error"} 1`,
		`# TYPE myrmex_tool_call_duration_seconds histogram`,
		`myrmex_tool_call_duration_seconds_count{agent="web-1",tool="run_command"} 2`,
		`myrmex_tool_call_duration_seconds_bucket{agent="web-1",tool="run_command",le="+Inf"} 2`,
		`myrmex_peer_forwards_total{status="success"} 1`,
		`myrmex_gateway_info{version=`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("exposition missing %q\n--- got ---\n%s", want, out)
		}
	}

	// Every non-comment line must be "name value" - a stray newline or an
	// unescaped label would break the scrape.
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if len(strings.Fields(line)) != 2 {
			t.Errorf("malformed exposition line: %q", line)
		}
	}
}

// The per-agent resource gauges only render when metrics_poll_seconds > 0.
// With polling off (the default) they must be absent rather than zero-valued,
// since a fabricated 0% would look like a healthy host to an alert rule.
func TestRenderMetricsOmitsResourceGaugesWhenPollingDisabled(t *testing.T) {
	resetMetrics()
	currentConfigMu.Lock()
	prev := currentConfig
	currentConfig = &config.GatewayConfig{MetricsPollSeconds: 0}
	currentConfigMu.Unlock()
	defer func() {
		currentConfigMu.Lock()
		currentConfig = prev
		currentConfigMu.Unlock()
	}()

	var sb strings.Builder
	renderMetrics(&sb)
	if strings.Contains(sb.String(), "myrmex_agent_cpu_usage_percent") {
		t.Error("resource gauges rendered with polling disabled")
	}
}

// renderMetrics must not panic before config load: currentConfig is nil until
// then (it is what /readyz keys off), and a scrape can arrive at any time.
func TestRenderMetricsWithNilConfig(t *testing.T) {
	resetMetrics()
	currentConfigMu.Lock()
	prev := currentConfig
	currentConfig = nil
	currentConfigMu.Unlock()
	defer func() {
		currentConfigMu.Lock()
		currentConfig = prev
		currentConfigMu.Unlock()
	}()

	var sb strings.Builder
	renderMetrics(&sb) // must not panic
	if !strings.Contains(sb.String(), "myrmex_agents_connected") {
		t.Error("expected exposition to render with nil config")
	}
}
