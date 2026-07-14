package main

// Prometheus /metrics endpoint (issue #97).
//
// The exposition format is written by hand rather than pulling in
// prometheus/client_golang: the text format is a handful of Fprintf calls, and
// the only real external dependency of this module is golang.org/x/crypto (see
// CLAUDE.md). A client library would drag a transitive tree through vendor/ for
// no functional gain at this scale.
//
// ponytail: counters live in plain maps under one mutex. Scrapes are rare
// (every 15-60s) and tool calls are network-bound, so lock contention is not a
// concern; move to sharded/atomic counters only if a profile says otherwise.

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// latencyBuckets are the cumulative upper bounds (seconds) for the tool-call
// duration histogram. Chosen to straddle the 35s call timeout in
// AgentClient.Call, so a saturated bucket at +Inf means calls are timing out.
var latencyBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}

type toolCallKey struct {
	agent  string
	tool   string
	status string
}

type toolKey struct {
	agent string
	tool  string
}

// histogram is a fixed-bucket cumulative histogram over latencyBuckets.
type histogram struct {
	counts []uint64 // parallel to latencyBuckets; +Inf tracked by count
	sum    float64
	count  uint64
}

func (h *histogram) observe(seconds float64) {
	if h.counts == nil {
		h.counts = make([]uint64, len(latencyBuckets))
	}
	for i, b := range latencyBuckets {
		if seconds <= b {
			h.counts[i]++
		}
	}
	h.sum += seconds
	h.count++
}

var (
	metricsMu    sync.Mutex
	toolCalls    = map[toolCallKey]uint64{}
	toolLatency  = map[toolKey]*histogram{}
	peerForwards = map[string]uint64{}
)

// recordToolCall records one completed operator-initiated tool call.
//
// It is called from exactly one place - the send wrapper installed by
// instrumentToolCall in handleCallTool - which is the single choke point every
// operator tool call routes through regardless of transport (stdio, SSE
// /message, and REST /api/call, which dispatches via handleClientRequest).
//
// Deliberately NOT instrumented in AgentClient.Call: that is also used by
// pollMetricsOnce, querySystemInfo and handleListTools, whose periodic internal
// traffic would swamp real operator activity and change what this metric means.
func recordToolCall(agent, tool, status string, d time.Duration) {
	metricsMu.Lock()
	defer metricsMu.Unlock()

	toolCalls[toolCallKey{agent: agent, tool: tool, status: status}]++

	k := toolKey{agent: agent, tool: tool}
	h := toolLatency[k]
	if h == nil {
		h = &histogram{}
		toolLatency[k] = h
	}
	h.observe(d.Seconds())
}

// recordPeerForward records one HA peer-forwarded call (handleApiCall's
// forward path returns before reaching handleCallTool, so it is counted here).
func recordPeerForward(status string) {
	metricsMu.Lock()
	defer metricsMu.Unlock()
	peerForwards[status]++
}

// instrumentToolCall wraps a ResponseSender so the tool call is recorded when
// its response is sent, whatever path produced it.
//
// Wrapping send (rather than deferring in handleCallTool) is what makes the
// asynchronous paths correct: the upstream-MCP branch dispatches a goroutine
// and returns immediately, so a deferred timer there would measure ~0s. Error
// returns are covered too, since sendErrorDirect also goes through send.
//
// sync.Once guards against double-counting if a path ever sends twice.
func instrumentToolCall(send ResponseSender, agent, tool string) ResponseSender {
	start := time.Now()
	var once sync.Once
	return func(resp JsonRpcResponse) {
		once.Do(func() {
			// JsonRpcResponse.Error is interface{}; nil means success. Same
			// check handleApiCall uses to classify a response.
			status := "success"
			if resp.Error != nil {
				status = "error"
			}
			recordToolCall(agent, tool, status, time.Since(start))
		})
		send(resp)
	}
}

// escapeLabelValue escapes a label value per the Prometheus text exposition
// format. Agent IDs and tool names are operator-supplied, so this is not
// theoretical: an unescaped quote would produce an unparseable scrape.
func escapeLabelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func writeHelp(w io.Writer, name, help, typ string) {
	fmt.Fprintf(w, "# HELP %s %s\n", name, help)
	fmt.Fprintf(w, "# TYPE %s %s\n", name, typ)
}

// renderMetrics writes the full exposition body. Split from handleMetrics so it
// is testable against an io.Writer without an HTTP server.
func renderMetrics(w io.Writer) {
	// currentConfig is nil until config load (it is what /readyz keys off), so
	// guard the read like every other reader in this package does.
	currentConfigMu.RLock()
	var gatewayID string
	var pollSeconds int
	if currentConfig != nil {
		gatewayID = currentConfig.GatewayID
		pollSeconds = currentConfig.MetricsPollSeconds
	}
	currentConfigMu.RUnlock()

	writeHelp(w, "myrmex_gateway_info", "Gateway build and identity info.", "gauge")
	fmt.Fprintf(w, "myrmex_gateway_info{version=\"%s\",gateway_id=\"%s\"} 1\n",
		escapeLabelValue(version), escapeLabelValue(gatewayID))

	// --- Agents -------------------------------------------------------------
	agentsMu.RLock()
	clients := make([]*AgentClient, 0, len(agents))
	for _, c := range agents {
		clients = append(clients, c)
	}
	agentsMu.RUnlock()
	sort.Slice(clients, func(i, j int) bool { return clients[i].agentID < clients[j].agentID })

	writeHelp(w, "myrmex_agents_connected", "Number of agents with an open SSH tunnel to this gateway.", "gauge")
	fmt.Fprintf(w, "myrmex_agents_connected %d\n", len(clients))

	writeHelp(w, "myrmex_agent_online", "1 if the agent's last-seen time is within the liveness window, else 0.", "gauge")
	for _, c := range clients {
		online := 0
		if c.Online() {
			online = 1
		}
		fmt.Fprintf(w, "myrmex_agent_online{agent_id=\"%s\"} %d\n", escapeLabelValue(c.agentID), online)
	}

	// Fleet-level resource gauges, parsed from the newest get_metrics sample
	// using the same alertMetrics shape the alerting path already uses. Only
	// present when metrics_poll_seconds > 0 populates metricsHistory.
	if pollSeconds > 0 {
		type agentGauge struct {
			id string
			m  alertMetrics
		}
		var gauges []agentGauge
		for _, c := range clients {
			if m, ok := c.latestAlertMetrics(); ok {
				gauges = append(gauges, agentGauge{id: c.agentID, m: m})
			}
		}
		if len(gauges) > 0 {
			writeHelp(w, "myrmex_agent_cpu_usage_percent", "Most recent CPU usage percent reported by the agent.", "gauge")
			for _, g := range gauges {
				fmt.Fprintf(w, "myrmex_agent_cpu_usage_percent{agent_id=\"%s\"} %g\n", escapeLabelValue(g.id), g.m.CPUUsagePercent)
			}
			writeHelp(w, "myrmex_agent_mem_used_percent", "Most recent memory used percent reported by the agent.", "gauge")
			for _, g := range gauges {
				fmt.Fprintf(w, "myrmex_agent_mem_used_percent{agent_id=\"%s\"} %g\n", escapeLabelValue(g.id), g.m.MemUsedPercent)
			}
			writeHelp(w, "myrmex_agent_disk_used_percent", "Most recent disk used percent reported by the agent.", "gauge")
			for _, g := range gauges {
				fmt.Fprintf(w, "myrmex_agent_disk_used_percent{agent_id=\"%s\"} %g\n", escapeLabelValue(g.id), g.m.DiskUsedPercent)
			}
		}
	}

	// --- Upstreams ----------------------------------------------------------
	upstreamClientsMu.RLock()
	upstreams := make([]UpstreamCaller, 0, len(upstreamClients))
	for _, uc := range upstreamClients {
		upstreams = append(upstreams, uc)
	}
	upstreamClientsMu.RUnlock()
	sort.Slice(upstreams, func(i, j int) bool { return upstreams[i].GetName() < upstreams[j].GetName() })

	writeHelp(w, "myrmex_upstream_up", "1 if the upstream MCP server reports status \"connected\", else 0.", "gauge")
	for _, uc := range upstreams {
		up := 0
		if uc.GetStatus() == "connected" {
			up = 1
		}
		fmt.Fprintf(w, "myrmex_upstream_up{server=\"%s\"} %d\n", escapeLabelValue(uc.GetName()), up)
	}

	// --- Tool calls ---------------------------------------------------------
	metricsMu.Lock()
	callKeys := make([]toolCallKey, 0, len(toolCalls))
	for k := range toolCalls {
		callKeys = append(callKeys, k)
	}
	sort.Slice(callKeys, func(i, j int) bool {
		if callKeys[i].agent != callKeys[j].agent {
			return callKeys[i].agent < callKeys[j].agent
		}
		if callKeys[i].tool != callKeys[j].tool {
			return callKeys[i].tool < callKeys[j].tool
		}
		return callKeys[i].status < callKeys[j].status
	})

	writeHelp(w, "myrmex_tool_calls_total", "Operator-initiated tool calls dispatched by this gateway.", "counter")
	for _, k := range callKeys {
		fmt.Fprintf(w, "myrmex_tool_calls_total{agent=\"%s\",tool=\"%s\",status=\"%s\"} %d\n",
			escapeLabelValue(k.agent), escapeLabelValue(k.tool), escapeLabelValue(k.status), toolCalls[k])
	}

	latKeys := make([]toolKey, 0, len(toolLatency))
	for k := range toolLatency {
		latKeys = append(latKeys, k)
	}
	sort.Slice(latKeys, func(i, j int) bool {
		if latKeys[i].agent != latKeys[j].agent {
			return latKeys[i].agent < latKeys[j].agent
		}
		return latKeys[i].tool < latKeys[j].tool
	})

	writeHelp(w, "myrmex_tool_call_duration_seconds", "Tool call latency, gateway-observed (dispatch to response).", "histogram")
	for _, k := range latKeys {
		h := toolLatency[k]
		agent := escapeLabelValue(k.agent)
		tool := escapeLabelValue(k.tool)
		for i, b := range latencyBuckets {
			fmt.Fprintf(w, "myrmex_tool_call_duration_seconds_bucket{agent=\"%s\",tool=\"%s\",le=\"%g\"} %d\n",
				agent, tool, b, h.counts[i])
		}
		fmt.Fprintf(w, "myrmex_tool_call_duration_seconds_bucket{agent=\"%s\",tool=\"%s\",le=\"+Inf\"} %d\n", agent, tool, h.count)
		fmt.Fprintf(w, "myrmex_tool_call_duration_seconds_sum{agent=\"%s\",tool=\"%s\"} %g\n", agent, tool, h.sum)
		fmt.Fprintf(w, "myrmex_tool_call_duration_seconds_count{agent=\"%s\",tool=\"%s\"} %d\n", agent, tool, h.count)
	}

	fwdStatuses := make([]string, 0, len(peerForwards))
	for s := range peerForwards {
		fwdStatuses = append(fwdStatuses, s)
	}
	sort.Strings(fwdStatuses)
	metricsMu.Unlock()

	writeHelp(w, "myrmex_peer_forwards_total", "Calls forwarded to a peer gateway holding the target agent (HA mesh).", "counter")
	for _, s := range fwdStatuses {
		fmt.Fprintf(w, "myrmex_peer_forwards_total{status=\"%s\"} %d\n", escapeLabelValue(s), peerForwards[s])
	}
}

// latestAlertMetrics returns the newest get_metrics sample for this agent,
// parsed into the same alertMetrics shape the alerting path uses. ok is false
// when no sample has been collected (polling disabled, or agent just connected).
func (c *AgentClient) latestAlertMetrics() (alertMetrics, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.metricsHistory) == 0 {
		return alertMetrics{}, false
	}
	raw := c.metricsHistory[len(c.metricsHistory)-1].Raw
	var m alertMetrics
	if err := json.Unmarshal(raw, &m); err != nil {
		return alertMetrics{}, false
	}
	return m, true
}

// handleMetrics serves the Prometheus exposition. Registered behind requireAuth
// (see startHTTPServer), so a scraper must present a bearer token like any
// other API client - the fleet topology exposed here is not public data.
func handleMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	renderMetrics(w)
}
