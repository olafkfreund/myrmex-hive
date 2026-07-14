package main

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/olafkfreund/myrmex-hive/pkg/config"
)

// dashboardPath is the example Grafana dashboard shipped for #99.
const dashboardPath = "../../dashboards/myrmex-hive.json"

// myrmexMetricRe finds every myrmex_* identifier referenced in a PromQL
// expression. Histogram queries reference the generated _bucket/_sum/_count
// series, which are stripped back to the base name below.
var myrmexMetricRe = regexp.MustCompile(`myrmex_[a-z0-9_]+`)

// exportedMetricNames renders the real exposition and returns the set of
// metric names it declares (via its # TYPE lines).
//
// Some metrics are conditional - the per-agent resource gauges only render
// when metrics_poll_seconds > 0 AND an agent has a sample - so this stages a
// fake agent with a sample first. Without it the exported set is incomplete
// and the sync check below would wrongly flag live metrics as missing.
func exportedMetricNames(t *testing.T) map[string]bool {
	t.Helper()

	currentConfigMu.Lock()
	prevCfg := currentConfig
	currentConfig = &config.GatewayConfig{MetricsPollSeconds: 30}
	currentConfigMu.Unlock()
	t.Cleanup(func() {
		currentConfigMu.Lock()
		currentConfig = prevCfg
		currentConfigMu.Unlock()
	})

	// Built directly rather than via NewAgentClient: that constructor spawns
	// readLoop/querySystemInfo/metricsPoller, which would all dereference the
	// nil SSH channel. renderMetrics only reads agentID, liveness,
	// metricsHistory and the breach flags, so a bare struct is enough.
	fake := &AgentClient{
		agentID:   "dashboard-test-agent",
		ipAddress: "127.0.0.1",
		pending:   make(map[string]chan JsonRpcResponse),
		stopPoll:  make(chan struct{}),
		lastSeen:  time.Now(),
		metricsHistory: []MetricSample{{
			Timestamp: time.Now(),
			Raw:       json.RawMessage(`{"cpu_usage_percent":10,"mem_used_percent":20,"disk_used_percent":30}`),
		}},
	}

	agentsMu.Lock()
	agents[fake.agentID] = fake
	agentsMu.Unlock()
	t.Cleanup(func() {
		agentsMu.Lock()
		delete(agents, fake.agentID)
		agentsMu.Unlock()
	})

	var sb strings.Builder
	renderMetrics(&sb)

	names := map[string]bool{}
	for _, line := range strings.Split(sb.String(), "\n") {
		if !strings.HasPrefix(line, "# TYPE ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			names[fields[2]] = true
		}
	}
	if len(names) == 0 {
		t.Fatal("no metrics exported; renderMetrics changed shape?")
	}
	return names
}

// dashboardExprs pulls every panel target's PromQL expression out of the
// dashboard JSON.
func dashboardExprs(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	var dash struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("dashboard is not valid JSON: %v", err)
	}

	var exprs []string
	for _, p := range dash.Panels {
		for _, tgt := range p.Targets {
			if tgt.Expr != "" {
				exprs = append(exprs, tgt.Expr)
			}
		}
	}
	if len(exprs) == 0 {
		t.Fatal("no panel expressions found in the dashboard")
	}
	return exprs
}

// This is the "kept in sync with the metric names exported by /metrics"
// acceptance criterion from #99, enforced rather than asserted in a comment: a
// dashboard querying a metric that was renamed or dropped renders empty panels,
// which looks like "no traffic" rather than "broken dashboard".
func TestDashboardOnlyReferencesExportedMetrics(t *testing.T) {
	exported := exportedMetricNames(t)

	// Histogram base names also legitimately appear with these suffixes.
	suffixes := []string{"_bucket", "_sum", "_count"}

	for _, expr := range dashboardExprs(t) {
		for _, ref := range myrmexMetricRe.FindAllString(expr, -1) {
			if exported[ref] {
				continue
			}
			matched := false
			for _, sfx := range suffixes {
				if base := strings.TrimSuffix(ref, sfx); base != ref && exported[base] {
					matched = true
					break
				}
			}
			if !matched {
				var have []string
				for n := range exported {
					have = append(have, n)
				}
				sort.Strings(have)
				t.Errorf("dashboard references %q which /metrics does not export.\nexpr: %s\nexported: %v", ref, expr, have)
			}
		}
	}
}

// The converse: a metric exported but on no panel is usually an oversight -
// #99 asks the dashboard to cover fleet size, tool calls, connectivity,
// upstream health and alert state, which is everything we export today.
func TestDashboardCoversEveryExportedMetric(t *testing.T) {
	exported := exportedMetricNames(t)

	referenced := map[string]bool{}
	for _, expr := range dashboardExprs(t) {
		for _, ref := range myrmexMetricRe.FindAllString(expr, -1) {
			referenced[ref] = true
			for _, sfx := range []string{"_bucket", "_sum", "_count"} {
				if base := strings.TrimSuffix(ref, sfx); base != ref {
					referenced[base] = true
				}
			}
		}
	}

	var missing []string
	for name := range exported {
		if !referenced[name] {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Errorf("exported metrics with no dashboard panel: %v", missing)
	}
}
