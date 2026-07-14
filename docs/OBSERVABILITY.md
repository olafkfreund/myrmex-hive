# Observability: Prometheus metrics

The gateway can expose a Prometheus exposition endpoint at `/metrics`. It is
**opt-in**: with nothing configured the route is not registered and the gateway
behaves exactly as before.

## Enabling

```json
{
  "metrics_enabled": true,
  "metrics_poll_seconds": 30
}
```

- `metrics_enabled` turns on the `/metrics` route.
- `metrics_poll_seconds` is optional and independent, but the per-agent resource
  gauges (CPU/memory/disk) are only present when it is > 0, since it is what
  populates the samples they read. Without it you still get everything else.

## Scraping

`/metrics` sits behind the same `requireAuth` middleware as every other API
path — a scraper must present a bearer token. The fleet topology it exposes
(agent IDs, counts, tool usage) is not public data, and there is deliberately no
unauthenticated bypass.

Any role reaches it; use **read-only**, the least privilege that works:

```json
{
  "tokens": { "s3cr3t-scrape-token": "read-only" }
}
```

```yaml
# prometheus.yml
scrape_configs:
  - job_name: myrmex-gateway
    scheme: https
    authorization:
      credentials: s3cr3t-scrape-token
    tls_config:
      # The gateway generates a self-signed cert in-memory unless tls.enabled
      # pins a real one. Drop this once you have a proper certificate.
      insecure_skip_verify: true
    static_configs:
      - targets: ['gateway.internal:8080']
```

Verify by hand:

```bash
curl -sk -H 'Authorization: Bearer s3cr3t-scrape-token' https://localhost:8080/metrics
```

## Metrics

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `myrmex_gateway_info` | gauge | `version`, `gateway_id` | Always 1; carries build/identity as labels. |
| `myrmex_agents_connected` | gauge | — | Agents with an open SSH tunnel to this gateway. |
| `myrmex_agent_online` | gauge | `agent_id` | 1 if last-seen is within the liveness window, else 0. |
| `myrmex_agent_cpu_usage_percent` | gauge | `agent_id` | Newest polled CPU sample. Requires `metrics_poll_seconds > 0`. |
| `myrmex_agent_mem_used_percent` | gauge | `agent_id` | Newest polled memory sample. Requires `metrics_poll_seconds > 0`. |
| `myrmex_agent_disk_used_percent` | gauge | `agent_id` | Newest polled disk sample. Requires `metrics_poll_seconds > 0`. |
| `myrmex_upstream_up` | gauge | `server` | 1 if the upstream MCP server reports `connected`. |
| `myrmex_agent_alert_breached` | gauge | `agent_id`, `dimension` | 1 if the last polled sample breached the configured threshold. Requires `alert_thresholds`. |
| `myrmex_tool_calls_total` | counter | `agent`, `tool`, `status` | Operator-initiated tool calls. |
| `myrmex_tool_call_duration_seconds` | histogram | `agent`, `tool` | Gateway-observed latency, dispatch to response. |
| `myrmex_peer_forwards_total` | counter | `status` | Calls forwarded to a peer gateway holding the target agent. |
| `myrmex_alert_deliveries_total` | counter | `target`, `status` | Outbound alert deliveries (see Alert routing). |

Gateway-native tools appear with `agent="gateway"` (e.g. `tool="ask_gemma"`),
matching the `gateway__` namespace.

### What the numbers mean (and don't)

Worth knowing before you build alerts on these:

- **`status` is the JSON-RPC outcome, not the command's verdict.** A command
  rejected by the agent allowlist returns a *well-formed* result saying it was
  rejected, so it counts as `status="success"`. The call worked; the command was
  refused. Alert on rejections from the **audit log**, not from this counter.
- **Only operator-initiated calls are counted.** The gateway's own internal
  traffic (metrics polling, system-info queries, `tools/list`) bypasses the
  counted path, so these numbers reflect real usage rather than the poll
  interval.
- **Latency is gateway-observed**, spanning dispatch to response over the
  tunnel. It includes agent execution and network time, not just gateway
  overhead.
- **The top histogram bucket is 30s and `AgentClient.Call` times out at 35s.** A
  bucket count that only grows at `+Inf` means calls are timing out.
- **Counters reset on restart**, as they are in-memory. Use `rate()`/`increase()`,
  which handle resets, rather than raw counter values.

## Grafana dashboard

An example dashboard is shipped at
[`dashboards/myrmex-hive.json`](../dashboards/myrmex-hive.json): fleet size and
connectivity, tool-call rate/error-ratio/latency percentiles, per-agent
CPU/memory/disk, upstream health, threshold breaches, alert-delivery failures,
and HA peer forwards.

Import it:

1. Grafana → **Dashboards** → **New** → **Import**
2. **Upload dashboard JSON file**, pick `dashboards/myrmex-hive.json`
3. Select your Prometheus datasource when prompted for `DS_PROMETHEUS`
4. **Import**

Or via the API:

```bash
curl -X POST http://grafana:3000/api/dashboards/import \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $GRAFANA_TOKEN" \
  -d "{\"dashboard\": $(cat dashboards/myrmex-hive.json), \"overwrite\": true,
       \"inputs\": [{\"name\": \"DS_PROMETHEUS\", \"type\": \"datasource\",
                     \"pluginId\": \"prometheus\", \"value\": \"Prometheus\"}]}"
```

Provision it declaratively by mounting the file into Grafana's dashboard
provisioning path (`/etc/grafana/provisioning/dashboards/`).

Panels that stay empty are telling you something real:

- **CPU/memory/disk** need `metrics_poll_seconds > 0`.
- **Threshold breaches** additionally needs `alert_thresholds`.
- **Alert delivery failures** needs an alert target (see below); no target
  means no deliveries to fail.
- **HA peer forwards** only populates in a multi-gateway peer mesh.

The dashboard is kept in sync with the exported metric names by a test
(`cmd/gateway/dashboard_test.go`), which fails the build if a panel references
a metric `/metrics` does not export, or if an exported metric has no panel. A
dashboard drifting out of sync renders empty panels, which reads as "no
traffic" rather than "broken dashboard" — hence the check.

### Useful queries

```promql
# Tool call error rate over 5m
sum(rate(myrmex_tool_calls_total{status="error"}[5m]))
  / sum(rate(myrmex_tool_calls_total[5m]))

# p95 latency per tool
histogram_quantile(0.95,
  sum by (le, tool) (rate(myrmex_tool_call_duration_seconds_bucket[5m])))

# Agents that dropped off
myrmex_agent_online == 0
```

## Alert routing (webhook / Alertmanager)

The gateway's threshold alerts (`alert_thresholds`) go to the log and the signed
audit trail by default. They can additionally be routed to on-call systems. Both
targets are opt-in; with neither set, nothing changes.

```json
{
  "metrics_poll_seconds": 30,
  "alert_thresholds": { "cpu_percent": 90, "mem_percent": 90, "disk_percent": 85 },
  "alert_webhook_url": "https://hooks.example.com/myrmex",
  "alertmanager_url": "http://alertmanager:9093",
  "alert_delivery_retries": 3
}
```

Set either, or both — each configured target receives every alert. Delivery is
asynchronous, so a slow or dead receiver never stalls the metrics poller.

### Generic webhook

POSTs `application/json`:

```json
{
  "agent_id": "web-1",
  "dimension": "cpu",
  "status": "firing",
  "value": 91.5,
  "threshold": 90,
  "timestamp": "2026-07-14T17:26:14Z",
  "gateway_id": "gw-1"
}
```

`status` is `firing` on breach onset and `resolved` on recovery.

### Alertmanager

POSTs to `<alertmanager_url>/api/v2/alerts` (give the **base** URL; the path is
appended). Alerts carry `alertname=MyrmexThresholdBreach` plus `agent_id`,
`dimension`, `gateway_id` and `severity` labels.

Alertmanager has no "resolved" field — an alert resolves via `endsAt`. Firing
alerts deliberately omit `endsAt` so Alertmanager applies its own
`resolve_timeout`; resolved alerts set it. Route on the labels:

```yaml
route:
  routes:
    - matchers: [ alertname="MyrmexThresholdBreach" ]
      receiver: myrmex-oncall
```

### Delivery, retries and failure

- Alerts are sent **only on transitions** — once per breach onset and once on
  recovery — not every poll while a breach persists. On-call is not re-paged
  for a sustained breach.
- Failed deliveries retry with exponential backoff (1s, 2s, 4s…),
  `alert_delivery_retries` times (default 3; set negative to disable retrying).
- A **4xx is treated as permanent** and is not retried — a malformed or
  unauthorized request will never be accepted, so retrying only burns attempts.
  **429 is the exception** and is retried, as it means "slow down", not "never".
- Watch `myrmex_alert_deliveries_total{status="error"}`. A silently failing
  integration otherwise only reveals itself when a page never arrives:

  ```promql
  rate(myrmex_alert_deliveries_total{status="error"}[5m]) > 0
  ```

> **No auth on the webhook yet.** There is no field for a bearer token or
> custom headers, so point `alert_webhook_url` at an endpoint that either
> doesn't need auth or accepts a secret in the URL. Same for TLS: the system
> trust store is used, with no skip-verify escape hatch.

## Implementation note

The exposition format is written by hand (`cmd/gateway/metrics.go`) rather than
via `prometheus/client_golang`. The text format is a handful of `Fprintf` calls,
and this project's only real external dependency is `golang.org/x/crypto` — a
client library would drag a transitive tree through `vendor/` for no functional
gain at this scale. If the metric surface grows substantially, revisit.
