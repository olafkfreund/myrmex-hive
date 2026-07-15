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
[`dashboards/myrmex-hive.json`](https://github.com/olafkfreund/myrmex-hive/blob/main/dashboards/myrmex-hive.json): fleet size and
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

### Authenticating to the receiver

Most on-call systems want a token. Send arbitrary headers with each delivery:

```json
{
  "alert_webhook_url": "https://events.pagerduty.com/v2/enqueue",
  "alert_webhook_headers": {
    "Authorization": "env:PAGERDUTY_TOKEN",
    "X-Routing-Key": "team-sre"
  },
  "alertmanager_url": "https://alertmanager.internal",
  "alertmanager_headers": { "Authorization": "file:/run/secrets/am-token" }
}
```

Header **values** resolve through the same secret indirection as `llm_api_key`
— `env:` / `file:` / `agenix:` / `vault:` — so the token never has to sit in
the config file. Header **names** are not secrets and are used as-is.

Notes:

- `Content-Type: application/json` is set first, so you can override it if your
  receiver insists on something else.
- `GET /api/config` redacts header **values** (names stay visible). It cannot
  know which values are credentials, so it redacts them all — including
  innocuous ones like a routing key.
- A misconfigured token fails fast: a 4xx is treated as permanent and is not
  retried. Watch `myrmex_alert_deliveries_total{status="error"}`.
- URLs are redacted in log lines and delivery errors (userinfo and query
  stripped), since a secret smuggled into the URL was the only option before
  this existed — and Go's `*url.Error` stringifies with the full URL.

> **TLS:** the system trust store is used, with no custom-CA or skip-verify
> option. A receiver with a private certificate is not supported yet.

## Distributed tracing (OpenTelemetry)

Tool calls, Gemma orchestration, upstream proxying and peer forwarding can be
traced and exported over OTLP/HTTP. Opt-in; with `tracing_enabled` unset no
tracer provider is installed, every span call site is a no-op, and no exporter
goroutine or network call exists.

```json
{
  "tracing_enabled": true,
  "otlp_endpoint": "otel-collector:4318",
  "otlp_insecure": true,
  "trace_service_name": "myrmex-gateway",
  "trace_sample_ratio": 1.0,
  "otlp_headers": { "authorization": "env:OTLP_TOKEN" }
}
```

- `otlp_endpoint` is **host:port only** — no scheme, no path. The exporter
  appends `/v1/traces`. Defaults to `localhost:4318`.
- `otlp_insecure` sends plain HTTP; collectors commonly listen on plaintext
  4318 inside a trusted network.
- `otlp_headers` values go through the same secret indirection as
  `llm_api_key` (`env:` / `file:` / `agenix:` / `vault:`), so a hosted
  backend's token never has to sit in the config file.
- `trace_sample_ratio` defaults to 1.0 (sample everything) — a gateway's
  tool-call rate is low enough that full sampling is the useful default. Lower
  it for a busy fleet. Sampling is `ParentBased`, so a decision made by the
  gateway that forwarded to us is honored rather than re-rolled (which would
  produce half-sampled, broken traces).

### Spans

| Span | Parent | Covers |
|---|---|---|
| `mcp.tool_call` | root (or the forwarding peer) | The whole operator tool call, any transport. Attributes: `myrmex.agent_id`, `myrmex.tool`. |
| `mcp.agent_call` | `mcp.tool_call` | The SSH-tunnel hop — separates time on the agent from gateway overhead. |
| `mcp.upstream_call` | `mcp.tool_call` | Proxying to an upstream MCP server. |
| `mcp.peer_forward` | `mcp.tool_call` | Forwarding to the peer gateway holding the agent. Injects W3C `traceparent`. |
| `gemma.orchestration` | `mcp.tool_call` | The whole multi-step LLM loop. |
| `gemma.step` | `gemma.orchestration` | One step — shows *which* tool call was slow, not just a slow total. |

Resource attributes carry `service.name`, `service.version` and
`myrmex.gateway_id`, so a trace can be attributed to one gateway in an HA mesh.

A failing call sets the span status to error with the JSON-RPC error, using the
same definition of "error" as `myrmex_tool_calls_total` — traces and metrics
agree. (Which means the same caveat applies: an allowlist rejection is a
well-formed result and is *not* an error here.)

### Propagation

- **Gateway → gateway** is propagated: `forwardToPeer` injects W3C
  `traceparent`, `handleInternalCall` extracts it, so a forwarded call is
  **one** trace spanning both gateways rather than two disconnected ones.
- **Gateway → agent is deliberately NOT propagated.** The agent has no tracer,
  so injecting a `traceparent` into the JSON-RPC params would be a wire-format
  change nothing reads. The tunnel hop is still visible as `mcp.agent_call` on
  the gateway side. Propagating becomes worthwhile only if the agent is ever
  instrumented.

### Verifying

```bash
docker run --rm --network host \
  -v ./collector.yaml:/etc/otelcol/config.yaml \
  otel/opentelemetry-collector:latest --config /etc/otelcol/config.yaml
```

with a `debug` exporter at `verbosity: detailed`; a tool call then prints its
spans. A dead collector is never fatal — the exporter retries and logs
`[TRACE] exporter error: ...` while the gateway keeps serving.

## Implementation note

The Prometheus exposition is written by hand (`cmd/gateway/metrics.go`) rather
than via `prometheus/client_golang`: the text format is a handful of `Fprintf`
calls, so a client library would drag a transitive tree through `vendor/` for no
functional gain. If the metric surface grows substantially, revisit.

Tracing went the other way and uses the real OTel SDK, which is most of the
~21MB `vendor/`. That was a deliberate trade: unlike a text exposition, tracing
has genuinely subtle parts — W3C context propagation, parent-based sampling,
batching, retry — where reimplementing the spec buys bugs we own rather than
saving bytes.
