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
| `myrmex_tool_calls_total` | counter | `agent`, `tool`, `status` | Operator-initiated tool calls. |
| `myrmex_tool_call_duration_seconds` | histogram | `agent`, `tool` | Gateway-observed latency, dispatch to response. |
| `myrmex_peer_forwards_total` | counter | `status` | Calls forwarded to a peer gateway holding the target agent. |

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

## Implementation note

The exposition format is written by hand (`cmd/gateway/metrics.go`) rather than
via `prometheus/client_golang`. The text format is a handful of `Fprintf` calls,
and this project's only real external dependency is `golang.org/x/crypto` — a
client library would drag a transitive tree through `vendor/` for no functional
gain at this scale. If the metric surface grows substantially, revisit.
