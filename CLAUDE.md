# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Myrmex Hive (`github.com/olafkfreund/myrmex-hive`) is a Go implementation of the Model Context Protocol (MCP) for securely managing distributed edge servers with **zero inbound ports on the targets**. Agents dial *out* to a central Gateway over SSH; operators reach the Gateway (never the agents) via CLI, MCP, or REST. A local LLM (Ollama/Gemma) orchestrates multi-step actions.

Three binaries from `cmd/`: **agent** (runs on targets), **gateway** (central hub), **myrmex** (operator CLI).

## Commands

Prefer the `Justfile` recipes:

- `just build` — builds all three binaries into `bin/`
- `just validate` — `go vet ./...` + `go fmt ./...` (CI runs both; keep the tree fmt-clean)
- `just test` — `go test -v ./...`
- `just run-gateway` / `just run-agent` — build then run locally against `gateway_config.json` / `agent_config.json`
- `just generate-keys` — generate Ed25519 keys for local testing (`generate_keys.sh`)
- `just docker-test` — `setup_test_env.sh` then `go run cmd/integration-test/main.go` (spins up the compose stack and drives it end-to-end)
- `just clean` — removes `bin/`, generated keys, and `test_env/`

Run one package's tests or a single test:
```bash
go test -v ./pkg/command/           # a package
go test -v -run TestName ./cmd/gateway/
```
The security-critical layers are covered: `pkg/command` (allowlist + no-shell execution, ~97%), `pkg/audit` (signature/chain tamper detection), `cmd/agent`'s host-key verification and tool-arg validation, and the gateway's auth/redaction/OIDC paths. Still untested (lower value): `cmd/myrmex` (CLI glue) and `pkg/metrics` (OS introspection).

Nix (CI builds via Nix, so flake changes must pass): `nix build`, `nix flake check`, `nix run .#myrmex -- --help`. `nix develop` gives a shell with `go`, `just`, `docker-compose`.

Ollama side-services for the LLM: `docker compose --profile ollama-cpu up -d` (or `ollama-gpu`, needs NVIDIA toolkit), preloaded with `gemma4:e4b`.

## Architecture (the big picture)

**Reverse-tunnel topology.** The Agent (`cmd/agent/main.go`) is an SSH *client*: it dials the Gateway (`:2222`), authenticates with an Ed25519 key sending `agent_id` as the SSH username, opens a single channel named `mcp`, and serves JSON-RPC (`tools/list`, `tools/call`) over it. It **rejects all inbound channels** — targets never listen for management traffic. The Gateway (`cmd/gateway/main.go`) is the SSH *server*; each connected agent becomes an `AgentClient` (wraps the `ssh.Channel`) held in a global registry (`addAgent`/`getAgent`/`removeAgent`). This inversion is the whole security model — when debugging connectivity, the flow is always agent → gateway:2222, never the reverse.

**The Gateway is four servers in one process** (`main()` wires them up):
1. SSH receiver (`startSSHServer` / `handleSSHConnection`) — accepts agent tunnels.
2. Stdio MCP server (`startStdioMCPServer`) — MCP over stdin/stdout for local clients.
3. HTTP/SSE MCP + REST (`startHTTPServer`) on `:8080` — `handleSse`/`handleMessage` for SSE MCP; REST endpoints `/api/status`, `/api/call`, `/api/tools`, `/api/chat`, `/api/config`, `/api/keys`; and a web portal at `/` (`PortalHTML`).
4. Upstream MCP proxying — the Gateway can itself be a client of other MCP servers over SSE (`UpstreamClient`) or stdio (`StdioUpstreamClient`), configured via `upstream_servers` / `external_mcp_servers` and hot-reloaded (`reloadUpstreamClients`).

`cmd/gateway/main.go` is large (~6.5k lines) but gateway concerns are split across sibling files in the same package — **grep the package, not just `main.go`**: `oidc.go` (native OIDC/JWKS, #114), `metrics.go` (Prometheus exposition, #97), `alerting.go` (webhook/Alertmanager delivery, #100), `tracing.go` (OpenTelemetry, #98), `audit_api.go` (the `/api/audit` viewer, #111), `redact.go` (secret redaction on `/api/config`, #131), `portal.js` (the web portal's JS, embedded — #137). Beyond the endpoints listed above, the HTTP server also serves `/api/fleet`, `/api/approvals`, `/api/enroll` + `/api/agents/revoke`, `/api/audit`, `/metrics` (opt-in), and the peer-mesh `/internal/*`.

**Tool namespacing.** Every tool the Gateway exposes is `<agentID>__<toolName>` (split on `__` in `handleCallTool`). The prefix `gateway__` is reserved for Gateway-native tools (`ask_gemma`, `humanize_syslog`) — see `handleGatewayToolCall`. Agents natively provide `get_metrics`, `run_command`, `read_logs`, `get_system_info`, plus typed tools `service_control`, `file_read`, `container_ps`, `k8s_get`, and `package_query` (all dispatched in `handleCallTool`, `cmd/agent/main.go`). Every one that touches the host still routes through the `pkg/command` allowlist — `file_read` shells out to allowlisted `cat`, `service_control` to allowlisted `systemctl` — so a tool is never a bypass of the command allowlist.

**LLM orchestration.** `executeGemmaOrchestration` is the agentic loop: it asks the local Ollama model (`pkg/llm`) to pick an allowlisted command given a natural-language prompt (`GemmaCommandSelection`), executes it over the tunnel, and summarizes the result. `callGeminiAPI` is an alternate cloud path (Google Gemini) gated by `antigravity_token`.

**Security enforcement lives in two places:**
- `pkg/command/command.go` (`ExecuteCommand`) — runs approved commands via `os/exec` directly, **never through a shell**, so there is no shell-expansion/injection surface. The command name must be in the allowlist and its args must match the per-command `args_regex`.
- Gateway RBAC — `tokens` maps bearer token → role (`admin`/`operator`/`read-only`); `rolePermissions` is the capability matrix; `requireAuth` is the middleware. Actions are recorded to a **cryptographically signed audit log** (`logAuditEvent` + `signAuditData`, signed with the Gateway's SSH host key) when `audit_log_path` is set.

**Shared packages (`pkg/`):**
- `config` — all config structs + JSON loaders (`AgentConfig`, `GatewayConfig`, `UpstreamServer`, `ExternalMcpServerConfig`). Start here to understand any config field.
- `command` — allowlist validation + safe execution (above).
- `llm` — minimal Ollama HTTP client (`Generate`, `HumanizeLog`).
- `metrics` — per-OS system metrics via build tags (`metrics_linux.go`, `metrics_darwin.go`, `metrics_windows.go` behind `metrics.go`).

**Operator CLI (`cmd/myrmex/main.go`).** Talks only to the Gateway REST API (default `https://localhost:8080`), auth via `--token` or `MYRMEX_TOKEN`. Commands: `status`, `agents`, `upstreams`, `tools`, `config`, `call <agentID>__<tool>`, `ask "<prompt>"`. Supports `-o json` for piping to `jq`; otherwise renders Markdown in the terminal (`renderMarkdown`).

## Conventions & gotchas

- **Dependencies are vendored** (`vendor/`) and the flake sets `vendorHash = null` to use it directly. After changing `go.mod`, run `go mod vendor` or the Nix build breaks. Direct deps are `golang.org/x/crypto` (SSH), the OpenTelemetry SDK + OTLP/HTTP exporter (tracing, #98), and `coreos/go-oidc` + `go-jose` (native OIDC/JWKS validation, #114) — the OTel tree pulls gRPC/protobuf transitively and is most of the ~21MB `vendor/` (25 modules). **The bar for a new dependency is high**: prefer the stdlib. The Prometheus exposition (`cmd/gateway/metrics.go`) is hand-written for exactly this reason — the text format is a few `Fprintf` calls. OTel was taken deliberately because tracing's subtleties (context propagation, sampling, batching, retry) are where reimplementing a spec buys bugs rather than saves bytes.
- Agent-side gateway host-key verification is real (`buildHostKeyCallback` in `cmd/agent/main.go`): by default **trust-on-first-use** (learns and persists the gateway key to `<private_key_path>.gateway_hostkey`, then requires a match — a changed key is rejected as a possible MITM), or **explicit pinning** via `gateway_host_key` in the agent config. Covered by `cmd/agent/main_test.go`. (Historical note: this replaced an earlier `InsecureIgnoreHostKey()`; that is gone from production and now appears only in a gateway test.)
- GoReleaser (`.goreleaser.yaml`) renames binaries for distribution: `myrmex-gateway`, `myrmex-agent`, `myrmex`. The `bin/` names from `just build` differ (`gateway`, `agent`, `myrmex`).
- Config lives in `agent_config.json` / `gateway_config.json` at repo root for local runs. Multiple `gateway_addrs` on the agent enable HA failover cycling.
- Deployment surfaces: `Dockerfiles/`, `docker-compose.test.yml` (agent-1..3, agent-nginx, agent-db, gateway, ollama profiles), `k8s/` (agent DaemonSet + gateway), and a NixOS module `services.myrmex-hive` (`flake.nix`, role = gateway|agent).
- The repo root also hosts a Jekyll site (`_posts/`, `_layouts/`, `_config.yml`, `index.md`, GitHub Pages via `.github/workflows/pages.yml`) — unrelated to the Go build.
