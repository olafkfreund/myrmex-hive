# MCP-Hive: Secure SSH-based Linux Monitoring & Command Gateway

MCP-Hive is a Model Context Protocol (MCP) framework designed to securely monitor and manage Linux servers, Docker containers, and Kubernetes clusters using SSH-key authentication. 

Instead of exposing standard SSH ports on your target servers, **MCP-Hive Agents** connect *outbound* to a central **MCP-Hive Gateway** over a highly encrypted SSH tunnel (using Ed25519 keys). The Gateway aggregates these connections and exposes a single aggregated MCP interface to AI clients (like Claude, Antigravity, or other tools), allowing secure, controlled system operations.

---

## Architecture Diagram

```
┌──────────────────────────────────────┐        ┌──────────────────────────────┐
│  Target Linux Node (Agent)           │        │ Secure Gateway Server        │
│                                      │        │                              │
│  - Gathers CPU, Memory, Disk         │        │ - Authenticates agents       │
│  - Runs strict command allowlist     │        │ - Aggregates client tools    │
│  - Connects OUTBOUND via SSH         │        │ - Exposes MCP over Stdio/SSE │
│                                      │        │                              │
│             │                        │        │              ▲               │
└─────────────┼────────────────────────┘        └──────────────┼───────────────┘
              │                                                │
              │ SSH Outbound (TCP :2222)                       │ Stdio (Claude / Antigravity)
              ▼                                                ▼
       ┌──────────────┐                                 ┌──────────────┐
       │ SSH Server   │ ──────────────────────────────> │ MCP Gateway  │
       │              │    JSON-RPC over SSH channel    │ Router       │
       └──────────────┘                                 └──────────────┘
                                                               │
                                                               ▼
                                                        ┌──────────────┐
                                                        │ Local LLM    │
                                                        │ (Gemma 2)    │
                                                        └──────────────┘
```

---

## Core Security Features

1. **Zero Open Ports**: Agents connect outbound to the Gateway. Target servers require no public IPs or inbound firewall modifications.
2. **OS-Approved High Encryption**: Connections use SSH (via Go's native, standard `crypto/ssh` package), enforcing Ed25519 signatures and industry-standard cipher suites (AES-GCM, ChaCha20-Poly1305).
3. **Defense-in-Depth Allowlist**: The Agent executes commands directly (bypassing shell shells to prevent command injection) and checks all arguments against a strict regex allowlist specified in `agent_config.json`.
4. **Local LLM Orchestration**: The Gateway integrates with Ollama (e.g. Gemma 2) to translate natural language prompts into approved command lists, executes them, and humanizes raw command/syslog outputs.

---

## Directory Structure

```
├── cmd/
│   ├── agent/          # Agent entrypoint (SSH client & metrics gatherer)
│   └── gateway/        # Gateway entrypoint (SSH server & MCP routing hub)
├── pkg/
│   ├── command/        # Secure command execution validation engine
│   ├── config/         # Config loaders for Agent and Gateway
│   ├── llm/            # Local LLM (Ollama) integration helper
│   └── metrics/        # Native Linux metrics parser (procfs & Statfs)
├── Dockerfiles/        # Multi-stage Docker deployment configurations
├── k8s/                # Kubernetes Deployment & DaemonSet manifests
├── Justfile            # Build, test, and validate tasks
└── README.md           # Documentation
```

---

## Quickstart Guide

### 1. Requirements
* Go 1.21+
* Just (optional, for running recipe commands)
* Ollama running locally (for Gemma 2 integration)

### 2. Generate Credentials
Run the key generator script to create a secure Ed25519 keypair for the agent and register its public key in the gateway's `authorized_keys` file:
```bash
just generate-keys
# Or manually:
# ssh-keygen -t ed25519 -f id_ed25519 -N "" -q
# cat id_ed25519.pub > authorized_keys
```

### 3. Build & Validate
Compile the binaries and perform static code checking:
```bash
just validate
just build
```

### 4. Run Locally
**Start the Gateway:**
```bash
just run-gateway
```

**Start the Agent (in a separate terminal):**
```bash
just run-agent
```

---

## Configuration Settings

### Agent (`agent_config.json`)
The Agent defines its identity and the commands it is allowed to execute:
```json
{
  "gateway_addr": "localhost:2222",
  "private_key_path": "id_ed25519",
  "agent_id": "prod-server-1",
  "allowed_commands": [
    {
      "name": "uptime",
      "args_regex": "^$"
    },
    {
      "name": "df",
      "args_regex": "^-h$"
    },
    {
      "name": "systemctl",
      "args_regex": "^(status|restart) (nginx|docker|sshd)$"
    }
  ]
}
```

### Gateway (`gateway_config.json`)
The Gateway defines its listen address, authorized public keys, and LLM configuration:
```json
{
  "listen_addr": ":2222",
  "host_key_path": "",
  "authorized_keys_path": "authorized_keys",
  "ollama_url": "http://localhost:11434",
  "ollama_model": "gemma2:2b"
}
```
*Note: If `host_key_path` is left empty, the Gateway generates a transient host key at startup for ease of development.*

---

## Using with MCP Clients (e.g. Claude Desktop)

To expose all target agents to Claude Desktop, add the gateway command configuration to your `claude_desktop_config.json` (typically under `~/.config/Claude/claude_desktop_config.json` on Linux):

```json
{
  "mcpServers": {
    "mcp-hive": {
      "command": "/absolute/path/to/mcp-os-agent/bin/gateway",
      "args": ["-config", "/absolute/path/to/mcp-os-agent/gateway_config.json"]
    }
  }
}
```

Once loaded, Claude will have access to the following tools:
* `gateway__list_agents`: Lists all registered servers.
* `<agent_id>__get_metrics`: Collects RAM, Disk, CPU, Load average metrics.
* `<agent_id>__run_command`: Runs approved commands.
* `gateway__ask_gemma`: Integrates local LLM to execute high-level tasks.
* `gateway__humanize_syslog`: Explains syslog warnings.

---

## Local LLM Examples

### 1. Humanizing Syslogs
If you feed a raw syslog warning like:
> `sshd[12402]: Invalid user admin from 192.168.1.15 port 43212`

Calling `gateway__humanize_syslog` will prompt Gemma 2 to return:
> *"Warning: There was a failed login attempt for the user 'admin' from IP 192.168.1.15."*

### 2. High-level Commands (Ask Gemma)
By calling `gateway__ask_gemma` with `agent_id: "prod-server-1"` and `prompt: "check if the system load is high and free memory if it is too low"`:
1. Gemma looks up the agent's available tools.
2. Gemma calls `prod-server-1__get_metrics`.
3. Gemma analyzes the metrics. If memory is low, it finds that `systemctl restart nginx` (or another allowed command) is available in the allowlist.
4. Gemma triggers the command, inspects the result, and explains to the user: *"Memory usage was at 92%. I restarted the Nginx service to release memory, which is now at 45%."*
