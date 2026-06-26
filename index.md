---
layout: default
title: Home
---

## Welcome to Myrmex Hive

Myrmex Hive is a decentralized, secure, and geeky agent orchestration framework built on top of the **Model Context Protocol (MCP)**. It is designed to securely monitor, query, and manage distributed edge servers, Docker hosts, and Kubernetes nodes without exposing any ingress ports on your target systems.

---

### 1. Architecture & Security Model

Myrmex Hive is built for zero-trust environments where target edge systems (agents) must remain completely isolated from direct inbound network traffic.

```
┌──────────────────────────────────────┐        ┌──────────────────────────────┐
│  Target Edge Node (Myrmex Agent)     │        │ Central Hive Gateway         │
│                                      │        │                              │
│  - Gathers CPU, Memory, Disk         │        │ - Authenticates agents       │
│  - Runs strict command allowlist     │        │ - Aggregates client tools    │
│  - Connects OUTBOUND via SSH         │        │ - Exposes MCP over HTTP/SSE  │
│                                      │        │                              │
│             │                        │        │              ▲               │
└─────────────┼────────────────────────┘        └──────────────┼───────────────┘
              │                                                │
              │ SSH Outbound Tunnel (Port 2222)                │ Stdio / SSE MCP Interface
              ▼                                                ▼
       ┌──────────────┐                                 ┌──────────────┐
       │ Secure SSHD  │ ──────────────────────────────> │ Myrmex Hive  │
       │ Receiver     │    JSON-RPC over SSH channel    │ Orchestrator │
       └──────────────┘                                 └──────────────┘
                                                               │
                                                               ▼
                                                        ┌──────────────┐
                                                        │ Ollama LLM   │
                                                        │ (Gemma 4/2)  │
                                                        └──────────────┘
```

#### Security Principles (Why We Made These Choices)
* **Zero Inbound Ports**: Instead of running an SSH daemon or exposing management ports (like HTTP/gRPC) on your target servers, the **Myrmex Agent** initiates a secure, outbound connection to the **Myrmex Gateway**. This eliminates the primary attack vector of public scanner discovery and automated brute-force attacks.
* **OS-Grade Encryption**: Outbound tunnels utilize standard SSH protocol channels managed via Go's native `crypto/ssh` package, enforcing secure Ed25519 signature validation and high-grade ciphers (ChaCha20-Poly1305, AES-GCM).
* **Defense-in-Depth Allowlist**: The Agent executes binaries directly via OS process forks (`os/exec`) rather than invoking a shell shell (like `/bin/sh` or `bash`). This completely bypasses shell shell expansion, neutralizing shell injection vulnerabilities. Arguments are strictly validated against developer-defined regular expressions in `config.json`.
* **Central Token Authorization**: Access to the Gateway's control API is guarded via secure bearer token authentication.

---

### 2. Multi-Platform Installation Guide

Myrmex Hive supports Go, Nix, Linux, macOS, and Windows environments.

#### Nix / NixOS (Declarative Flake)
Add Myrmex Hive to your `flake.nix` inputs:
```nix
inputs.myrmex-hive.url = "github:olafkfreund/myrmex-hive";
```

You can then run the CLI tool directly:
```bash
nix run github:olafkfreund/myrmex-hive#myrmex -- --help
```

To deploy a Myrmex Agent or Gateway as a declarative systemd service on NixOS, enable the module in your `configuration.nix`:
```nix
{ inputs, config, pkgs, ... }: {
  imports = [ inputs.myrmex-hive.nixosModules.default ];

  services.myrmex-hive = {
    enable = true;
    role = "agent"; # Or "gateway"
    configPath = "/etc/myrmex/agent_config.json";
  };
}
```

#### Linux & macOS (Direct Install)
To download, compile, and configure the Agent as a background daemon (systemd on Linux, LaunchDaemon on macOS):
```bash
sudo ./install.sh
```
*The installer automatically compiles the agent binary, generates secure Ed25519 keys, writes the `config.json`, and boots the service.*

#### Windows (PowerShell Script)
To install the Agent on Windows Server or Windows 10/11, launch PowerShell as **Administrator** and run:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install.ps1
```
*The PowerShell script compiles the binary, registers the agent configuration under `C:\ProgramData\mcp-agent\`, generates OpenSSH keys, and schedules a background task to launch the agent at system startup.*

---

### 3. Local LLM Setup (Ollama & Gemma)

Myrmex Hive orchestrates actions and interprets output using local LLMs.
1. Install [Ollama](https://ollama.com/) on your Gateway server.
2. Pull the desired model (Gemma 2/4):
   ```bash
   ollama pull gemma2:2b
   ```
3. Ensure Ollama is running and accessible (default `http://localhost:11434`). Link it in `gateway_config.json`.

---

### 4. Using the Myrmex CLI (`myrmex`)

The Go-based Myrmex CLI allows operators to interact with the gateway, view agents, invoke tools, and launch the assistant directly from the terminal.

#### Global Options
* `--url`: Gateway API base URL (default: `https://localhost:8080`)
* `--token`: Gateway token (or `MYRMEX_TOKEN` environment variable)
* `-o`, `--output`: Output format (`text` or `json`)

#### CLI Command Reference
* **Status**: View connected edge agents and configured upstream servers:
  ```bash
  myrmex status
  ```
* **Agents**: List detailed specifications of all connected agents:
  ```bash
  myrmex agents
  ```
* **Tools**: List all available tools across the swarm:
  ```bash
  myrmex tools
  ```
* **Call**: Execute a tool on a specific agent. Automatically unmasks and un-escapes payloads:
  ```bash
  myrmex call agent-nginx__get_metrics
  ```
* **Call with JSON output**: Outputs a clean, raw JSON payload directly to stdout (perfect for piping to `jq`):
  ```bash
  myrmex call agent-nginx__get_metrics -o json | jq '.cpu_usage_percent'
  ```
* **Ask**: Prompt the Myrmex AI assistant to analyze and perform actions. Terminal output is beautifully styled in monospace markdown:
  ```bash
  myrmex ask "Is nginx running on agent-nginx? If not, restart it."
  ```
* **Ask with JSON output**: Forward the final AI response directly to other automated tools or agents:
  ```bash
  myrmex ask "Check system metrics" -o json
  ```

---

### 5. Real-Life Orchestration Scenarios

#### Scenario A: Automated Cluster Recovery
An operator issues a query:
`myrmex ask "Check load average on agent-db. If it's over 4.0, run diagnostic logs and let me know what process is consuming CPU."`
1. The orchestrator calls `agent-db__get_metrics`.
2. The orchestrator parses the returned metrics JSON.
3. If the load is over `4.0`, the local Gemma model identifies that `agent-db__run_command` with argument `{"cmd":"top"}` (or an allowed diagnostics script) is available in the allowlist.
4. The orchestrator executes the tool, parses the logs, and presents a clean, formatted report directly to the terminal.

#### Scenario B: Integration with Antigravity SDK
You can easily drive Myrmex Hive programmatically from other automated AI systems, such as **Antigravity SDK** agents. 
The gateway exposes standard endpoints (`/api/chat` and `/api/call`) protected by the secure bearer token. Your Antigravity agents can query the endpoint, receive structured tool list payloads, and trigger actions over the SSH tunnel.

---

### 6. GCP Best Practices

For cloud deployments on Google Cloud Platform:
1. **VM Isolation**: Deploy the Myrmex Gateway on a secure Compute Engine VM inside a private VPC. Expose the Gateway's control interface (`:8080`) only through **Identity-Aware Proxy (IAP)** to enforce IAM roles.
2. **Kubernetes Agents**: Deploy Myrmex Agents on Google Kubernetes Engine (GKE) as a DaemonSet to automatically monitor and manage GKE node resources.
3. **Secret Security**: Avoid storing the Gateway auth token in config files. Fetch the token dynamically at startup from **Google Secret Manager**.

---

### 7. Airgapped Datacenters

In highly secure, airgapped systems:
* Myrmex Hive requires no public DNS or external internet access.
* Deploy **Ollama** locally on the Gateway server. Since Ollama and the Myrmex Gateway run in the same local network, LLM inference occurs entirely within the airgapped perimeter.
* Agents establish SSH tunnels internally over local subnets, maintaining a completely airgapped, auditable management plane.
