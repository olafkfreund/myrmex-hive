# Myrmex Hive: Secure Agent Orchestrator & Gateway

Myrmex Hive is a decentralized, secure, and geeky agent orchestration framework built on top of the **Model Context Protocol (MCP)**. It is designed to securely monitor, query, and manage distributed edge servers, Docker hosts, and Kubernetes nodes without exposing any ingress ports on your target systems.

---

## 1. Architecture & Security Model

Myrmex Hive is designed for zero-trust environments where target edge systems (agents) must remain completely isolated from direct inbound network traffic.

```mermaid
flowchart TD
    %% Node Definitions
    subgraph Edge ["Target Edge Node (Myrmex Agent)"]
        Agent["Myrmex Agent<br/>(CPU/Mem/Disk, strict allowlist)"]
    end

    subgraph Gateway ["Central Hive Gateway"]
        SSHD["Secure SSHD Receiver<br/>(Port 2222)"]
        Orch["Myrmex Hive Orchestrator"]
        LLM["Ollama LLM<br/>(Gemma 4/2)"]
    end

    Client["Client / CLI / Portal<br/>(Stdio / SSE MCP Interface)"]

    %% Connections
    Agent -- "SSH Outbound Tunnel" --> SSHD
    SSHD -- "JSON-RPC over SSH channel" --> Orch
    Orch <--> LLM
    Client <--> Orch

    %% Styling / Colors
    classDef edgeNode fill:#282828,stroke:#fabd2f,stroke-width:2px,color:#ebdbb2;
    classDef gatewayNode fill:#282828,stroke:#fe8019,stroke-width:2px,color:#ebdbb2;
    classDef clientNode fill:#282828,stroke:#b8bb26,stroke-width:2px,color:#ebdbb2;

    class Agent edgeNode;
    class SSHD,Orch,LLM gatewayNode;
    class Client clientNode;
```

### Security Principles (Why We Made These Choices)
* **Zero Inbound Ports**: Instead of running an SSH daemon or exposing management ports (like HTTP/gRPC) on your target servers, the **Myrmex Agent** initiates a secure, outbound connection to the **Myrmex Gateway**. This eliminates the primary attack vector of public scanner discovery and automated brute-force attacks.
* **OS-Grade Encryption**: Outbound tunnels utilize standard SSH protocol channels managed via Go's native `crypto/ssh` package, enforcing secure Ed25519 signature validation and high-grade ciphers (ChaCha20-Poly1305, AES-GCM).
* **Defense-in-Depth Allowlist**: The Agent executes binaries directly via OS process forks (`os/exec`) rather than invoking a shell shell (like `/bin/sh` or `bash`). This completely bypasses shell shell expansion, neutralizing shell injection vulnerabilities. Arguments are strictly validated against developer-defined regular expressions in `config.json`.
* **Central Token Authorization**: Access to the Gateway's control API is guarded via secure bearer token authentication.

---

## 2. Quickstart & Installation

Myrmex Hive supports Go, Nix, Linux, macOS, and Windows environments.

### Nix / NixOS (Declarative Flake)
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

### macOS (Homebrew)

```bash
brew tap olafkfreund/myrmex
brew install --cask myrmex-hive
```

Installs all three binaries: `myrmex` (operator CLI), `myrmex-gateway`, and `myrmex-agent`.

*macOS only — Homebrew casks are not supported on Linuxbrew. On Linux use the deb/rpm packages from the [releases page](https://github.com/olafkfreund/myrmex-hive/releases), the Nix flake, `install.sh`, or the container images.*

### Linux & macOS (Direct Install)
To download, compile, and configure the Agent as a background daemon (systemd on Linux, LaunchDaemon on macOS):
```bash
sudo ./install.sh
```
*The installer automatically compiles the agent binary, generates secure Ed25519 keys, writes the `config.json`, and boots the service.*

### Windows (PowerShell Script)
To install the Agent on Windows Server or Windows 10/11, launch PowerShell as **Administrator** and run:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\install.ps1
```
*The PowerShell script compiles the binary, registers the agent configuration under `C:\ProgramData\mcp-agent\`, generates OpenSSH keys, and schedules a background task to launch the agent at system startup.*

### Kubernetes (Helm)

Versioned container images and a Helm chart are published to GHCR on every release:

```bash
helm install hive oci://ghcr.io/olafkfreund/charts/myrmex-hive \
  --version 1.0.0 \
  --namespace myrmex --create-namespace
```

`--version` pins the chart and the images together (v1.0.1+; v1.0.0 predates
image/chart publishing). See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the image list, a working install
with agent keys, and the TLS/Service/`agent_id` caveats.

---

## 3. Configuration

### Agent Configuration (`agent_config.json`)
Allows you to define a single gateway or a list of multiple gateway addresses for High Availability (HA) failover cycling:
```json
{
  "agent_id": "agent-nginx",
  "gateway_addr": "gateway-1.internal:2222",
  "gateway_addrs": [
    "gateway-1.internal:2222",
    "gateway-2.internal:2222"
  ],
  "private_key_path": "/etc/mcp-agent/id_ed25519",
  "allowed_commands": [
    {
      "name": "uptime",
      "args_regex": "^$"
    },
    {
      "name": "systemctl",
      "args_regex": "^(status|restart) (nginx|postgresql)$"
    }
  ]
}
```

### Gateway Configuration (`gateway_config.json`)
Configures the receiver, TLS certs, OIDC/Tokens RBAC role mapping (`admin`, `operator`, `read-only`), and signed audit log path:
```json
{
  "listen_addr": ":2222",
  "http_addr": ":8080",
  "host_key_path": "host_key",
  "authorized_keys_path": "authorized_keys",
  "ollama_url": "http://localhost:11434",
  "ollama_model": "gemma4:e4b",
  "auth_token": "fallback_admin_token",
  "tokens": {
    "admin-token-123": "admin",
    "operator-token-456": "operator",
    "read-token-789": "read-only"
  },
  "audit_log_path": "audit.log",
  "metrics_enabled": true
}
```
*Note: If `audit_log_path` is set, Myrmex Gateway records all `/api/call` and `/api/chat` executions alongside a cryptographic signature generated using the Gateway's private SSH host key.*

*Note: `oidc_issuer` enables native OIDC/JWKS validation of real SSO tokens (opt-in; static tokens keep working alongside). See [docs/SECRETS.md](docs/SECRETS.md).*

*Note: `metrics_enabled` exposes a Prometheus endpoint at `/metrics` (opt-in; behind the same bearer-token auth as the rest of the API). Myrmex Gateway can also route threshold alerts to a webhook/Alertmanager and export OpenTelemetry traces over OTLP — all opt-in. See [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md) for the metric reference, a `scrape_config`, the Grafana dashboard, alert routing and tracing.*

### Fail-closed defaults

Myrmex Gateway **fails closed**: it refuses to start (or rejects a connection) rather than run in an insecure state. When preparing configs and keys, three rules are enforced:

1. **`authorized_keys` comment = agent-id (identity binding).** The Gateway takes each connected agent's identity from the **comment** on its `authorized_keys` entry, and rejects any key whose comment is empty or does not match the `agent_id` the agent presents. Generate every agent key with its agent-id as the comment:
   ```bash
   ssh-keygen -t ed25519 -f id_ed25519 -N "" -C "agent-nginx"
   ```
   Then the public line in `authorized_keys` must keep that comment (`ssh-ed25519 AAAA... agent-nginx`).

2. **Persistent `host_key_path` required when `audit_log_path` is set.** Audit entries are signed with the Gateway's SSH host key, so a transient (regenerated-on-restart) key would make past signatures unverifiable. The Gateway **refuses to start** if `audit_log_path` is set but `host_key_path` is empty. Generate a stable host key once and point `host_key_path` at it:
   ```bash
   ssh-keygen -t ed25519 -f host_key -N "" -C "myrmex-gateway"
   ```
   The Gateway also refuses to start without `authorized_keys_path` (no agent allowlist).

3. **Agents verify the Gateway host key.** By default agents use **trust-on-first-use (TOFU)**: on first connect they learn and persist the Gateway host key to `<private_key_path>.gateway_hostkey` (override with `known_host_key_path`) and require a matching key thereafter — no config change needed. To pin explicitly instead, set `gateway_host_key` in `agent_config.json` to the Gateway host public-key line:
   ```json
   { "gateway_host_key": "ssh-ed25519 AAAA... myrmex-gateway" }
   ```

The local test fixtures (`generate_keys.sh`, `setup_test_env.sh`) already satisfy all three: agent keys are commented with their agent-ids, a persistent `test_env/gateway/host_key` is generated and mounted, and agents rely on TOFU.

---

## 4. Local LLM Setup (Ollama & Gemma 4)

Myrmex Hive orchestrates actions and interprets output using local LLMs.

### Option A: Running as Docker Side-Services (Recommended)
An optional Docker setup is available via profiles in `docker-compose.test.yml` preloaded with the `gemma4:e4b` model (offline-ready):

* **CPU-only mode**:
  ```bash
  docker compose --profile ollama-cpu up -d
  ```
* **GPU-accelerated mode** (requires NVIDIA Container Toolkit):
  ```bash
  docker compose --profile ollama-gpu up -d
  ```

### Option B: Manual Host Setup
1. Install [Ollama](https://ollama.com/) on your Gateway server.
2. Pull the desired model (Gemma 4):
   ```bash
   ollama pull gemma4:e4b
   ```
3. Ensure Ollama is running and accessible (default `http://localhost:11434`). Link it in `gateway_config.json`.

---

## 5. Using the Myrmex CLI (`myrmex`)

The Go-based Myrmex CLI allows operators to interact with the gateway, view agents, invoke tools, and launch the assistant directly from the terminal.

### Global Options
* `--url`: Gateway API base URL (default: `https://localhost:8080`)
* `--token`: Gateway token (or `MYRMEX_TOKEN` environment variable)
* `-o`, `--output`: Output format (`text` or `json`)

### CLI Command Reference
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

## 6. Real-Life Orchestration Scenarios

### Scenario A: Automated Cluster Recovery
An operator issues a query:
`myrmex ask "Check load average on agent-db. If it's over 4.0, run diagnostic logs and let me know what process is consuming CPU."`
1. The orchestrator calls `agent-db__get_metrics`.
2. The orchestrator parses the returned metrics JSON.
3. If the load is over `4.0`, the local Gemma model identifies that `agent-db__run_command` with argument `{"cmd":"top"}` (or an allowed diagnostics script) is available in the allowlist.
4. The orchestrator executes the tool, parses the logs, and presents a clean, formatted report directly to the terminal.

### Scenario B: Integration with Antigravity SDK
You can easily drive Myrmex Hive programmatically from other automated AI systems, such as **Antigravity SDK** agents. 
The gateway exposes standard endpoints (`/api/chat` and `/api/call`) protected by the secure bearer token. Your Antigravity agents can query the endpoint, receive structured tool list payloads, and trigger actions over the SSH tunnel.

### Scenario C: Airgapped Gemma 4 Setup & Cryptographic Auditing
An enterprise administrator configures a secure, fully compliance-audited local assistant using the offline-ready Ollama side-service:
1. **Launch Ollama**: The administrator starts the preloaded CPU-only Gemma 4 side-service in Docker:
   ```bash
   docker compose --profile ollama-cpu up -d
   ```
2. **Configure Gateway**: In `gateway_config.json`, the gateway is linked to the Ollama endpoint:
   ```json
   "ollama_url": "http://myrmex-ollama-cpu:11434",
   "ollama_model": "gemma4:e4b"
   ```
3. **Execute Operator Request**: An operator executes a compliance-audited CLI query:
   ```bash
   myrmex ask "Verify the nginx server is running on agent-nginx" --token "operator-token-456"
   ```
4. **Log & Verify Audit Event**: Since the request has write-like evaluation steps, the gateway logs a cryptographically signed entry in `audit.log` showing the timestamp, token role (`operator`), API route (`/api/chat`), and base64 signature. The security auditor verifies the log authenticity using the gateway's public SSH host key.

---

## 7. GCP Best Practices

For cloud deployments on Google Cloud Platform:
1. **VM Isolation**: Deploy the Myrmex Gateway on a secure Compute Engine VM inside a private VPC. Expose the Gateway's control interface (`:8080`) only through **Identity-Aware Proxy (IAP)** to enforce IAM roles.
2. **Kubernetes Agents**: Deploy Myrmex Agents on Google Kubernetes Engine (GKE) as a DaemonSet to automatically monitor and manage GKE node resources.
3. **Secret Security**: Avoid storing the Gateway auth token in config files. Fetch the token dynamically at startup from **Google Secret Manager**.

---

## 8. Airgapped Datacenters

In highly secure, airgapped systems:
* Myrmex Hive requires no public DNS or external internet access.
* Deploy **Ollama** locally on the Gateway server. Since Ollama and the Myrmex Gateway run in the same local network, LLM inference occurs entirely within the airgapped perimeter.
* Agents establish SSH tunnels internally over local subnets, maintaining a completely airgapped, auditable management plane.
