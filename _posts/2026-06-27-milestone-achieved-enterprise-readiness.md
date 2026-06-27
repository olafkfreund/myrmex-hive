---
layout: post
title: "Milestone Achieved: Enterprise Readiness & Airgapped Gemma 4 Setup"
date: 2026-06-27 09:00:00 +0100
author: olafkfreund
---

We are proud to announce the completion of a major milestone for **Myrmex Hive**: the platform is now fully ready for deployment in highly regulated, airgapped enterprise environments.

By closing critical architecture gaps, we have combined decentralized agent orchestration with security, compliance, high availability, and offline AI reasoning.

### What We Have Achieved

Here is a summary of the capabilities now ready in the repository:

1. **High Availability (HA) Failover**: Edge agents now accept multiple upstream Gateway addresses (`gateway_addrs`) and automatically cycle through them to maintain persistent, redundant control tunnels even if primary nodes experience downtime.
2. **Dynamic RBAC & Access Control**: The gateway implements dynamic path-based authorization. Authentication tokens map directly to roles (`admin`, `operator`, `read-only`), restricting access to sensitive endpoints.
3. **Cryptographically Signed Audit Logs**: For full compliance and accountability, all actions executed through `/api/call` and `/api/chat` are stored in a structured JSON audit log. Each entry is cryptographically signed using the Gateway's private SSH host key to prevent log tampering.
4. **Offline Gemma 4 Sidecar**: An optional, preloaded Docker Compose service is available. It pulls and embeds the `gemma4:e4b` model inside the container layer at build-time, allowing secure, offline LLM inference.
5. **Multi-Platform Go CLI**: The compilation of the multi-platform `myrmex` command-line tool is complete, supporting beautiful markdown text formatting and raw JSON outputs (`-o json`) for piping to other automation suites.

---

### How to Use the New Setup

Getting started with the secure enterprise configuration requires only a few steps:

#### 1. Setup Configuration Tunnels
Ensure your agents are configured with multiple gateway addresses. In `agent_config.json`:
```json
{
  "gateway_addrs": [
    "gateway1.local:2222",
    "gateway2.local:2222"
  ],
  "agent_id": "agent-nginx",
  "private_key_path": "id_ed25519"
}
```

#### 2. Run the Sidecar & Gateway Swarm
To deploy the Gateway and agents alongside the local Gemma 4 assistant:

* **CPU-Only Mode**:
  ```bash
  docker compose --profile ollama-cpu up -d
  ```
* **GPU-Accelerated Mode** (Requires NVIDIA Container Toolkit):
  ```bash
  docker compose --profile ollama-gpu up -d
  ```

#### 3. Query the Orchestrator with the CLI
Install the compiled binary for your OS and query the agents using the formatted output or raw JSON:

```bash
# Formatted Markdown Ask (uses local Gemma 4)
myrmex ask "Is the database service running?" --token "operator-token-456"

# Pipe Raw JSON Call Output
myrmex call agent-nginx__get_metrics -o json | jq '.connections'
```

#### 4. Audit & Compliance Verification
Check the local `audit.log` file on the Gateway host. Every tool execution contains a unique cryptographic signature. You can verify the integrity of the action log using the gateway's public SSH host key:
```json
{
  "timestamp": "2026-06-27T08:00:00Z",
  "token_role": "operator",
  "action": "/api/chat",
  "payload": "Verify nginx is running",
  "signature": "SHA256:..."
}
```
