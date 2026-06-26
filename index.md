---
layout: default
title: Home
---

## Welcome to Myrmex Hive

Myrmex Hive (formerly MCP-Hive) is a secure, geeky, and lightweight **Agent Orchestrator and Gateway** built specifically to manage a swarm of remote OS agents using the Model Context Protocol (MCP).

By utilizing a secure outbound SSH tunnel, Myrmex Hive allows multiple distributed edge nodes (Linux, macOS, and Windows) to connect back to a central gateway without exposing any ingress ports on the edge devices.

### Core Features

* **Multi-Transport MCP Integration**: Register and manage local Stdio subprocess servers and remote SSE connections directly from the control portal.
* **Outbound SSH Tunneling**: Simple, lightweight agent nodes establish encrypted connections back to the Gateway.
* **Gemma 4 Small Orchestration**: An integrated local LLM coordinate engine that queries agent nodes and executes tools.
* **Gruvbox Dark Aesthetics**: Pure monospace layout designed for terminal dwellers and command line power users.
* **No Bloat**: Built in pure Go, HTML5, Vanilla CSS, and JavaScript.

### Getting Started

To run Myrmex Hive locally or spin up a test swarm:

```bash
# Clone the repository
git clone https://github.com/olafkfreund/myrmex-hive.git
cd myrmex-hive

# Format and check syntax
just validate

# Launch a 5-node agent and gateway swarm in docker
docker compose -f docker-compose.test.yml up -d --build
```
