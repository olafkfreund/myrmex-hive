---
layout: post
title: "Deploying Gemma 4 with Ollama Side-Services"
date: 2026-06-27 08:00:00 +0100
author: olafkfreund
---

We are introducing full support for Google's **Gemma 4** model preloaded within a self-contained, offline-ready Ollama side-service for Myrmex Hive.

In enterprise and airgapped environments, relying on public cloud APIs for LLM inference poses severe data privacy, latency, and compliance risks. By coupling the Myrmex Gateway with a local Ollama instance running Gemma 4, all orchestrations, diagnostic log reasoning, and tool calls are handled completely within the private perimeter.

### 1. Preloaded Offline Gemma 4 Image

During the build step, the container launches a background instance of Ollama to download and bundle the `gemma4:e4b` model weights into the Docker image layers. This avoids any network calls at runtime:

```dockerfile
FROM ollama/ollama:latest
ENV OLLAMA_HOST=0.0.0.0
ENV OLLAMA_ORIGINS="*"
RUN (ollama serve &) && \
    sleep 5 && \
    ollama pull gemma4:e4b && \
    pkill ollama
```

### 2. Dual CPU and GPU Integration

Depending on host hardware availability, administrators can run Ollama using CPU-only mode or harness hardware acceleration using Nvidia GPUs:

#### A. CPU-Only Deployment
```bash
docker compose --profile ollama-cpu up -d
```

#### B. GPU-Accelerated Deployment (Nvidia GPUs)
```bash
docker compose --profile ollama-gpu up -d
```

### 3. Verification & Compliance Auditing

Once the container is running, the gateway connects to it via standard HTTP API. When an operator triggers a query:

```bash
myrmex ask "Check if service nginx is running on agent-nginx" --token "operator-token-456"
```

1. The gateway routes the prompt to the Ollama container.
2. Gemma 4 parses the response, identifies that it needs system status metrics, and executes the `agent-nginx__get_metrics` tool.
3. Every API transaction is logged in `audit.log` and cryptographically signed with the gateway's private SSH host key, providing tamper-proof audit trails for compliance verification.
