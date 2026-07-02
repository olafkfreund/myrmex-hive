---
layout: post
title: "Myrmex Hive v1.0.0: Zero-Inbound Fleet Management, Hardened"
date: 2026-07-02 10:00:00 +0100
author: olafkfreund
---

Today we are releasing **Myrmex Hive v1.0.0** — the first major release of an open-source Go framework for securely managing distributed edge servers with **zero inbound ports on the targets**.

The path to 1.0.0 started as a security review. We set out to audit the trust boundaries of the early prototype and came out the other side with a hardened, feature-complete platform: signed audit trails, fine-grained access control, a shell-free execution boundary, and an LLM orchestration loop that assumes its own prompts are hostile. What follows is what shipped, and why it matters.

### The core idea: agents dial out, never in

Myrmex Hive inverts the usual management topology. Agents on the targets make **only outbound SSH connections** to a central gateway. The targets never listen for management traffic — there is nothing inbound to firewall, port-scan, or exploit. Operators reach the gateway (never the agents directly) over CLI, MCP, or REST.

This single design decision is what makes the rest of the security model tractable, and it is why the platform fits three audiences especially well:

- **Regulated and compliance-heavy** environments (healthcare, finance, defense) that need a tamper-evident record of every action.
- **Airgapped and OT** networks that cannot expose inbound ports and cannot call out to a cloud LLM.
- **Edge and distributed-fleet** operators managing servers behind NAT, in the field, or across untrusted networks.

### What's in v1.0.0

**Tamper-evident audit log.** Every action is written to a signed, hash-chained (Ed25519) audit log — each entry links to the one before it, so tampering or deletion is detectable, not just discouraged. A `myrmex audit verify / export / watch` toolchain lets you check integrity, export for compliance, and follow the log live.

**Fine-grained RBAC.** Tokens are scoped per-agent, per-tag, and per-tool. Commands are classified into risk tiers, high-risk actions can require human-in-the-loop approval, and rate limiting caps the blast radius of any single token.

**Fleet telemetry.** Heartbeat, metrics history, inventory, and threshold-based alerting feed a Fleet + Approvals dashboard — so you can see the state of the whole fleet and act on pending approvals in one place.

**Optional, pluggable LLM orchestration.** Natural-language orchestration is available but never required. It runs against Ollama, OpenAI, vLLM, or llama.cpp, and works **fully airgapped** with a local model. The tool-calling loop is bounded and hardened against prompt injection — the model proposes, the safety boundary disposes.

**A shell-free execution boundary.** Agents run a typed tool library (service, container, k8s, package, file) behind a **regex allowlist**. Commands are executed directly — never through a shell — so there is no shell-expansion or injection surface. This is the hard line the LLM (and every operator) is constrained by.

**Full agent lifecycle.** Enrollment via join-tokens, revocation, key rotation, mTLS, and OIDC (via proxy). A `myrmex bootstrap` command turns onboarding a new agent into a single step.

**Secret indirection.** Secrets are referenced, not embedded — pull them from env, file, Vault, or agenix.

**Multi-gateway peer-mesh HA.** Gateways form a peer mesh with a shared fleet view and cross-gateway call forwarding, so operators keep working through a gateway outage.

### Supply-chain integrity

v1.0.0 ships **Cosign-signed, cross-platform binaries with SBOMs** for linux, macOS, and Windows on amd64 and arm64. Built with Go 1.25.

### Quickstart

Install the CLI:

```bash
go install github.com/olafkfreund/myrmex-hive/cmd/myrmex@v1.0.0
```

Or download a release archive from the [releases page](https://github.com/olafkfreund/myrmex-hive/releases/tag/v1.0.0), or use the `install.sh` script.

Onboard an agent and query the fleet:

```bash
# One-command agent onboarding
myrmex bootstrap

# Ask a natural-language question (local LLM, works airgapped)
myrmex ask "Is the database service running?" --token "operator-token"

# Verify the integrity of the audit log
myrmex audit verify
```

### Links

- **Repository:** [github.com/olafkfreund/myrmex-hive](https://github.com/olafkfreund/myrmex-hive)
- **Release:** [v1.0.0](https://github.com/olafkfreund/myrmex-hive/releases/tag/v1.0.0)

Myrmex Hive is open source. If zero-inbound fleet management with a tamper-evident audit trail solves a problem you have, we would love your feedback and contributions.
