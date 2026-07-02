# Reddit Launch Post — Myrmex Hive v1.0.0

**Suggested subreddit:** r/selfhosted (primary) — or r/devops as a secondary, reframed slightly toward fleet/compliance ops.

**Suggested title:**
Managing edge servers without opening a single inbound port — my zero-inbound fleet tool just hit 1.0

---

**Body:**

If you've ever had to manage boxes behind NAT, in the field, or on a network where opening an inbound management port is a non-starter, you know the usual options aren't great — VPN mesh everywhere, a jump host with an exposed port, or an agent that phones home to someone else's cloud.

I've been building an open-source tool to scratch this itch, and it just reached v1.0.0, so I wanted to share it here. (Disclosure: I'm the author.)

**The core idea:** the agent on each target only makes **outbound** SSH connections to a central gateway. The targets never listen for management traffic — there's literally nothing inbound to firewall or port-scan. You (the operator) talk to the gateway via CLI, REST, or MCP, never to the agents directly.

That one decision made the rest of the security model much easier to reason about, so 1.0 leans into it:

- **Tamper-evident audit log** — every action is signed and hash-chained (Ed25519), so deleting or editing an entry is detectable. There's a `myrmex audit verify/export/watch` toolchain.
- **Fine-grained access control** — tokens scoped per-agent/tag/tool, command risk tiers, optional human approval for risky actions, rate limiting.
- **Shell-free execution** — agents run a typed tool library (service/container/k8s/package/file) behind a regex allowlist, executed directly, never through a shell. No shell-injection surface.
- **Optional local LLM** — you can ask it things in natural language via Ollama/OpenAI/vLLM/llama.cpp. It works **fully airgapped** with a local model, and the tool-calling loop is bounded + hardened against prompt injection. Totally optional — the whole thing runs fine without it.
- **Fleet telemetry** — heartbeat, metrics history, inventory, threshold alerts, and a dashboard.
- **Lifecycle stuff** — join-token enrollment, key rotation, revocation, mTLS, OIDC-via-proxy, and a one-command `myrmex bootstrap`.

It's Go 1.25, ships Cosign-signed cross-platform binaries with SBOMs (linux/macos/windows, amd64/arm64).

Install: `go install github.com/olafkfreund/myrmex-hive/cmd/myrmex@v1.0.0`, or grab a release archive / use `install.sh`.

Repo + release: https://github.com/olafkfreund/myrmex-hive/releases/tag/v1.0.0

Happy to answer questions about the architecture or the threat model. I'd genuinely like to hear where this breaks for your setup, or what would make it actually usable for you.
