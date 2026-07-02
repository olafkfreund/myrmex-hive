# LinkedIn Launch Post — Myrmex Hive v1.0.0

What if managing your entire edge fleet required **zero inbound ports** on any target?

That's the whole idea behind Myrmex Hive — and today it hits **v1.0.0**.

Agents dial *out* to a central gateway over SSH. The targets never listen for management traffic. There's nothing inbound to firewall, port-scan, or exploit. Operators reach the gateway — never the agents directly.

What started as a security review turned into a hardened, feature-complete 1.0:

🔒 Signed + hash-chained (Ed25519) audit log — tampering is detectable, not just discouraged
🛡️ Fine-grained RBAC — per-agent/tag/tool token scoping, risk tiers, human-in-the-loop approvals
📊 Fleet telemetry + a Fleet & Approvals dashboard
🤖 Optional LLM orchestration (Ollama / OpenAI / vLLM / llama.cpp) that runs **fully airgapped** — and treats its own prompts as hostile
⚙️ A shell-free regex allowlist as the execution safety boundary
🔑 Agent lifecycle: enrollment, revocation, key rotation, mTLS, OIDC — plus one-command `myrmex bootstrap`

Cosign-signed cross-platform binaries with SBOMs. Built in Go 1.25.

Built for the environments where this matters most: regulated (healthcare, finance, defense), airgapped/OT, and distributed edge fleets.

It's open source. Try it, break it, tell me what's missing:
👉 https://github.com/olafkfreund/myrmex-hive/releases/tag/v1.0.0

#OpenSource #DevOps #Cybersecurity #EdgeComputing #Golang #MCP #Airgapped
