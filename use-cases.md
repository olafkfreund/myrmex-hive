---
layout: default
title: Use Cases
permalink: /use-cases/
---

## What Myrmex Hive is actually for

One property drives every use case below: **the machines you manage never listen
for management traffic.** Agents dial *out* to the Gateway; operators talk only
to the Gateway. There is no port to scan, no management daemon to exploit, no
inbound firewall rule to argue about.

Everything an agent can do is the exact union of the commands you allowlist —
nothing wider. That is what makes it safe to point at production.

---

### 1. Test, debug and chaos-test a service you just built

**The problem.** You have a new service on a real host. You want to run it,
break it deliberately, watch what happens, restart it, change a setting, and go
round again — without SSHing in and without handing a script a shell.

**How it works.** Fault injection, probes and config variants are allowlist
entries, not features. You get a fixed verb set (`cpu`, `mem`, `latency`,
`loss`, `kill`) and a recovery path, and nothing else.

```bash
# Probe → break → observe → recover, every step through the Gateway
myrmex call web-1__run_command --arguments '{"name":"curl","args":["-s","--max-time","3","http://127.0.0.1:8080/healthz"]}'
myrmex call web-1__run_command --arguments '{"name":"/opt/myrmex/chaos.sh","args":["latency","60","250","eth0"]}'
myrmex call web-1__read_logs   --arguments '{"path":"/var/log/myservice.log","lines":50}'
myrmex call web-1__service_control --arguments '{"action":"restart","service":"myservice"}'
```

**The guard rails.** Every fault is time-bounded and self-reverting, and the
teardown is detached so it survives even the agent being killed — a `netem`
rule that outlives your test is an outage, not an experiment. Every injection
lands in a signed audit log, so you get a tamper-evident record of which fault
hit which host and when.

→ **[Service testing & chaos]({{ '/docs/SERVICE_TESTING.html' | relative_url }})**

---

### 2. Fleet health and incident triage in one question

**The problem.** Something is wrong somewhere across fifty machines and you do
not yet know where. The traditional answer is a dashboard you have to
interpret, or fifty SSH sessions.

**How it works.** Ask in English. A local model picks an allowlisted command
per agent, runs it over the tunnel, and aggregates the answers.

```bash
myrmex ask --all "Report disk usage and flag anything over 85%"
myrmex ask --agents agent-1,agent-2 "How busy are these two?"
```

**The guard rails.** The model cannot invent capability: it may only select
tools the agent advertises, and each selection still passes the allowlist. Not
sure what it will do? Ask it to show you first:

```bash
myrmex ask --plan "Restart nginx on agent-nginx if it looks wedged"
```

`--plan` consults the model at every step and executes nothing, listing the
calls it *would* have made.

---

### 3. Operations you have to prove afterwards

**The problem.** Regulated environments do not just need the right thing done;
they need evidence of what was done, by whom, and that the record has not been
edited since.

**How it works.** Every action is written to a hash-chained log signed with the
Gateway's SSH host key. Anyone can verify it with the public key alone:

```bash
myrmex audit verify --log audit.log --host-key gateway_host_key.pub
# Total entries: 812, Valid: 812, Signature failures: 0, Chain breaks: 0
```

**What makes it useful rather than decorative.** The log distinguishes
`success`, `denied` (the allowlist refused it — nothing ran) and `failure` (an
approved command ran and went wrong). Those are opposite facts in an incident
review, and a run of `denied` entries is exactly the signal that someone is
probing the boundary. Deleting an entry breaks the chain, which is how deletion
is detected at all.

→ **[Compliance & audit]({{ '/docs/COMPLIANCE.html' | relative_url }})**

---

### 4. Edge estates: retail, industrial, branch offices

**The problem.** Hundreds of boxes behind NAT, on other people's networks, on
connections you do not control. You cannot open inbound ports on any of them,
and you should not want to.

**How it works.** Each agent makes one outbound SSH connection to the Gateway
and serves MCP over it. Nothing listens on the target. Agents can be given
several gateway addresses and will cycle through them on failure.

**Why it fits.** The usual remote-management answer — an SSH daemon per site,
or a VPN back to head office — puts a listening service on every box and a
credential on every jump path. Here the target's only exposure is an outbound
connection it initiates, to one host, authenticated with a key whose identity
the Gateway binds to the agent ID.

---

### 5. Kubernetes and container hosts

**The problem.** You want node-level truth — disk pressure, kubelet state, what
containers are actually running — not just what the control plane believes.

**How it works.** Deploy the agent as a DaemonSet. Typed tools cover the common
questions without handing anyone a shell:

```bash
myrmex call node-7__container_ps --arguments '{}'
myrmex call node-7__k8s_get      --arguments '{"resource":"pods"}'
myrmex call node-7__package_query --arguments '{"manager":"apk","query":"openssl"}'
```

Each still routes through the allowlist — `k8s_get` shells out to an
allowlisted `kubectl`, so a typed tool is never a bypass.

→ **[Deployment]({{ '/docs/DEPLOYMENT.html' | relative_url }})**

---

### 6. Airgapped and sovereignty-constrained environments

**The problem.** You want the convenience of an LLM assistant over your
infrastructure, and you are not permitted to send infrastructure telemetry to
a third-party API.

**How it works.** The orchestrator talks to a local Ollama. Model, prompts, tool
output and results stay inside your perimeter:

```bash
docker compose --profile ollama-cpu up -d   # preloaded Gemma 4
```

No cloud dependency at any point in the loop. If you *do* want a hosted model,
that is an explicit opt-in, not the default.

---

### 7. Managed service providers

**The problem.** One control plane, many customers, and a hard requirement that
an operator scoped to customer A cannot touch customer B.

**How it works.** Tag agents, then scope tokens to tags. A scoped token cannot
call an agent outside its scope, and cannot use tools outside its list. Layer
on SSO where you need it: OIDC/JWKS validation with group→role mapping is
native, and unmapped groups are denied rather than defaulted.

**Honest limit.** `GET /api/fleet` lists every agent to any authorised caller —
names and OS only, never a way to *act* on them. If you have mutually hostile
tenants, that listing is the one thing to scope-filter first.

---

### 8. Scheduled watchdogs that only speak up when something changes

**The problem.** Nobody reads a dashboard at 3am, and a cron job that emails on
every run trains you to ignore it.

**How it works.** A scheduled task re-runs an orchestration on an interval and
routes the summary through the same alert path as threshold alerts — webhook or
Alertmanager. You get a soak test that pages you when the answer changes, not
when the clock ticks.

→ **[Observability]({{ '/docs/OBSERVABILITY.html' | relative_url }})**

---

## What it is deliberately not

Being clear about this saves you an evaluation:

- **Not a general remote shell.** There is no "run anything". You grow
  capability one reviewed allowlist entry at a time — that constraint is the
  product, not a limitation of it.
- **Not an arbitrary file editor.** There is no `file_write`. To change a file
  you allowlist a script that owns *what* may change; the agent gets a menu,
  not a filesystem.
- **Not a jump host or TCP proxy.** An agent can *probe* other services from
  its vantage point, but it will not forward arbitrary connections into your
  network.
- **Not a metrics platform.** It exposes Prometheus metrics and ships a Grafana
  dashboard; it does not try to replace either.

---

## Start here

New to it? The **[Golden Path]({{ '/golden-path/' | relative_url }})** walks
through what agents can and cannot do to your hosts, and the fastest safe route
from "installed" to "this is saving me work".
