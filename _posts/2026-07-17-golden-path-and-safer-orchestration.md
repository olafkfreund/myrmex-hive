---
layout: post
title: "The Golden Path: safer, broader LLM orchestration"
date: 2026-07-17 10:00:00 +0100
author: olafkfreund
---

Myrmex Hive's security model and distribution were solid. What was thin was the
part operators actually touch every day: *how do I get value out of this without
being afraid of it?* This release is about that — a documented golden path, plus
seven improvements that make the LLM orchestration loop safer to trust and
broader in reach.

### Start here: the Golden Path

The most common question from new operators is blunt: **can the agents change my
hosts, or only look?** The honest answer — agents *can* start, stop, and restart
services and run allowlisted commands, but there is **no arbitrary file write**,
and every mutation clears six independent gates (RBAC → risk tier → approval →
rate limit → allowlist → signed audit), each failing closed.

The new [Golden Path guide]({{ '/golden-path/' | relative_url }})
lays this out as a capability model and a staged rollout: enroll an agent, get
value from read-only tools first, grant one controlled mutation behind approval,
then let the LLM drive remediation. Capability is something you grant on purpose,
never a default.

### Preview before you act: `ask --plan`

Trust is easier to give when you can see what will happen first. `ask --plan`
runs the full orchestration loop — the model is consulted at every step — but
executes nothing. The response lists the tool calls it *would* have made:

```bash
myrmex ask --plan "Restart nginx on agent-nginx if it looks wedged"
```

Happy with the plan? Drop the flag to let it act. It works fleet-wide too.

### One prompt, the whole fleet

Orchestration used to target a single agent. Now it can fan out across many and
aggregate the summaries — "how's the whole fleet doing?" in one call:

```bash
myrmex call gateway__ask_gemma \
  --arguments '{"prompt":"Report disk usage and flag anything over 85%","all_agents":true}'
```

Each agent still gets the exact same bounded, gated orchestration; fleet mode is
just the single-agent loop in a loop.

### Let it run itself: scheduled tasks

Opt-in `scheduled_tasks` run an orchestration prompt on a timer and route the
summary through your existing alert targets — unattended health checks that work
between shifts:

```json
"scheduled_tasks": [
  { "name": "nightly-disk-check", "agent_id": "agent-nginx",
    "prompt": "Report disk usage and flag anything over 85%", "interval_seconds": 3600 }
]
```

### Safer by default, and harder to ignore

- **Risk tiers fail closed.** Built-in mutating tools (`service_control`,
  `run_command`) now default to a non-`read` tier even if you never classified
  them — so a dangerous tool can't slip past approval gating just because a list
  wasn't updated. A guard test enforces that every built-in tool is classified.
- **Approvals page you.** A new pending approval now notifies your configured
  alert targets, so a legitimate mutation can't quietly expire because nobody was
  watching the portal.
- **Metrics carry a trend.** `get_metrics` now surfaces recent history when the
  Gateway is polling, so the model judges health on a trend rather than a single
  instantaneous sample.
- **A quality gate for the model itself.** An opt-in nightly eval drives the real
  orchestration loop against a live model and grades its output — format,
  hallucination, convergence, and prompt-injection resistance — so a model swap
  that makes the assistant "dumber" gets caught automatically.

All of it is opt-in and backward-compatible: an existing config keeps behaving
exactly as before. See the [Golden Path guide]({{ '/golden-path/' | relative_url }})
to put it together.
