---
layout: post
title: "Chaos-test your own service — and what running it actually taught us"
date: 2026-07-21
---

Myrmex Hive can now be used as a **service test harness**: run your service on a
real host, break it deliberately, watch what happens, restart it, change a
setting, and go round again — without SSHing in and without handing anything a
shell.

The interesting part is not the feature. It is that **building it required no
agent code at all**, and that pointing it at a real service immediately found
seven bugs we had not found by reading the code.

---

## A capability is an allowlist profile, not a feature

An agent's power is exactly the union of the commands you allowlist. So a test
harness is a *profile* — a handful of reviewed entries — not a new subsystem:

- **`chaos.sh`** — fault injection with a fixed verb set: `cpu`, `mem`,
  `latency`, `loss`, `kill`, `status`.
- **probes** — `curl`/`wget`/`nc`/`dig` pinned to hosts you name. This covers
  the "use the host as a vantage point" need without any proxy.
- **`apply-config.sh`** — change config between iterations. There is no
  `file_write` tool by design, so the script owns *what* may change and the
  allowlist regex picks *which* named variant. The agent gets a menu, not a
  filesystem.

Everything ships in
[`examples/service-test-harness/`](https://github.com/olafkfreund/myrmex-hive/tree/main/examples/service-test-harness),
and the profile is regression-tested against the real allowlist validator —
fourteen dangerous variations must stay refused. It is a security boundary we
invite people to copy, so an over-permissive regex in it would be a
vulnerability with our name on it.

The loop, end to end:

```
healthy      → {"status":"ok"}
chaos kill   → sent SIGTERM to pid 2268289
probe        → exit status 7 (connection refused)
restart      → started pid=2273234
healthy      → {"status":"ok"}
```

Every step through the Gateway, every step in the signed audit log.

---

## What running it taught us

We could have shipped the harness on the strength of its unit tests. Instead we
pointed it at a real nginx container. Seven bugs, none of which were visible
from reading the code.

**A fault could outlive the test.** Timed chaos actions blocked for their
duration, and the agent kills any command at 30 seconds with **SIGKILL** —
which runs no shell EXIT traps. So `latency 60 250 eth0` was killed mid-sleep
with its `netem` rule still installed, *permanently*. Exactly the outage the
trap was written to prevent. Faults now detach: the teardown is scheduled in an
independent session before the fault is applied, and survives even the agent
dying.

**The audit log called denials "success".** A refused call comes back as a
well-formed JSON-RPC *result*, not an *error*, so the Gateway logged
`status: success, Tool execution completed` for calls that never ran. In an
incident review, "an operator ran this" and "the allowlist stopped them" are
opposite facts — and a run of denials is precisely the signal that someone is
probing the boundary. There are now three statuses: `success`, `denied`
(nothing ran) and `failure` (it ran and went wrong).

**The example could not run on Alpine.** `chaos.sh` needed bash; Alpine ships
busybox `ash`. The example was unusable on the most common container base
there is. It is POSIX `sh` now.

**You could kill a service you could not restart.** `service_control` shells
out to `systemctl`, and containers have no systemd — so `kill` worked and
recovery silently did nothing. The docs now lead with: *verify the restart path
before injecting anything.*

**Probing `localhost` reported false outages.** `localhost` resolves to `::1`
first, so an IPv4-only service answers `Connection refused` while being
perfectly healthy — and in a chaos run you would blame your own fault
injection. Pin `127.0.0.1`.

**The container images did not build.** Four Dockerfiles ran
`go build -o gateway cmd/gateway/main.go` — a *file*, not the package — so only
`main.go` compiled and the other seven files in `cmd/gateway` were silently
ignored. It rotted for weeks because nothing builds those files: not CI, and
not local runs, which reuse cached images.

**The integration suite was failing.** It slept a flat six seconds for agent
registration; `agent-db` takes fourteen. It reported a fleet-wide registration
failure that did not exist.

---

## The lesson we are keeping

Every one of those came from *running* the thing, not from reading it. The unit
tests were green throughout. The one that stings most is the SIGKILL bug: we had
written a confident paragraph of documentation explaining why the cleanup was
safe, and the cleanup did not run.

Guards were added for each — including a static check across all Dockerfiles, so
that particular bug cannot come back quietly.

→ **[Service testing & chaos]({{ '/docs/SERVICE_TESTING.html' | relative_url }})**
&nbsp;·&nbsp; **[Use cases]({{ '/use-cases/' | relative_url }})**
