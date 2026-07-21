---
layout: default
title: Service testing & chaos
---

# Using Myrmex Hive as a service test harness

You built a service. You want to run it, break it on purpose, watch what it
does, restart it, change something, and go round again — on a real host, not
your laptop. This page shows how to do that with the agent you already have,
**without writing any Go**.

The short version: the agent's power is exactly the set of commands you
allowlist. A test harness is therefore a *profile* — a handful of allowlist
entries — not a feature. Everything below is config.

Companion pages: [the Golden Path](GOLDEN_PATH.md) for the capability and
safety model, [Compliance & audit](COMPLIANCE.md) for the signed log.

---

## 1. What you get today

| Testing activity | How |
|---|---|
| Start / stop / restart the service under test | `service_control`, or an allowlisted `systemctl` |
| Read its logs while it misbehaves | `read_logs`, `journalctl` (allowlisted) |
| Inspect config, metrics, containers, packages | `file_read`, `get_metrics`, `container_ps`, `package_query` |
| **Inject faults** (CPU, memory, latency, loss, kill) | allowlisted `chaos.sh` — shipped in this repo |
| **Probe other services from the host** | allowlisted `curl` / `nc` / `dig`, pinned to hosts you name |
| **Apply a config variant between runs** | allowlisted apply script |
| Repeat on a schedule and get told what broke | `scheduled_tasks` + `ask_gemma` |
| Signed record of every fault injected | the audit log, automatically |

Two things you **cannot** do — see [section 6](#6-the-two-real-limits):
arbitrary file writes, and using the agent as a general TCP proxy.

---

## 2. The profile

Copy the `allowed_commands` entries from
[`examples/service-test-harness/agent_config.harness.json`](https://github.com/olafkfreund/myrmex-hive/blob/main/examples/service-test-harness/agent_config.harness.json)
into your agent's config and edit them to name *your* service, *your* hosts,
*your* interfaces.

Three rules, each of which has bitten someone:

1. **One entry per command name.** The allowlist matches the first entry whose
   name matches and stops — a second `curl` entry is dead config. Add variants
   as regex alternations inside the one entry.
2. **Pin your hosts.** `curl` with a permissive host pattern turns the agent
   into a request forwarder for anyone who can reach the Gateway.
3. **Absolute paths for scripts.** `/opt/myrmex/chaos.sh`, not `chaos.sh`.
   Relative names resolve through `PATH`, which an attacker may influence.

The shipped profile is regression-tested against the real validator
(`pkg/command/harness_profile_test.go`) — both that the documented workflow is
permitted and that fourteen dangerous variations are refused.

---

## 3. Fault injection

[`examples/service-test-harness/chaos.sh`](https://github.com/olafkfreund/myrmex-hive/blob/main/examples/service-test-harness/chaos.sh)
is one script with a fixed verb set:

| Action | Effect |
|---|---|
| `cpu <duration> <workers>` | burn N cores |
| `mem <duration> <mb>` | hold N MB resident |
| `latency <duration> <ms> <if>` | add egress latency (`tc netem`) |
| `loss <duration> <pct> <if>` | drop egress packets |
| `kill <signal> <pidfile>` | signal the service (TERM/KILL/HUP/USR1/USR2) |
| `status` | report active chaos |

It is one script rather than raw `tc`/`kill` entries for two reasons: an
`args_regex` tight enough to make raw `tc` safe is harder to review than a
fixed verb set, and chaos needs *cleanup* — a `netem` rule outlives the
command that added it.

**Every timed action self-reverts, and durations are capped at 300s.** A fault
that outlives the test is an outage, not an experiment.

**Timed actions return immediately and revert in the background.** That is
load-bearing, for three reasons:

1. The agent kills any command at 30s, and it kills with **SIGKILL** — which
   runs no shell EXIT traps. A fault that blocked for 60s would be killed
   mid-sleep with its `netem` rule still installed, *permanently*. So the
   teardown is scheduled in an independent session (`setsid`) before the fault
   is applied, and survives even the agent dying.
2. Tool output is buffered until the command exits, so a blocking fault means
   you can observe nothing *while* it is happening — the entire point of
   injecting it.
3. It is why a 300s fault works despite a 30s command timeout.

So `chaos.sh latency 60 250 eth0` returns at once with
`auto-reverts in 60s`, and you spend those 60 seconds probing.

---

## 4. The loop, end to end

This is a real transcript against a live Gateway and agent — a service on
:8099, killed and recovered through the tunnel.

`run_command` takes `{"name": ..., "args": [...]}` — the command and its argv
split, never a single string, because nothing goes through a shell.

```bash
export MYRMEX_TOKEN=<your-token>

# Baseline
myrmex call test-target-1__run_command \
  --arguments '{"name":"curl","args":["-s","--max-time","3","http://127.0.0.1:8099/healthz"]}'
# → {"status":"ok","load1":7.31}

# Inject: kill the service
myrmex call test-target-1__run_command \
  --arguments '{"name":"/opt/myrmex/chaos.sh","args":["kill","TERM","/run/myservice.pid"]}'
# → kill: sent SIGTERM to pid 2268289

# Observe the outage
# probe  → Command failed: exit status 7   (connection refused)
# status → inactive (dead)

# Recover
myrmex call test-target-1__run_command \
  --arguments '{"name":"/opt/myrmex/service.sh","args":["restart"]}'
# → started pid=2273234

# Verify
# probe → {"status":"ok","load1":7.31}
```

Change a variant between iterations with the apply script, then repeat:

```bash
myrmex call test-target-1__run_command \
  --arguments '{"name":"/opt/myrmex/apply-config.sh","args":["high-timeout"]}'
```

### Make it run itself

`scheduled_tasks` re-runs an `ask_gemma` orchestration on an interval and
routes the summary through the same alert path as threshold alerts — a soak
test that pages you only when the answer changes. See
[Observability](OBSERVABILITY.md).

---

## 5. What the boundary refuses

Live, against the profile above:

```text
kill TERM /run/sshd.pid       → arguments do not match the approved pattern
curl http://evil.example.com/ → arguments do not match the approved pattern
bash -c whoami                → command "bash" is not in the approved allowlist
chaos.sh cpu 99999 64         → arguments do not match the approved pattern
```

Nothing runs through a shell, so `status; rm -rf /` is one argument that fails
its regex, not two commands.

Every call — permitted or refused — lands in the signed audit log, so a chaos
run leaves a tamper-evident record of which fault hit which host when:

```text
Total entries: 15, Valid: 15, Signature failures: 0, Chain breaks: 0
Result: AUDIT LOG VERIFICATION PASSED
```

---

## 6. The two real limits

**No arbitrary file writes.** There is no `file_write` tool, deliberately —
`file_read` is read-only and every mutation goes through a reviewed allowlist
entry. To change files between iterations, allowlist a script that owns *what*
may change and let the regex pick *which* variant. You hand the agent a menu,
not a filesystem.

**No general TCP proxy.** The agent can *probe* other services (`curl`, `nc`,
`dig` — that covers most "use the host as a vantage point" needs), but it
cannot forward arbitrary connections. If you need a jump host, use one; this
agent is deliberately not one.

## 7. Two sharp edges

- **Commands are killed at 30 seconds, with SIGKILL** (`pkg/command`). Fine for
  restarts, probes and short faults. Anything that must outlive 30s has to
  detach — as `chaos.sh` does — because SIGKILL runs no cleanup. **Never
  allowlist a long-running command that cleans up after itself in a trap or a
  `defer`: it will be killed before it can.**
- **Output is buffered, not streamed.** You get it when the command exits, so
  there is no live tail *during* a run. Poll `read_logs` between iterations,
  and prefer faults that return immediately so you can observe while they act.

A long soak is therefore a `scheduled_tasks` poke loop, not one long command.

---

## 8. Lessons from running this against a real service

Everything here was found by pointing the harness at the nginx container in
`docker-compose.test.yml`, not by reasoning about it. Expect to hit these.

**Verify recovery BEFORE you inject anything.** Restart the service through the
harness first. If the restart path does not work, you have no business breaking
it — you will have killed something you cannot bring back. This is not
hypothetical: `service_control` shells out to `systemctl`, and a container has
no systemd, so on a container target the documented recovery path silently does
nothing while `kill` works perfectly.

**Allowlist a start path, not just reload.** `nginx -s reload` needs a running
master; once the process is dead it cannot help. The recovery entry must be
able to *start* a stopped service. Remember the allowlist stops at the first
entry matching a command name, so fold start and reload into one entry:

```json
{ "name": "nginx", "args_regex": "(-s (reload|quit))?" }
```

(The empty alternative permits bare `nginx`, i.e. start.)

**Probe `127.0.0.1`, not `localhost`.** `localhost` resolves to `::1` first,
and a service listening only on IPv4 refuses the connection — so a perfectly
healthy service reports `Connection refused`. That is a *false outage*, and in
a chaos run you will blame your own fault injection for it.

**Minimal images do not have your tools.** Alpine — the most common container
base — ships no `curl` and no `dig`. It does have busybox `wget` and `nc`:

```json
{ "name": "wget", "args_regex": "-q -O - -T \\d{1,2} http://127\\.0\\.0\\.1(:\\d{1,5})?/[a-zA-Z0-9/_.-]*" }
```

Check what actually exists on the target before writing the profile; an
allowlist entry for a missing binary fails as `failure`, not `denied`, which
at least tells you the two apart.

**`chaos.sh` has to get onto the target.** It is a file, not a protocol — ship
it with your config management, bake it into the image, or mount it
(`- ./chaos.sh:/app/chaos.sh:ro`). The allowlist references an absolute path;
putting the file there is your job.

---

## 9. Before you point this at production

- Give the harness token its own scope (`scoped_tokens`) limited to the test
  agents — chaos capability should not ride on your day-to-day operator token.
- Put the chaos tool in an approval-gated risk tier
  (`require_approval_tiers`) so injecting a fault needs a second pair of eyes.
- Rehearse on a staging host. The allowlist stops the agent doing what you did
  not authorise; it cannot stop you authorising something you will regret.
