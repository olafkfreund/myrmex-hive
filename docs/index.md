# Myrmex Hive

Zero-inbound-port MCP gateway for managing distributed edge servers.

Agents dial **out** to a central Gateway over SSH; operators reach the Gateway
(never the agents) via CLI, MCP, or REST. Target machines never listen for
management traffic, which removes the usual attack surface: no exposed SSH
daemon, no management port for scanners to find.

!!! note "This page intentionally links rather than repeats"

    The [README](https://github.com/olafkfreund/myrmex-hive#readme) is the
    single source for the architecture overview, quickstart and configuration
    reference. Duplicating it here would guarantee drift — an earlier attempt
    at these docs shipped a README copy that was stale within weeks.

## Where to go

| If you want to… | Read |
|---|---|
| **Understand what agents can do & get value fast** | **[Golden Path](GOLDEN_PATH.md)** |
| Deploy with Helm or containers | [Deployment](DEPLOYMENT.md) |
| Scrape metrics, route alerts, or trace calls | [Observability](OBSERVABILITY.md) |
| Keep tokens out of config files | [Secrets](SECRETS.md) |
| Enroll agents and rotate/revoke their keys | [Agent enrollment](ENROLLMENT.md) |
| Verify the signed audit log | [Compliance & audit](COMPLIANCE.md) |
| Publish to the public MCP registry | [MCP registry](MCP_REGISTRY.md) |

## Install

```bash
# macOS
brew tap olafkfreund/myrmex && brew install --cask myrmex-hive

# Kubernetes — --version pins the chart AND the images together
helm install hive oci://ghcr.io/olafkfreund/charts/myrmex-hive --version 1.1.0

# Containers (signed from v1.0.3 onward)
docker pull ghcr.io/olafkfreund/myrmex-gateway:1.1.0
```

Full options — Nix flake, `install.sh`, Windows, deb/rpm — are in the
[README](https://github.com/olafkfreund/myrmex-hive#2-quickstart--installation)
and [Deployment](DEPLOYMENT.md).

## The three binaries

| Binary | Role |
|---|---|
| `myrmex-gateway` | Central hub: SSH receiver (2222), MCP/REST API + web portal (8080) |
| `myrmex-agent` | Runs on each target; dials out, rejects all inbound channels |
| `myrmex` | Operator CLI; talks only to the Gateway's REST API |

Both `myrmex-gateway` and `myrmex-agent` **fail closed** — neither starts
without a config file and Ed25519 keys. That is deliberate; see
[Fail-closed defaults](https://github.com/olafkfreund/myrmex-hive#fail-closed-defaults).
