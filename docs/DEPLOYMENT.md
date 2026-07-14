# Deployment: container images and Helm chart

Myrmex Hive publishes versioned container images and a versioned Helm chart to
GHCR on every release tag. This document covers installing from those published
artifacts.

For the security model behind the topology below (agents dial *out*; the
gateway is the only thing that listens), see the [README](../README.md).

## Container images

Three multi-arch (`linux/amd64` + `linux/arm64`) images are published per release:

| Image | Contents |
|---|---|
| `ghcr.io/olafkfreund/myrmex-gateway` | Central hub: SSH receiver (2222), MCP/REST API + web portal (8080) |
| `ghcr.io/olafkfreund/myrmex-agent` | Per-node agent; dials out to the gateway |
| `ghcr.io/olafkfreund/myrmex` | Operator CLI |

Each is tagged with the release version and `latest`:

```bash
docker pull ghcr.io/olafkfreund/myrmex-gateway:1.0.0
docker pull ghcr.io/olafkfreund/myrmex-agent:1.0.0
```

Pin the version tag in production. `latest` moves on every release.

Per-arch tags (`:1.0.0-amd64`, `:1.0.0-arm64`) are published as the backing
manifests. Pull the plain version tag — Docker resolves the right architecture.

### Verifying release artifacts

The release checksums are signed with [cosign](https://github.com/sigstore/cosign)
keyless signing, and SBOMs are published for the binary archives:

```bash
cosign verify-blob \
  --certificate checksums.txt.pem \
  --signature checksums.txt.sig \
  --certificate-identity-regexp 'https://github.com/olafkfreund/myrmex-hive.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt
```

> The **container images are not signed yet** — only the release checksums are.
> Verify images by digest until image signing lands.

## Helm chart

The chart is published as an OCI artifact. There is no chart repo to add:

```bash
helm install hive oci://ghcr.io/olafkfreund/charts/myrmex-hive \
  --version 1.0.0 \
  --namespace myrmex --create-namespace
```

`--version` pins the chart **and** the images: the chart's `appVersion` tracks
the release tag, and the image tags default to `appVersion`. One version knob
moves both. Override per-image with `image.tag`, `gateway.image.tag`, or
`agent.image.tag` if you need to mix.

Inspect before installing:

```bash
helm show values oci://ghcr.io/olafkfreund/charts/myrmex-hive --version 1.0.0
helm template hive oci://ghcr.io/olafkfreund/charts/myrmex-hive --version 1.0.0
```

### What it deploys

- **Gateway** — Deployment + Service exposing `2222` (agent tunnel) and `8080`
  (MCP/REST/portal). Disable with `gateway.enabled=false`.
- **Agent** — DaemonSet, one pod per node. Defaults to
  `hostNetwork`/`hostPID`/`privileged` so `get_metrics` and `get_system_info`
  see real host state. Set those false for a sandboxed, less capable agent.
  Disable with `agent.enabled=false`.

### A real install

The default values start, but the agent cannot authenticate until the gateway
trusts its key. Generate a keypair, then pass both sides:

```bash
ssh-keygen -t ed25519 -N '' -f ./agent_key

helm install hive oci://ghcr.io/olafkfreund/charts/myrmex-hive \
  --version 1.0.0 \
  --namespace myrmex --create-namespace \
  --set-file gateway.authorizedKeys=./agent_key.pub \
  --set-file agent.privateKey=./agent_key
```

`--set-file` for keys is dev/test convenience — it puts the private key in Helm
release values. For anything real, create the Secrets out of band and point the
chart at them with `gateway.existingSecret` / `agent.existingSecret`, which is
also the GitOps/sealed-secrets path. See [SECRETS.md](SECRETS.md).

### Things that will bite you

- **The gateway serves 8080 over HTTPS only**, with a self-signed certificate
  regenerated in-memory on every restart. That is why the probes default to
  `scheme: HTTPS`. Set `gateway.tls.enabled=true` with a `kubernetes.io/tls`
  Secret to pin a real certificate.
- **The Service is `ClusterIP`.** Agents dialing in from outside the cluster
  need port 2222 reachable — set `gateway.service.type=LoadBalancer` (or
  NodePort, or a TCP-mode Ingress) for those.
- **Every DaemonSet pod shares one `agent_id`.** The gateway's registry is keyed
  by `agent_id`, so identical IDs across nodes collide. For distinct per-node
  identities, render one Secret per node group and use `agent.existingSecret`.
- **GHCR packages must be public** for anonymous pulls. If they are private, set
  `imagePullSecrets` and run `helm registry login ghcr.io` before installing.

### Upgrading

```bash
helm upgrade hive oci://ghcr.io/olafkfreund/charts/myrmex-hive --version 1.1.0
```

Rolling the gateway drops agent tunnels; agents reconnect on their own. Give
them more than one gateway via `gateway_addrs` for HA failover.

## Raw manifests

`k8s/` holds unversioned example manifests. They are kept for reference and for
people who want to read the YAML directly — the chart is the supported install
path.
