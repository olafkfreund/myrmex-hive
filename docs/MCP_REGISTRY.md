# Publishing to the public MCP registry

`server.json` at the repo root is the manifest the [official MCP
registry](https://registry.modelcontextprotocol.io) consumes. This documents how
it is kept valid and how to publish it.

## What the manifest says

| Field | Value |
|---|---|
| `name` | `io.github.olafkfreund/myrmex-hive` |
| `packages[0].identifier` | `ghcr.io/olafkfreund/myrmex-gateway:<version>` |
| `packages[0].transport` | `stdio` — the gateway speaks MCP over stdin/stdout (`startStdioMCPServer`) |

The gateway is the MCP server; agents are reached *through* it as namespaced
tools (`<agentID>__<tool>`). There is deliberately **no `remotes` entry**: a
Myrmex gateway is self-hosted, so there is no public URL to advertise.

## Three rules that will reject a publish

Both are enforced by the registry, and both have bitten this repo:

**1. The image must carry an ownership label.** The registry pulls the image
named in `packages[0].identifier` and requires:

```
io.modelcontextprotocol.server.name = io.github.olafkfreund/myrmex-hive
```

matching `name` in `server.json` exactly. It is applied in `.goreleaser.yaml`
on the `gateway-amd64`/`gateway-arm64` builds. **The label must be on the
*published* image**, so bumping `server.json` to a version that has not been
released yet will fail verification.

**2. `identifier` must include the tag.** The documented format is
`registry/namespace/repository:tag` — `ghcr.io/olafkfreund/myrmex-gateway:1.1.0`,
not the bare repository.

**3. An OCI package must NOT have a `version` field.** The tag in `identifier`
*is* the version:

```json
"packages": [{
  "registryType": "oci",
  "identifier": "ghcr.io/olafkfreund/myrmex-gateway:1.1.0"
}]
```

This one is not in the JSON Schema — the schema accepts `packages[].version`
and the registry rejects it:

```
400: OCI packages must not have 'version' field —
     include version in 'identifier' instead
```

**Schema-valid is not the same as publishable.** The registry runs server-side
rules the schema does not express, so a clean `check-jsonschema` proves less
than it looks. CI now checks this specific rule too, but expect the live API to
be the final word.

Because of rule 1, publishing is always *after* the release that carries the
label, never before.

## Publishing

`mcp-publisher` authenticates interactively; there is no unattended path for
`io.github.*` names short of GitHub Actions OIDC.

```bash
# 1. Install (see https://github.com/modelcontextprotocol/registry/releases)
VERSION=v1.8.0
curl -sL "https://github.com/modelcontextprotocol/registry/releases/download/${VERSION}/mcp-publisher_$(uname -s | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/').tar.gz" \
  | tar xz mcp-publisher

# 2. Authenticate. The io.github.olafkfreund/* namespace is owned by the
#    GitHub account of the same name, so GitHub login proves ownership.
#    Opens a device-code flow in your browser.
./mcp-publisher login github

# 3. Publish (validates server.json, then verifies the image label)
./mcp-publisher publish
```

Verify it landed:

```bash
curl -s 'https://registry.modelcontextprotocol.io/v0/servers?search=myrmex' | jq .
```

## Keeping it valid

CI validates `server.json` against **the schema the file itself declares**, and
fails if that `$schema` URL is unreachable. That second check is not
theoretical: the manifest previously pointed at a
`2025-06-18` schema that now 404s, and had never been valid against any live
schema (it used snake_case keys, an over-long description, and an image name
that was never published).

Run the same check locally:

```bash
SCHEMA=$(jq -r '."$schema"' server.json)
check-jsonschema --schemafile "$SCHEMA" server.json
```

When the registry publishes a new schema version, bump `$schema` and fix
whatever the validator then complains about — the CI step is what tells you.

## Releasing a new version

1. Bump `version` and `packages[0].identifier`/`packages[0].version` in
   `server.json` to the version you are about to tag.
2. Tag and let the release publish the labeled image (see
   [DEPLOYMENT.md](DEPLOYMENT.md)).
3. Run `mcp-publisher publish` once the image is live.
