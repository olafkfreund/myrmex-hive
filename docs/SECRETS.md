# Secret Management

Myrmex Hive never requires secrets to be written inline in `gateway_config.json`.
Any secret-bearing field can instead hold an **indirection reference** that the
Gateway resolves at config load time (and on reload). This lets you keep the
JSON config in version control while the actual secret lives in an environment
variable, an on-disk file, a NixOS secrets store (agenix / sops-nix), or
HashiCorp Vault.

Resolution happens in `pkg/config/config.go` (`resolveSecret`), applied in
`LoadGatewayConfig` to:

- `auth_token`
- `antigravity_token`
- every key in the `tokens` map (bearer token → role)
- every `scoped_tokens[].token`

Anything that does not match a known prefix is returned **unchanged**, so plain
inline values continue to work (backward compatible).

## Indirection forms

| Form | Resolves to | Example |
| --- | --- | --- |
| `env:NAME` | value of environment variable `NAME` | `"env:MYRMEX_AUTH_TOKEN"` |
| `file:/path` | trimmed contents of the file at `/path` | `"file:/run/secrets/myrmex-token"` |
| `agenix:<name>` | trimmed contents of `/run/agenix/<name>` | `"agenix:myrmex-token"` |
| `vault:<path>#field` | `field` read from Vault KV at `<path>` | `"vault:secret/data/myrmex#auth_token"` |
| `${NAME}` | value of environment variable `NAME` (whole-string form) | `"${MYRMEX_AUTH_TOKEN}"` |
| anything else | the literal string, unchanged | `"s3cr3t-inline"` |

Notes:

- **`agenix:<name>`** is convenience sugar for `file:/run/agenix/<name>`. The
  `<name>` must match `^[A-Za-z0-9._-]+$` (no slashes, no `..`) to prevent path
  traversal; an invalid name is logged and resolves to `""`.
- **`file:` / `agenix:` read errors** and **Vault errors** are logged to stderr
  and resolve to `""` rather than crashing the Gateway. An empty `auth_token`
  will then fail config validation, surfacing the misconfiguration at startup.
- **Vault** uses `VAULT_ADDR` (default `http://127.0.0.1:8200`) and
  `VAULT_TOKEN` from the environment, and supports both KV v2
  (`.data.data.<field>`) and KV v1 (`.data.<field>`) layouts.

### Examples

```json
{
  "auth_token": "agenix:myrmex-token",
  "antigravity_token": "vault:secret/data/myrmex#antigravity_token",
  "tokens": {
    "env:MYRMEX_ADMIN_TOKEN": "admin",
    "file:/run/agenix/myrmex-operator": "operator"
  },
  "scoped_tokens": [
    { "token": "agenix:myrmex-readonly", "role": "read-only" }
  ]
}
```

Both the **keys** of `tokens` and the `token` field of `scoped_tokens` are
resolved, so bearer tokens themselves can come from any indirection source.

## NixOS integration

### agenix

agenix decrypts each declared secret to a file under `/run/agenix/<name>` at
activation time, owned by whatever user/group you specify. Point Myrmex at that
file — either with the `agenix:` sugar or an explicit `file:` path.

```nix
# configuration.nix / a NixOS module
age.secrets."myrmex-token" = {
  file  = ../secrets/myrmex-token.age;   # encrypted at rest, in git
  mode  = "0400";
  owner = "myrmex";
  group = "myrmex";
};

# Gateway config value (in gateway_config.json, or rendered by your module):
#   "auth_token": "agenix:myrmex-token"
# which is exactly equivalent to:
#   "auth_token": "file:/run/agenix/myrmex-token"
```

Decrypted path: `config.age.secrets."myrmex-token".path` → `/run/agenix/myrmex-token`.

### sops-nix

sops-nix works the same way: it decrypts secrets to files at runtime (by
default under `/run/secrets/<name>`). There is **no dedicated `sops:` form** —
because the plaintext is already a file, consume it with `file:`:

```nix
sops.secrets."myrmex-token" = {
  owner = "myrmex";
  # path defaults to /run/secrets/myrmex-token
};

# Gateway config value:
#   "auth_token": "file:/run/secrets/myrmex-token"
```

If you customize `sops.secrets.<name>.path`, use that path in the `file:` form.

## Secret rotation

Because secrets are resolved from their indirection source at **config load**
and again on **config reload**, rotating a secret is a two-step operation:
change the underlying source, then make the Gateway re-read it.

1. **Rotate the underlying secret at its source:**
   - **agenix:** re-encrypt with the new value (`agenix -e secrets/myrmex-token.age`),
     deploy, and run `nixos-rebuild switch`. agenix rewrites
     `/run/agenix/myrmex-token` with the new plaintext.
   - **sops-nix:** update the sops file, deploy, `nixos-rebuild switch`; the
     plaintext under `/run/secrets/` is refreshed.
   - **Vault:** write the new version to the KV path
     (`vault kv put secret/myrmex auth_token=<new>`). No file changes needed.
   - **file/env:** replace the file contents or update the environment.

2. **Make the Gateway re-read the resolved value.** Secrets are re-resolved
   whenever the config is reloaded via `POST /api/config`, or on a full Gateway
   restart. Trigger one of:
   - `POST /api/config` (config reload) — re-runs `resolveSecret` on all
     secret fields, picking up the new source values without dropping agent
     tunnels where possible; **or**
   - restart the `myrmex-hive` service (`systemctl restart myrmex-gateway`).

   For zero-downtime rotation, roll new tokens in **additively**: add the new
   token to `tokens`/`scoped_tokens` first, reload, distribute the new token to
   clients, then remove the old token and reload again.

> Rotate the source **before** triggering the reload. If the reload runs while
> the source is empty or unreadable, the field resolves to `""` and (for
> `auth_token`) config validation fails, so the reload is rejected and the
> previously loaded config stays in effect.

## What is never exposed

- **Resolved secret values are never logged.** For the primary `auth_token`,
  only a **SHA-256 fingerprint** is emitted for correlation — never the token
  itself. Indirection *references* (e.g. the file path or env var name) may
  appear in error messages, but not the secret contents.
- **`GET /api/config` never returns resolved secret values.** The config
  surfaced over the API omits/redacts secret-bearing fields, so tokens cannot
  be read back out of a running Gateway.
