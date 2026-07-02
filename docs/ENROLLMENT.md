# Agent Enrollment, Bootstrap, Rotation & Revocation

Myrmex Hive agents never accept inbound connections and never hold a
long-lived shared secret out of the box. Instead, an agent's Ed25519 public
key must be explicitly enrolled into the Gateway's `authorized_keys` file
before the agent can open its SSH tunnel. This document covers the full
lifecycle: minting a join token, enrolling a key, one-command bootstrap,
key rotation, and revocation — plus rotating the Gateway's own host key.

All commands below are `myrmex` CLI subcommands. Run `myrmex --help` for the
full flag reference.

## 1. The enrollment lifecycle

```
 admin                      agent host                      gateway
   |                             |                               |
   | myrmex enroll-token ------->|                               |
   |   (admin --token)           |                               |
   |<---- join_token, expires ---|                               |
   |                             |                               |
   |  (hand join_token to        |                               |
   |   whoever provisions        |                               |
   |   the agent host)           |                               |
   |                             |                               |
   |                     myrmex enroll ------------------------->|
   |                       --join-token --agent-id               |
   |                       --public-key-file                     |
   |                             |<---- success -------------------|
   |                             |                               |
   |                     agent connects (SSH) -------------------->|
   |                       (agent_config.json points at           |
   |                        private_key_path / gateway_addr)      |
```

Two Gateway REST endpoints implement this:

- `POST /api/enroll/token` (admin bearer token required) — mints a
  short-lived, single-use join token bound to one `agent_id`.
  Body: `{"agent_id": "agent-4"}`.
  Response: `{"join_token": "...", "agent_id": "agent-4", "expires_at": "..."}`.
- `POST /api/enroll` (**no** bearer token — the join token itself is the
  credential) — redeems a join token, appending the given public key to the
  Gateway's `AuthorizedKeysPath` under the validated `agent_id`.
  Body: `{"join_token": "...", "agent_id": "agent-4", "public_key": "ssh-ed25519 AAAA... agent-4"}`.

Join tokens are single-use and expire (`EnrollmentTokenTTLSeconds` in the
Gateway config, default 900s), so a leaked token has a narrow blast radius.

### Minting a token and enrolling by hand

```sh
# On a machine with an admin token:
myrmex enroll-token --agent-id agent-4 --token <admin-token>
# -> prints the join token and its expiry

# On (or for) the agent host, once you have a keypair:
myrmex enroll \
  --join-token <token> \
  --agent-id agent-4 \
  --public-key-file id_ed25519.pub
```

`enroll` needs no `--token`/`MYRMEX_TOKEN` — the join token is the
credential. `enroll-token` always needs an admin token.

## 2. One-command bootstrap (`myrmex bootstrap`)

For onboarding a brand-new agent, `myrmex bootstrap` does everything in one
step: generates a fresh Ed25519 keypair, mints a join token (if you have an
admin token and didn't pass one), enrolls the public key, and writes a
ready-to-run `agent_config.json`.

```sh
myrmex bootstrap \
  --agent-id agent-4 \
  --gateway-addr gateway.example.com:2222 \
  --token <admin-token>
```

This writes:

- `./id_ed25519` — the new private key (mode `0600`)
- `./id_ed25519.pub` — the corresponding OpenSSH public key
- `./agent_config.json` — `agent_id`, `gateway_addr`, `private_key_path`,
  `known_host_key_path`, and an empty `allowed_commands` array ready for you
  to fill in

Override output paths with `--key-out` / `--config-out`, or supply an
already-minted `--join-token` instead of an admin `--token` (useful when the
person provisioning the agent host is not the same person with Gateway
admin access — mint the token separately with `enroll-token` and hand it
over).

Next steps after bootstrap:

1. Copy the private key and `agent_config.json` to the target host.
2. Edit `allowed_commands` in `agent_config.json` — bootstrap deliberately
   leaves this empty; an agent with no allowed commands can connect but run
   nothing.
3. Run `agent --config agent_config.json` on the target host. The agent
   trust-on-first-use (TOFU) pins the Gateway's host key to
   `known_host_key_path` on its first successful connect.

## 3. Key rotation (`myrmex rotate`, #49)

Rotating an agent's key means: enroll a new key for the existing
`agent_id`, then (optionally) remove the old one.

```sh
myrmex rotate \
  --agent-id agent-4 \
  --public-key-file id_ed25519_new.pub \
  --token <admin-token>
```

By default `rotate` **only enrolls the new key** — it does not touch old
keys. The Gateway's `authorized_keys` format allows multiple keys per
`agent_id`, so the new key works immediately alongside the old one with
zero downtime for the agent's tunnel.

### `--revoke-old`

```sh
myrmex rotate \
  --agent-id agent-4 \
  --public-key-file id_ed25519_new.pub \
  --revoke-old \
  --token <admin-token>
```

**Important:** the Gateway's revocation endpoint (`POST
/api/agents/revoke`) removes *every* `authorized_keys` entry for an
`agent_id` by comment match — there is no "remove this one key" primitive.
So `--revoke-old` necessarily also removes the key `rotate` just enrolled,
and drops any live session for that agent. `myrmex rotate --revoke-old`
therefore:

1. Enrolls the new key.
2. Calls `/api/agents/revoke`, wiping *all* keys (old and new) and
   disconnecting the agent if it's currently connected.
3. Prints the exact `enroll-token` + `enroll` commands to re-add the new
   key, since it was just wiped along with the old one.

Recommended sequence for a clean rotation with a revoke step:

```sh
# 1. Enroll the new key (old key still works, agent stays connected)
myrmex rotate --agent-id agent-4 --public-key-file new.pub --token <admin-token>

# 2. Confirm the agent can reconnect/authenticate with the new key
#    (e.g. restart the agent process pointed at the new private key)

# 3. Only now, wipe all keys and re-enroll just the new one
myrmex rotate --agent-id agent-4 --public-key-file new.pub --revoke-old --token <admin-token>
```

Or, more simply, do the revoke and re-enroll as separate explicit steps
using `enroll-token` / `enroll` after confirming the new key works — this
avoids the "revoke wipes what I just enrolled" surprise entirely.

## 4. Revocation

To fully decommission an agent (not rotating, just removing it):

```sh
myrmex call gateway__revoke_agent --arguments '{}' # not applicable; use REST directly:
```

Revocation isn't currently a bare top-level `myrmex` subcommand outside of
`rotate --revoke-old` — call the endpoint directly if you just want to
revoke without rotating:

```sh
curl -sk -X POST https://<gateway>:8080/api/agents/revoke \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{"agent_id":"agent-4"}'
```

Response: `{"revoked":true,"keys_removed":<n>,"session_dropped":<bool>}`.
This removes all of the agent's keys from `authorized_keys` and, if the
agent is currently connected, disconnects its tunnel immediately.

## 5. Gateway host-key rotation

Agents pin the Gateway's SSH host key (either statically via
`gateway_host_key` in `agent_config.json`, or via TOFU into
`known_host_key_path`). Rotating the Gateway's own host key is an
operational, out-of-band step — the enrollment endpoints only manage
*agent* keys, not the Gateway's host identity:

1. Generate a new Gateway SSH host key and update the Gateway's
   `host_key_path` config to point at it (or replace the file in place).
2. Restart the Gateway so it presents the new host key on new SSH
   connections.
3. On each agent, either:
   - Delete the stale `known_host_key_path` file so the agent re-TOFU-pins
     the new host key on its next connection attempt (only safe if you
     trust the network path for that reconnect), or
   - Explicitly set `gateway_host_key` in `agent_config.json` to the new
     host public key ahead of time (safer — no blind TOFU re-trust).
4. If you use `myrmex audit verify`/`audit pubkey`, distribute the new host
   public key to auditors — audit log signatures are verified against
   whichever host key file you point `--host-key` at, and old log entries
   remain verifiable against the *old* key that signed them.

## Command reference

| Command | Auth | Purpose |
|---|---|---|
| `myrmex enroll-token --agent-id X` | admin `--token` | Mint a join token for `X`. |
| `myrmex enroll --join-token T --agent-id X --public-key-file F` | join token only | Redeem a token, register `X`'s public key. |
| `myrmex bootstrap --agent-id X [--token \| --join-token T]` | admin `--token` (to mint) or `--join-token` | Generate keypair + enroll + write `agent_config.json`. |
| `myrmex rotate --agent-id X --public-key-file F [--revoke-old]` | admin `--token` (to mint) or `--join-token` | Enroll a replacement key, optionally revoking all old keys. |

See `myrmex --help` for full flag documentation and example invocations.
