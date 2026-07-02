#!/usr/bin/env bash
set -euo pipefail

# Agent identity. The gateway now derives each agent's id from the COMMENT on
# its authorized_keys entry and rejects a key whose comment is empty or does not
# match the agent-id the connection requests. So the agent key MUST carry its
# agent-id as the key comment, and that agent-id must equal the "agent_id" in
# agent_config.json (the default local config uses "prod-server-1").
AGENT_ID="${AGENT_ID:-prod-server-1}"

echo "Generating Agent SSH keypair (Ed25519) with agent-id comment '${AGENT_ID}'..."
ssh-keygen -t ed25519 -f id_ed25519 -N "" -C "${AGENT_ID}" -q

echo "Adding Agent public key (with agent-id comment) to authorized_keys..."
cat id_ed25519.pub > authorized_keys

echo "Generating persistent Gateway SSH host key (Ed25519)..."
# A persistent host key is REQUIRED by the gateway whenever audit_log_path is
# set (audit signatures must stay verifiable across restarts) and lets agents
# pin/trust a stable gateway identity. Point "host_key_path" in
# gateway_config.json at this file to use it.
ssh-keygen -t ed25519 -f host_key -N "" -C "myrmex-gateway" -q

chmod 600 id_ed25519 host_key

echo "Keys generated successfully."
echo "  Agent private key : id_ed25519 (comment: ${AGENT_ID})"
echo "  Agent authorized  : authorized_keys"
echo "  Gateway host key  : host_key  (set host_key_path to this in gateway_config.json)"
