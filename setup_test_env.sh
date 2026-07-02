#!/usr/bin/env bash
set -euo pipefail

echo "Creating test directories..."
rm -rf test_env
mkdir -p test_env/gateway
mkdir -p test_env/agent-1
mkdir -p test_env/agent-2
mkdir -p test_env/agent-3
mkdir -p test_env/agent-nginx
mkdir -p test_env/agent-db

# Identity binding: the gateway derives each agent's id from the COMMENT on its
# authorized_keys entry and rejects a key whose comment is empty or does not
# match the agent-id the connection requests. Every agent keypair is therefore
# generated with its agent-id as the key comment (-C "<agent-id>").
echo "Generating SSH keys (with agent-id comments) for agent-1, agent-2, agent-3, agent-nginx, and agent-db..."
for agent in agent-1 agent-2 agent-3 agent-nginx agent-db; do
  ssh-keygen -t ed25519 -f "test_env/${agent}/id_ed25519" -N "" -C "${agent}" -q
done

# Persistent gateway host key: REQUIRED because the gateway config below sets
# audit_log_path (audit signatures must remain verifiable across restarts). It
# also gives agents a stable identity to trust-on-first-use (TOFU).
echo "Generating persistent Gateway SSH host key..."
ssh-keygen -t ed25519 -f test_env/gateway/host_key -N "" -C "myrmex-gateway" -q
chmod 600 test_env/gateway/host_key

echo "Creating authorized_keys on gateway from the commented agent public keys..."
: > test_env/gateway/authorized_keys
for agent in agent-1 agent-2 agent-3 agent-nginx agent-db; do
  cat "test_env/${agent}/id_ed25519.pub" >> test_env/gateway/authorized_keys
done

echo "Generating Gateway configuration..."
cat <<EOF > test_env/gateway/gateway_config.json
{
  "listen_addr": ":2222",
  "http_addr": ":8080",
  "host_key_path": "/app/host_key",
  "authorized_keys_path": "/app/authorized_keys",
  "ollama_url": "http://p510.tail833f7.ts.net:11434",
  "ollama_model": "gemma4:e4b",
  "auth_token": "40964684f37485ffa06c6dc97142f45e827e81bd46ccba04ab97ecfa53e7cf15",
  "audit_log_path": "/app/audit.log"
}
EOF

echo "Generating Agent configurations..."
cat <<EOF > test_env/agent-1/agent_config.json
{
  "gateway_addr": "gateway:2222",
  "private_key_path": "/app/id_ed25519",
  "agent_id": "agent-1",
  "allowed_commands": [
    {
      "name": "uptime",
      "args_regex": "^$"
    },
    {
      "name": "df",
      "args_regex": "^-h$"
    }
  ]
}
EOF

cat <<EOF > test_env/agent-2/agent_config.json
{
  "gateway_addr": "gateway:2222",
  "private_key_path": "/app/id_ed25519",
  "agent_id": "agent-2",
  "allowed_commands": [
    {
      "name": "free",
      "args_regex": "^-m$"
    }
  ]
}
EOF

cat <<EOF > test_env/agent-3/agent_config.json
{
  "gateway_addr": "gateway:2222",
  "private_key_path": "/app/id_ed25519",
  "agent_id": "agent-3",
  "allowed_commands": [
    {
      "name": "uptime",
      "args_regex": "^$"
    }
  ]
}
EOF

echo "Generating dummy syslog messages..."
cat <<EOF > test_env/agent-1/messages
2026-06-26T11:00:00Z auth.info sshd[100]: Server listening on 0.0.0.0 port 22.
2026-06-26T11:05:00Z auth.warning sshd[105]: Invalid user admin from 192.168.1.15 port 43212
2026-06-26T11:07:00Z daemon.err systemd[1]: Failed to start Nginx High-Performance Web Server.
EOF

# Set proper file permissions
chmod 600 test_env/agent-1/id_ed25519
chmod 600 test_env/agent-2/id_ed25519
chmod 600 test_env/agent-3/id_ed25519
chmod 600 test_env/agent-nginx/id_ed25519
chmod 600 test_env/agent-db/id_ed25519

echo "Generating Nginx Agent configuration..."
cat <<EOF > test_env/agent-nginx/agent_config.json
{
  "gateway_addr": "gateway:2222",
  "private_key_path": "/app/id_ed25519",
  "agent_id": "agent-nginx",
  "allowed_commands": [
    {
      "name": "uptime",
      "args_regex": "^$"
    }
  ]
}
EOF

echo "Generating DB Agent configuration..."
cat <<EOF > test_env/agent-db/agent_config.json
{
  "gateway_addr": "gateway:2222",
  "private_key_path": "/app/id_ed25519",
  "agent_id": "agent-db",
  "allowed_commands": [
    {
      "name": "uptime",
      "args_regex": "^$"
    }
  ]
}
EOF

echo "Test environment set up successfully."
