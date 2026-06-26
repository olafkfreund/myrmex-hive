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

echo "Generating SSH keys for Agent 1, 2, 3, nginx, and db..."
ssh-keygen -t ed25519 -f test_env/agent-1/id_ed25519 -N "" -q
ssh-keygen -t ed25519 -f test_env/agent-2/id_ed25519 -N "" -q
ssh-keygen -t ed25519 -f test_env/agent-3/id_ed25519 -N "" -q
ssh-keygen -t ed25519 -f test_env/agent-nginx/id_ed25519 -N "" -q
ssh-keygen -t ed25519 -f test_env/agent-db/id_ed25519 -N "" -q

echo "Creating authorized_keys on gateway containing all agent public keys..."
cat test_env/agent-1/id_ed25519.pub >> test_env/gateway/authorized_keys
cat test_env/agent-2/id_ed25519.pub >> test_env/gateway/authorized_keys
cat test_env/agent-3/id_ed25519.pub >> test_env/gateway/authorized_keys
cat test_env/agent-nginx/id_ed25519.pub >> test_env/gateway/authorized_keys
cat test_env/agent-db/id_ed25519.pub >> test_env/gateway/authorized_keys

echo "Generating Gateway configuration..."
cat <<EOF > test_env/gateway/gateway_config.json
{
  "listen_addr": ":2222",
  "http_addr": ":8080",
  "host_key_path": "",
  "authorized_keys_path": "/app/authorized_keys",
  "ollama_url": "http://p510.tail833f7.ts.net:11434",
  "ollama_model": "gemma4:e4b",
  "auth_token": "40964684f37485ffa06c6dc97142f45e827e81bd46ccba04ab97ecfa53e7cf15"
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
