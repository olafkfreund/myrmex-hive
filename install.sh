#!/usr/bin/env bash
# Installation script for MCP Agent (Linux and macOS)

set -e

# Target directories
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/mcp-agent"
LOG_DIR="/var/log"

echo "=== MCP Agent Installer ==="

# Check requirements
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (sudo)." >&2
  exit 1
fi

# Determine OS
OS_TYPE=$(uname -s | tr '[:upper:]' '[:lower:]')
echo "Detected Operating System: $OS_TYPE"

# 1. Compile or verify binary
if [ -f "./bin/agent" ]; then
  echo "Using existing compiled binary at ./bin/agent"
  cp ./bin/agent "$BIN_DIR/mcp-agent"
elif command -v go >/dev/null 2>&1; then
  echo "Compiling agent binary locally..."
  go build -o "$BIN_DIR/mcp-agent" cmd/agent/main.go
else
  echo "Error: Go compiler not found and no pre-built binary at ./bin/agent. Please build or place the binary." >&2
  exit 1
fi

chmod +x "$BIN_DIR/mcp-agent"
echo "Binary installed to $BIN_DIR/mcp-agent"

# 2. Setup Configuration
mkdir -p "$CONF_DIR"

if [ ! -f "$CONF_DIR/config.json" ]; then
  echo "Generating default agent configuration..."
  
  # Prompt settings with defaults
  read -p "Enter Agent ID [$(hostname)]: " AGENT_ID
  AGENT_ID=${AGENT_ID:-$(hostname)}
  
  read -p "Enter Gateway Address [localhost:2222]: " GATEWAY_ADDR
  GATEWAY_ADDR=${GATEWAY_ADDR:-"localhost:2222"}
  
  PRIVATE_KEY_PATH="$CONF_DIR/id_ed25519"

  cat > "$CONF_DIR/config.json" <<EOF
{
  "agent_id": "$AGENT_ID",
  "gateway_addr": "$GATEWAY_ADDR",
  "private_key_path": "$PRIVATE_KEY_PATH",
  "allowed_commands": [
    {"name": "df", "args_regex": ".*"},
    {"name": "free", "args_regex": ".*"},
    {"name": "uptime", "args_regex": ".*"}
  ]
}
EOF
  echo "Configuration created at $CONF_DIR/config.json"
else
  echo "Configuration file already exists at $CONF_DIR/config.json. Skipping generation."
fi

# 3. Setup SSH Keys
PRIVATE_KEY_PATH="$CONF_DIR/id_ed25519"
if [ ! -f "$PRIVATE_KEY_PATH" ]; then
  echo "Generating secure Ed25519 keypair for gateway authentication..."
  ssh-keygen -t ed25519 -N "" -f "$PRIVATE_KEY_PATH"
  chmod 600 "$PRIVATE_KEY_PATH"
  echo "Keypair generated successfully."
else
  echo "SSH Key already exists at $PRIVATE_KEY_PATH. Skipping generation."
fi

# 4. Configure Service Daemon
if [ "$OS_TYPE" = "linux" ]; then
  # Systemd Configuration
  SERVICE_FILE="/etc/systemd/system/mcp-agent.service"
  echo "Configuring systemd service..."
  
  cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=MCP OS Agent
After=network.target

[Service]
ExecStart=$BIN_DIR/mcp-agent -config $CONF_DIR/config.json
Restart=always
RestartSec=5
User=root
WorkingDirectory=$CONF_DIR

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable mcp-agent
  systemctl start mcp-agent
  echo "Systemd service registered, enabled, and started."

elif [ "$OS_TYPE" = "darwin" ]; then
  # macOS LaunchDaemon Configuration
  PLIST_FILE="/Library/LaunchDaemons/com.mcp.agent.plist"
  echo "Configuring macOS LaunchDaemon..."

  cat > "$PLIST_FILE" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mcp.agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>$BIN_DIR/mcp-agent</string>
        <string>-config</string>
        <string>$CONF_DIR/config.json</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/mcp-agent.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/mcp-agent.log</string>
</dict>
</plist>
EOF

  launchctl load -w "$PLIST_FILE"
  echo "LaunchDaemon registered and loaded."
fi

echo "==========================================="
echo "MCP Agent installation complete!"
echo ""
echo "IMPORTANT: Register the agent public key on your Gateway."
echo "Public Key Content:"
cat "${PRIVATE_KEY_PATH}.pub"
echo "==========================================="
