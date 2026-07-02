#!/usr/bin/env bash
# Installation script for MCP Agent (Linux and macOS)
#
# By default this script downloads a pre-built "myrmex-agent" binary from the
# project's GitHub Releases (GoReleaser output), so target/edge nodes do not
# need a Go toolchain installed. Pass --build-from-source to fall back to the
# old behaviour of compiling locally (or using an existing ./bin/agent), which
# is useful for airgapped environments or local development builds.

set -e

# Target directories
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/mcp-agent"
LOG_DIR="/var/log"

# GitHub repository that publishes GoReleaser release archives/binaries.
GITHUB_REPO="olafkfreund/myrmex-hive"
GITHUB_API_LATEST_RELEASE="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"

# --build-from-source: skip downloading a release archive and instead compile
# (or reuse an existing ./bin/agent) as this script always used to do.
BUILD_FROM_SOURCE=false
for arg in "$@"; do
  case "$arg" in
    --build-from-source)
      BUILD_FROM_SOURCE=true
      ;;
  esac
done

echo "=== MCP Agent Installer ==="

# Check requirements
if [ "$EUID" -ne 0 ]; then
  echo "Error: Please run as root (sudo)." >&2
  exit 1
fi

# Determine OS
OS_TYPE=$(uname -s | tr '[:upper:]' '[:lower:]')
echo "Detected Operating System: $OS_TYPE"

# Downloads and verifies the GoReleaser release archive for this OS/arch,
# extracts it, and installs the "myrmex-agent" binary to "$BIN_DIR/mcp-agent".
# Returns non-zero (without exiting) on any failure so the caller can fall
# back to a helpful error message pointing at --build-from-source.
download_release_binary() {
  if ! command -v curl >/dev/null 2>&1; then
    echo "Error: curl is required to download the release binary." >&2
    return 1
  fi
  if ! command -v tar >/dev/null 2>&1; then
    echo "Error: tar is required to extract the release archive." >&2
    return 1
  fi

  # Normalize `uname -m` output to Go's GOARCH naming used by GoReleaser.
  local raw_arch
  raw_arch=$(uname -m)
  local goarch
  case "$raw_arch" in
    x86_64|amd64)
      goarch="amd64"
      ;;
    aarch64|arm64)
      goarch="arm64"
      ;;
    *)
      echo "Error: unsupported architecture '$raw_arch'." >&2
      return 1
      ;;
  esac

  if [ "$OS_TYPE" != "linux" ] && [ "$OS_TYPE" != "darwin" ]; then
    echo "Error: no published release binaries for OS '$OS_TYPE'." >&2
    return 1
  fi

  echo "Querying GitHub API for the latest release ($GITHUB_REPO)..."
  local release_json
  if ! release_json=$(curl -fsSL "$GITHUB_API_LATEST_RELEASE"); then
    echo "Error: failed to query $GITHUB_API_LATEST_RELEASE" >&2
    return 1
  fi

  # Pull the archive's browser_download_url out of the release JSON without
  # depending on jq (edge nodes may not have it installed). GoReleaser names
  # archives "<project>_<version>_<os>_<arch>.tar.gz".
  local asset_url
  asset_url=$(printf '%s' "$release_json" \
    | grep -o "\"browser_download_url\"[[:space:]]*:[[:space:]]*\"[^\"]*_${OS_TYPE}_${goarch}\.tar\.gz\"" \
    | head -n1 \
    | sed -E 's/.*"(https:[^"]+)"/\1/')

  if [ -z "$asset_url" ]; then
    echo "Error: could not find a release asset for ${OS_TYPE}/${goarch}." >&2
    return 1
  fi

  local checksum_url
  checksum_url=$(printf '%s' "$release_json" \
    | grep -o '"browser_download_url"[[:space:]]*:[[:space:]]*"[^"]*checksums\.txt"' \
    | head -n1 \
    | sed -E 's/.*"(https:[^"]+)"/\1/')

  local tmp_dir
  tmp_dir=$(mktemp -d)
  local archive_name
  archive_name=$(basename "$asset_url")

  echo "Downloading $archive_name ..."
  if ! curl -fsSL -o "$tmp_dir/$archive_name" "$asset_url"; then
    echo "Error: failed to download release asset from $asset_url" >&2
    rm -rf "$tmp_dir"
    return 1
  fi

  if [ -n "$checksum_url" ]; then
    echo "Downloading checksums.txt for verification..."
    if curl -fsSL -o "$tmp_dir/checksums.txt" "$checksum_url"; then
      # Extract just the line for our archive so we can verify it in isolation.
      grep " ${archive_name}\$" "$tmp_dir/checksums.txt" > "$tmp_dir/${archive_name}.sha256" 2>/dev/null || true
      if [ -s "$tmp_dir/${archive_name}.sha256" ]; then
        echo "Verifying checksum..."
        if command -v sha256sum >/dev/null 2>&1; then
          if ! (cd "$tmp_dir" && sha256sum -c "${archive_name}.sha256"); then
            echo "Error: checksum verification failed for $archive_name" >&2
            rm -rf "$tmp_dir"
            return 1
          fi
        elif command -v shasum >/dev/null 2>&1; then
          if ! (cd "$tmp_dir" && shasum -a 256 -c "${archive_name}.sha256"); then
            echo "Error: checksum verification failed for $archive_name" >&2
            rm -rf "$tmp_dir"
            return 1
          fi
        else
          echo "Warning: no sha256sum/shasum utility found; skipping checksum verification." >&2
        fi
      else
        echo "Warning: checksum entry for $archive_name not found in checksums.txt; skipping verification." >&2
      fi
    else
      echo "Warning: could not download checksums.txt; skipping verification." >&2
    fi
  else
    echo "Warning: no checksums.txt published with this release; skipping verification." >&2
  fi

  echo "Extracting archive..."
  if ! tar -xzf "$tmp_dir/$archive_name" -C "$tmp_dir"; then
    echo "Error: failed to extract $archive_name" >&2
    rm -rf "$tmp_dir"
    return 1
  fi

  if [ ! -f "$tmp_dir/myrmex-agent" ]; then
    echo "Error: myrmex-agent binary not found inside downloaded archive." >&2
    rm -rf "$tmp_dir"
    return 1
  fi

  cp "$tmp_dir/myrmex-agent" "$BIN_DIR/mcp-agent"
  rm -rf "$tmp_dir"
  return 0
}

# 1. Obtain binary: download a pre-built release by default, or compile from
#    source when --build-from-source is passed (or no download is possible).
if [ "$BUILD_FROM_SOURCE" = true ]; then
  echo "--build-from-source specified: using local compile path."
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
else
  echo "Downloading pre-built agent binary from GitHub Releases..."
  if ! download_release_binary; then
    echo "Error: failed to download the release binary." >&2
    echo "Re-run with --build-from-source to compile locally instead (requires the Go toolchain)." >&2
    exit 1
  fi
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
