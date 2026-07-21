#!/usr/bin/env bash
# Apply a named config variant to the service under test, then reload it.
#
# This is the answer to "how do I change things between test iterations when
# there is no file_write tool?". The script owns WHAT may change; the agent's
# args_regex only picks WHICH named variant. The agent gets a menu, not a
# filesystem — so a compromised gateway can select a variant you wrote, and
# nothing else.
#
# Template: replace the variant bodies with your service's real config.

set -euo pipefail

SERVICE="${SERVICE:-myservice}"
CONFIG_DIR="${CONFIG_DIR:-/etc/${SERVICE}}"
TARGET="${CONFIG_DIR}/generated.conf"

variant="${1:?variant required: baseline|high-timeout|low-memory|no-cache}"

# Keep one backup so a bad variant is one command from being undone.
[ -f "$TARGET" ] && cp "$TARGET" "${TARGET}.prev"

case "$variant" in
baseline)     printf 'timeout=30\nmax_memory_mb=1024\ncache=on\n'  > "$TARGET" ;;
high-timeout) printf 'timeout=300\nmax_memory_mb=1024\ncache=on\n' > "$TARGET" ;;
low-memory)   printf 'timeout=30\nmax_memory_mb=128\ncache=on\n'   > "$TARGET" ;;
no-cache)     printf 'timeout=30\nmax_memory_mb=1024\ncache=off\n' > "$TARGET" ;;
*)
	echo "unknown variant: $variant" >&2
	exit 2
	;;
esac

# Reload rather than restart where the service supports it, so the variant is
# measured against a warm process rather than a cold start.
if command -v systemctl >/dev/null && systemctl is-active --quiet "$SERVICE"; then
	systemctl reload-or-restart "$SERVICE"
fi

echo "applied variant '${variant}' to ${TARGET}"
