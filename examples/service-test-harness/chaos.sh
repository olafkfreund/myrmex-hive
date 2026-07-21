#!/bin/sh
# Chaos actions for the Myrmex Hive service-test-harness profile.
#
# This script is the ONE thing you allowlist for fault injection. It exists
# because chaos actions are multi-step and need cleanup (a `tc` rule outlives
# the command that added it), and because an args_regex tight enough to make
# raw `tc`/`kill` safe is harder to review than a fixed verb set.
#
# The agent invokes it via run_command with an anchored args_regex, so the
# only reachable calls are the verbs below with well-formed arguments. See
# docs/SERVICE_TESTING.md.
#
# POSIX sh, NOT bash, and deliberately so: the targets worth breaking on
# purpose are often minimal containers. Alpine — the most common container
# base there is — ships busybox ash and no bash at all, so a bash shebang
# makes this example unusable exactly where it is most useful. No [[ ]], no
# arrays, no `local`, no `disown`, no `pipefail`.
#
# Every action is bounded: it self-reverts after DURATION seconds, so a lost
# gateway connection cannot leave a host degraded forever. That bound is the
# whole safety story here — do not remove it.
#
# Timed actions DETACH and return immediately. This is not a style choice:
#
#   1. The agent kills any command at 30s via exec.CommandContext, which sends
#      SIGKILL. Shell EXIT traps do NOT run on SIGKILL (verified). A blocking
#      `latency 60 ...` would therefore be killed mid-sleep with its netem rule
#      still installed — permanently. A fault that outlives the test is an
#      outage, which is exactly what this script exists to avoid.
#   2. Detached teardown survives the agent dying, not just the command ending.
#   3. Tool output is buffered until the command exits, so a blocking fault
#      means you cannot observe anything WHILE it is happening — which is the
#      entire point of injecting it.
#
# So: apply the fault, schedule the revert in an independent session, return.

set -eu

MAX_DURATION=300 # ponytail: hard ceiling so a typo'd duration can't wedge a host

# detach runs a command in its own session so it survives this script being
# killed — including SIGKILL from the agent's command timeout. setsid is the
# real guarantee; the bare background fallback covers hosts without util-linux
# and is strictly weaker (dies with its process group).
detach() {
	if command -v setsid >/dev/null 2>&1; then
		setsid nohup "$@" >/dev/null 2>&1 &
	else
		nohup "$@" >/dev/null 2>&1 &
	fi
}

usage() {
	cat <<'EOF'
usage: chaos.sh <action> [args]

  cpu <duration> <workers>       burn <workers> cores for <duration>s
  mem <duration> <megabytes>     hold <megabytes> MB resident for <duration>s
  latency <duration> <ms> <if>   add <ms> egress latency on <if> for <duration>s
  loss <duration> <pct> <if>     drop <pct>% of egress packets on <if> for <duration>s
  kill <signal> <pidfile>        send <signal> to the pid in <pidfile>
  status                         report what chaos is currently active

Durations are seconds and capped at 300.
EOF
}

die() {
	echo "$1" >&2
	exit "${2:-2}"
}

# is_uint is the POSIX stand-in for [[ $x =~ ^[0-9]+$ ]]. An empty string or
# any non-digit character fails.
is_uint() {
	case "${1:-}" in
	'' | *[!0-9]*) return 1 ;;
	*) return 0 ;;
	esac
}

# in_range validates an integer argument and its bounds in one place, so every
# numeric input is checked the same way.
in_range() {
	is_uint "$1" || die "$4 must be an integer, got: $1"
	[ "$1" -ge "$2" ] && [ "$1" -le "$3" ] || die "$4 must be $2..$3, got: $1"
}

bound() { in_range "$1" 1 "$MAX_DURATION" "duration"; }

action="${1:-}"
[ $# -gt 0 ] && shift

case "$action" in
cpu)
	duration="${1:?duration required}"
	workers="${2:?workers required}"
	bound "$duration"
	in_range "$workers" 1 64 "workers"
	i=0
	while [ "$i" -lt "$workers" ]; do
		detach timeout "$duration" sh -c 'while :; do :; done'
		i=$((i + 1))
	done
	echo "cpu: ${workers} worker(s) burning for ${duration}s (detached; observe with get_metrics)"
	;;

mem)
	duration="${1:?duration required}"
	mb="${2:?megabytes required}"
	bound "$duration"
	in_range "$mb" 1 4096 "megabytes"
	# head -c on /dev/zero into a shell var keeps the pages resident without
	# needing stress-ng installed on the target.
	detach timeout "$duration" sh -c "x=\$(head -c ${mb}000000 /dev/zero | tr '\\0' 'x'); sleep ${duration}"
	echo "mem: holding ${mb}MB for ${duration}s (detached; observe with get_metrics)"
	;;

latency | loss)
	duration="${1:?duration required}"
	amount="${2:?amount required}"
	iface="${3:?interface required}"
	bound "$duration"
	case "$iface" in
	'' | *[!a-zA-Z0-9_-]*) die "bad interface name: $iface" ;;
	esac
	command -v tc >/dev/null 2>&1 || die "tc not installed (iproute2)" 3

	if [ "$action" = latency ]; then
		is_uint "$amount" || die "latency must be an integer (ms), got: $amount"
		netem_kind=delay
		netem_arg="${amount}ms"
	else
		in_range "$amount" 0 100 "loss pct"
		netem_kind=loss
		netem_arg="${amount}%"
	fi

	# Schedule the teardown in an INDEPENDENT session before applying the rule.
	# An EXIT trap is not good enough here: the agent's 30s timeout kills with
	# SIGKILL, which runs no traps, so any duration over ~30s would strand the
	# rule permanently. This teardown outlives even the agent.
	detach sh -c "sleep ${duration}; tc qdisc del dev '${iface}' root 2>/dev/null || true"
	tc qdisc add dev "$iface" root netem "$netem_kind" "$netem_arg"
	echo "${action}: applied ${amount} on ${iface}, auto-reverts in ${duration}s"
	;;

kill)
	signal="${1:?signal required}"
	pidfile="${2:?pidfile required}"
	case "$signal" in
	TERM | KILL | HUP | USR1 | USR2) ;;
	*) die "signal not permitted: $signal" ;;
	esac
	[ -r "$pidfile" ] || die "pidfile not readable: $pidfile" 3
	pid="$(cat "$pidfile")"
	is_uint "$pid" || die "pidfile does not contain a pid" 3
	kill -"$signal" "$pid"
	echo "kill: sent SIG${signal} to pid ${pid}"
	;;

status)
	echo "== active netem qdiscs =="
	if command -v tc >/dev/null 2>&1; then
		tc qdisc show | grep netem || echo "(none)"
	else
		echo "(tc not installed)"
	fi
	echo "== load =="
	uptime
	;;

*)
	usage
	exit 2
	;;
esac
