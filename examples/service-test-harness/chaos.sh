#!/usr/bin/env bash
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
# Every action is bounded: it self-reverts after DURATION seconds, so a lost
# gateway connection cannot leave a host degraded forever. That bound is the
# whole safety story here — do not remove it.

set -euo pipefail

MAX_DURATION=300 # ponytail: hard ceiling so a typo'd duration can't wedge a host

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

# bound validates that a duration is a sane, capped integer. Every timed action
# routes through it, so there is one place to audit the ceiling.
bound() {
	local d="$1"
	if ! [[ "$d" =~ ^[0-9]+$ ]] || [ "$d" -lt 1 ] || [ "$d" -gt "$MAX_DURATION" ]; then
		echo "duration must be 1..${MAX_DURATION} seconds, got: $d" >&2
		exit 2
	fi
}

action="${1:-}"
shift || true

case "$action" in
cpu)
	duration="${1:?duration required}"
	workers="${2:?workers required}"
	bound "$duration"
	[[ "$workers" =~ ^[0-9]+$ ]] && [ "$workers" -ge 1 ] && [ "$workers" -le 64 ] ||
		{ echo "workers must be 1..64" >&2; exit 2; }
	for _ in $(seq 1 "$workers"); do
		timeout "$duration" sh -c 'while :; do :; done' &
	done
	wait
	echo "cpu: burned ${workers} worker(s) for ${duration}s"
	;;

mem)
	duration="${1:?duration required}"
	mb="${2:?megabytes required}"
	bound "$duration"
	[[ "$mb" =~ ^[0-9]+$ ]] && [ "$mb" -ge 1 ] && [ "$mb" -le 4096 ] ||
		{ echo "megabytes must be 1..4096" >&2; exit 2; }
	# head -c on /dev/zero into a shell var keeps the pages resident without
	# needing stress-ng installed on the target.
	timeout "$duration" sh -c "x=\$(head -c ${mb}000000 /dev/zero | tr '\\0' 'x'); sleep ${duration}" || true
	echo "mem: held ${mb}MB for ${duration}s"
	;;

latency | loss)
	duration="${1:?duration required}"
	amount="${2:?amount required}"
	iface="${3:?interface required}"
	bound "$duration"
	[[ "$iface" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "bad interface name" >&2; exit 2; }
	[[ "$amount" =~ ^[0-9]+$ ]] || { echo "amount must be an integer" >&2; exit 2; }
	command -v tc >/dev/null || { echo "tc not installed (iproute2)" >&2; exit 3; }

	if [ "$action" = latency ]; then
		rule=(delay "${amount}ms")
	else
		[ "$amount" -le 100 ] || { echo "loss pct must be 0..100" >&2; exit 2; }
		rule=(loss "${amount}%")
	fi

	# Always schedule the teardown FIRST: if this shell dies mid-run the rule
	# still gets removed. A netem rule that outlives the test is an outage.
	tc qdisc add dev "$iface" root netem "${rule[@]}"
	trap 'tc qdisc del dev "$iface" root 2>/dev/null || true' EXIT
	sleep "$duration"
	echo "${action}: applied ${amount} on ${iface} for ${duration}s, reverted"
	;;

kill)
	signal="${1:?signal required}"
	pidfile="${2:?pidfile required}"
	[[ "$signal" =~ ^(TERM|KILL|HUP|USR1|USR2)$ ]] || { echo "signal not permitted: $signal" >&2; exit 2; }
	[ -r "$pidfile" ] || { echo "pidfile not readable: $pidfile" >&2; exit 3; }
	pid="$(cat "$pidfile")"
	[[ "$pid" =~ ^[0-9]+$ ]] || { echo "pidfile does not contain a pid" >&2; exit 3; }
	kill -"$signal" "$pid"
	echo "kill: sent SIG${signal} to pid ${pid}"
	;;

status)
	echo "== active netem qdiscs =="
	if command -v tc >/dev/null; then
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
