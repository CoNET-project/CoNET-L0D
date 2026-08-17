#!/bin/bash
# 15-minute load watchdog for the conet-l0d MVP lab (.45 / .98).
# When load15 > STOP_ABOVE, safely SIGTERM geth (beacon/validator untouched).
# When load15 < START_BELOW and geth is down, start geth again.
# Serial ticks only: one check/stop/start finishes before the next sleep.
# Does NOT wipe datadir. Does NOT start validator. Does NOT restart beacon.
set -euo pipefail

LAB_DIR="${LAB_DIR:-/home/peter/conet-l0d-lab}"
CLIENT_SCRIPT="${CLIENT_SCRIPT:-$LAB_DIR/start-geth-beacon-only.sh}"
PROJECT_DIR="${PROJECT_DIR:-/home/peter/ethereum-pos-mainnet}"
NODE_DIR="${NODE_DIR:-$PROJECT_DIR/network/node-0}"

STOP_ABOVE="${STOP_ABOVE:-2.11}"
START_BELOW="${START_BELOW:-1.60}"
TICK_SECONDS="${TICK_SECONDS:-60}"

LOG_DIR="${LOG_DIR:-$LAB_DIR/logs}"
LOG_FILE="${LOG_FILE:-$LOG_DIR/geth-load-watchdog.log}"
PID_FILE="${PID_FILE:-$LAB_DIR/run/geth-load-watchdog.pid}"
LOCK_FILE="${LOCK_FILE:-$LAB_DIR/run/geth-load-watchdog.lock}"

mkdir -p "$LOG_DIR" "$(dirname "$PID_FILE")"

log() {
	local line
	line="$(date -u +'%Y-%m-%dT%H:%M:%SZ') $*"
	echo "$line" >> "$LOG_FILE"
	if [[ -t 1 ]]; then
		echo "$line"
	fi
}

die() {
	log "ERROR: $*"
	exit 1
}

pid_alive() {
	local pid="$1"
	[[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

read_load15() {
	awk '{print $3}' /proc/loadavg
}

float_gt() {
	awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 > b + 0) }'
}

float_lt() {
	awk -v a="$1" -v b="$2" 'BEGIN { exit !(a + 0 < b + 0) }'
}

geth_running() {
	local pid=""
	if [[ -f "$NODE_DIR/geth.pid" ]]; then
		pid="$(cat "$NODE_DIR/geth.pid" 2>/dev/null || true)"
		if pid_alive "$pid"; then
			return 0
		fi
	fi
	return 1
}

run_client() {
	# Do not leak the flock fd into geth/beacon helpers.
	"$CLIENT_SCRIPT" "$@" 9>&-
}

tick() {
	local load15 geth_state
	load15="$(read_load15)"
	if geth_running; then
		geth_state="up"
	else
		geth_state="down"
	fi

	if [[ "$geth_state" == "up" ]] && float_gt "$load15" "$STOP_ABOVE"; then
		log "load15=$load15 > $STOP_ABOVE; safe-stop geth (beacon stays)"
		run_client stop-geth
		if geth_running; then
			log "WARN geth still running after stop-geth"
		else
			log "geth stopped; waiting for load15 < $START_BELOW before restart"
		fi
		return 0
	fi

	if [[ "$geth_state" == "down" ]] && float_lt "$load15" "$START_BELOW"; then
		log "load15=$load15 < $START_BELOW; start geth (beacon untouched)"
		run_client start-geth
		if geth_running; then
			log "geth started"
		else
			log "WARN start-geth finished but geth is not running"
		fi
		return 0
	fi

	log "idle load15=$load15 geth=$geth_state stop>$STOP_ABOVE start<$START_BELOW"
}

usage() {
	echo "Usage: $0 {start|stop|status|once}"
}

cmd_status() {
	local wpid=""
	if [[ -f "$PID_FILE" ]]; then
		wpid="$(cat "$PID_FILE" 2>/dev/null || true)"
	fi
	if pid_alive "$wpid"; then
		echo "watchdog: running pid=$wpid"
	else
		echo "watchdog: not running"
	fi
	echo "load15=$(read_load15) stop>$STOP_ABOVE start<$START_BELOW tick=${TICK_SECONDS}s"
	if [[ -x "$CLIENT_SCRIPT" ]]; then
		"$CLIENT_SCRIPT" status || true
	fi
}

cmd_stop() {
	local wpid=""
	if [[ -f "$PID_FILE" ]]; then
		wpid="$(cat "$PID_FILE" 2>/dev/null || true)"
	fi
	if pid_alive "$wpid"; then
		log "Stopping watchdog pid=$wpid"
		pkill -P "$wpid" 2>/dev/null || true
		kill "$wpid" 2>/dev/null || true
		local i
		for ((i = 1; i <= 15; i++)); do
			pid_alive "$wpid" || break
			sleep 1
		done
		if pid_alive "$wpid"; then
			kill -9 "$wpid" 2>/dev/null || true
			pkill -9 -P "$wpid" 2>/dev/null || true
		fi
	fi
	if command -v fuser >/dev/null 2>&1; then
		fuser -k "$LOCK_FILE" >/dev/null 2>&1 || true
	fi
	rm -f "$PID_FILE"
	echo "watchdog stopped"
}

cmd_loop() {
	[[ -x "$CLIENT_SCRIPT" ]] || die "Missing client script: $CLIENT_SCRIPT"
	exec 9>"$LOCK_FILE"
	if ! flock -n 9; then
		die "another watchdog already holds $LOCK_FILE"
	fi
	echo $$ > "$PID_FILE"
	trap 'rm -f "$PID_FILE"; exit 0' INT TERM
	log "watchdog start pid=$$ stop>$STOP_ABOVE start<$START_BELOW tick=${TICK_SECONDS}s"
	while true; do
		tick
		# Close flock fd in the sleeper so a killed parent cannot leave the lock held.
		sleep "$TICK_SECONDS" 9>&-
	done
}

ACTION="${1:-start}"
case "$ACTION" in
start)
	if [[ -f "$PID_FILE" ]] && pid_alive "$(cat "$PID_FILE" 2>/dev/null || true)"; then
		echo "watchdog already running pid=$(cat "$PID_FILE")"
		exit 0
	fi
	nohup "$0" run >>"$LOG_FILE" 2>&1 &
	echo $! > "$PID_FILE"
	sleep 1
	cmd_status
	;;
run)
	cmd_loop
	;;
once)
	[[ -x "$CLIENT_SCRIPT" ]] || die "Missing client script: $CLIENT_SCRIPT"
	tick
	;;
stop)
	cmd_stop
	;;
status)
	cmd_status
	;;
*)
	usage
	exit 1
	;;
esac
