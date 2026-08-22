#!/bin/bash
# geth + beacon ONLY for the conet-l0d MVP lab on 74.208.224.45.
# Does NOT start validator. Does NOT wipe datadir. Does NOT geth init.
# Do not run leftover 06_restart_node22445.sh start (that script starts validator).
#
# L0_ONLY=1 (or $LAB_DIR/run/l0-only.env): no public bootnodes,
# --nodiscover / beacon --no-discovery (unless L0_DHT=1), overlay bootnode/peer to .98 only,
# INPUT+OUTPUT isolate chain CONET_L0D_P2P_ISOLATE* (never touch CONET_L0D).
# L0_ONLY advertises the overlay vIP (100.64.0.5). Do not bind RPC to it.
# L0_DHT=1 (lab comms test): drop beacon --no-discovery; do NOT pull public :4110 ENRs.
# With L0_DHT_BOOTSTRAP_ENR set, drop the static overlay --peer so discv5 is the
# only beacon path. Allowlist is overlay plus the DHT hub public /32 so Prysm can
# dial the public ENR; overlay-dht-steer.sh must DNAT that IP :4300/:4200 onto
# 100.64.0.6 (fail-closed if missing). Isolate still DROPs unsteered public P2P.
# Requires overlay listen DNAT/SNAT on the public-advertise peer. Does not close
# the P1 follow-the-chain gate. Crate already carries IPv4/UDP.
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-/home/peter/ethereum-pos-mainnet}"
NODE_DIR="${NODE_DIR:-$PROJECT_DIR/network/node-0}"
LAB_DIR="${LAB_DIR:-/home/peter/conet-l0d-lab}"
# Preserve explicit operator overrides before loading host defaults.  The
# source files contain lab fallbacks and must never replace a command-line
# stream peer selected for this restart.
EXPLICIT_BEACON_PEERS_SET="${EXTRA_BEACON_PEERS+x}"
EXPLICIT_BEACON_PEERS="${EXTRA_BEACON_PEERS:-}"
EXPLICIT_OVERLAY_BEACON_PEER_SET="${L0_OVERLAY_BEACON_PEER+x}"
EXPLICIT_OVERLAY_BEACON_PEER="${L0_OVERLAY_BEACON_PEER:-}"
# Canonical hub beacon IDs (--peer). Do not curl .98 :4100 for identity.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/l1-beacon-static-peers.env" ]]; then
	# shellcheck disable=SC1091
	source "$SCRIPT_DIR/l1-beacon-static-peers.env"
elif [[ -f "$LAB_DIR/scripts/l1-beacon-static-peers.env" ]]; then
	# shellcheck disable=SC1091
	source "$LAB_DIR/scripts/l1-beacon-static-peers.env"
fi
# Production hub overlay constants (216.225.202.82 / 100.64.0.7); override via env.
if [[ -f "$LAB_DIR/scripts/l0-prod82-hub.env" ]]; then
	# shellcheck disable=SC1091
	source "$LAB_DIR/scripts/l0-prod82-hub.env"
fi
# Optional dual-hub (.98 VIP). Default lab uses l0-dual-hub.env.disabled —
# SI exclusive occupy cannot mesh .45↔.82↔.98; enabling causes dial backoff.
if [[ -f "$LAB_DIR/scripts/l0-dual-hub.env" ]]; then
	# shellcheck disable=SC1091
	source "$LAB_DIR/scripts/l0-dual-hub.env"
fi
PUBLIC_IP="${PUBLIC_IP:-74.208.224.45}"
CHAIN_ID="${CHAIN_ID:-224422}"

GETH_BINARY="${GETH_BINARY:-$PROJECT_DIR/dependencies/go-ethereum-latest/build/bin/geth}"
PRYSM_BEACON_BINARY="${PRYSM_BEACON_BINARY:-$PROJECT_DIR/dependencies/prysm-v7.1.4/beacon-chain}"

JWT_SECRET_FILE="${JWT_SECRET_FILE:-$NODE_DIR/execution/jwtsecret}"
CONSENSUS_GENESIS="${CONSENSUS_GENESIS:-$NODE_DIR/consensus/genesis.ssz}"
CHAIN_CONFIG_FILE="${CHAIN_CONFIG_FILE:-$NODE_DIR/consensus/config.yml}"

GETH_HTTP_PORT="${GETH_HTTP_PORT:-8545}"
GETH_AUTH_RPC_PORT="${GETH_AUTH_RPC_PORT:-8200}"
GETH_P2P_PORT="${GETH_P2P_PORT:-8400}"
GETH_CACHE="${GETH_CACHE:-256}"

PRYSM_BEACON_RPC_PORT="${PRYSM_BEACON_RPC_PORT:-4000}"
PRYSM_BEACON_GRPC_GATEWAY_PORT="${PRYSM_BEACON_GRPC_GATEWAY_PORT:-4100}"
PRYSM_BEACON_P2P_TCP_PORT="${PRYSM_BEACON_P2P_TCP_PORT:-4200}"
PRYSM_BEACON_P2P_UDP_PORT="${PRYSM_BEACON_P2P_UDP_PORT:-4300}"

# L0_ONLY defaults advertise to the overlay vIP. Public P2P keeps PUBLIC_IP.
# Operator may export ADVERTISE_IP to override. Do not bind RPC to the vIP.
L0_OVERLAY_VIP="${L0_OVERLAY_VIP:-100.64.0.5}"
FEE_RECIPIENT="${FEE_RECIPIENT:-0x0981275553A41E00ec1006fe074971285E00c2A3}"
DEPOSIT_CONTRACT_ADDRESS="${DEPOSIT_CONTRACT_ADDRESS:-0x4242424242424242424242424242424242424242}"

# Live EL bootnodes from l1-node.md (2026-08-17) plus the .98 lab peer.
# Do not use leftover 192.76 / old .50 id.
LAB_98_ENODE="${LAB_98_ENODE:-enode://006561987aaeea06a6f2c54d37656a4acccd0c1e16c9025700be1cfc45c6b79596293426694f0cf5eccacc1f92392628a93adb52c607b86b78f8601e5247459b@198.251.77.98:8400}"
HUB_BOOTNODES="${HUB_BOOTNODES:-enode://e5fe89d9ad924db6e4699480242a12fccba2c00e35772db706e46190c0ded9bb2b7e0d996826f5e46d369e01336213ef263c5038f94552e5f5e6e8ec76573a3f@38.102.126.30:8400,enode://d9243095bca94720f88d38c93ae4ccefc8b67651c66b4c93c915f845f6abfd39a091465db02db32b1a5b8061566c1558d2e6842f75620bf533480bab8a180168@38.102.126.50:8400,enode://5cf9a159e641318cda27e6bc1b4185667c0cdb1b54c3df5b8626eacbacea93af64c243dbdd09b40c62ba24792d0afc571cf17cbc47a5ed5a6207f27054c01d65@216.225.202.23:8400,enode://8e09d44bb4c29543a172e53dd8a74677a2a63d3d98a3d530f9d8b6f6bd6802a542f5b79d509ff737a9a764a66ab44a81403597cb50e350178ddd91f487e28f2d@216.225.202.22:8400,enode://dc0624c81896cdec036af7096886b1629a288b4824a467038df645c5c6b0f7fe75e13758ea80c0c37ba6245b221680db1fb553d564e54b55410eb6063bb64ca0@216.225.197.3:8400,enode://f1e249c97ce861441b3bd4832213cc634dd5c23d1a8722cd9c1aea28492779f6b64e012e8d97d56006d69be5224903ea5a787d8af68e9542db82ac1f76491dd5@216.225.202.82:8400}"
EXECUTION_BOOTNODES="${EXECUTION_BOOTNODES:-${HUB_BOOTNODES},${LAB_98_ENODE}}"

# Optional *extra* static --peer (comma-separated). Primary overlay peer is
# L0_OVERLAY_BEACON_PEER (from l0-prod82-hub.env → .82 VIP). Default empty:
# do NOT auto-add .98 public/VIP — SI exclusive occupy + isolate make dual-hub
# dial backoff. Enable via l0-dual-hub.env or export EXTRA_BEACON_PEERS=...
EXTRA_BEACON_PEERS="${EXTRA_BEACON_PEERS:-}"

# Fallbacks only if l0-prod82-hub.env is missing (legacy .98-as-hub lab).
L0_OVERLAY_ENODE="${L0_OVERLAY_ENODE:-enode://006561987aaeea06a6f2c54d37656a4acccd0c1e16c9025700be1cfc45c6b79596293426694f0cf5eccacc1f92392628a93adb52c607b86b78f8601e5247459b@100.64.0.6:8400}"
L0_OVERLAY_BEACON_PEER="${L0_OVERLAY_BEACON_PEER:-/ip4/100.64.0.6/tcp/4200/p2p/16Uiu2HAmF1SXGHnne9DQTHGfgGQgje3cBV8pdSLJF25ajYKr2hvS}"
# Comma-separated extra overlay enodes (e.g. second hub @100.64.0.6 when primary is .7).
L0_EXTRA_OVERLAY_ENODES="${L0_EXTRA_OVERLAY_ENODES:-}"
L0_GETH_MAXPEERS="${L0_GETH_MAXPEERS:-}"
# Combined /tcp/4200/udp/4300 is one multiaddr; libp2p reports "no transport for protocol"
# and falls back to the hub public IP, which isolate then times out. discv5 uses ENR+steer.
L0_NETRESTRICT="${L0_NETRESTRICT:-100.64.0.0/10}"
# DHT hub defaults follow l0-prod82-hub.env when present; legacy .98 only as fallback.
L0_DHT_HUB_PUBLIC_IP="${L0_DHT_HUB_PUBLIC_IP:-198.251.77.98}"
L0_DHT_HUB_OVERLAY_VIP="${L0_DHT_HUB_OVERLAY_VIP:-100.64.0.6}"
L0_DHT_STEER_CHAIN="${L0_DHT_STEER_CHAIN:-CONET_L0D_DHT_STEER}"
L0_ONLY_ENV="${L0_ONLY_ENV:-$LAB_DIR/run/l0-only.env}"
ISOLATE_CHAIN="${ISOLATE_CHAIN:-CONET_L0D_P2P_ISOLATE}"
ISOLATE_OUT_CHAIN="${ISOLATE_OUT_CHAIN:-CONET_L0D_P2P_ISOLATE_OUT}"
TUN_IFACE="${TUN_IFACE:-conet-l0}"

if [[ -f "$L0_ONLY_ENV" ]]; then
	# shellcheck disable=SC1090
	source "$L0_ONLY_ENV"
fi
L0_ONLY="${L0_ONLY:-0}"
L0_DHT="${L0_DHT:-0}"
# Optional discv5 bootstrap. Prefer .82 :4100 ENR (works). .98 :4100 identity
# returns HTTP 500 when --no-discovery — do not treat that as a missing peer_id.
# When this ENR is set, L0_DHT drops the static overlay --peer (discv5 only).
# That is not a ban on dialing the hub public IP in the ENR: allowlist includes
# the hub /32 so libp2p can connect(); packets must still ride L0 via steer.
L0_DHT_BOOTSTRAP_ENR="${L0_DHT_BOOTSTRAP_ENR:-}"
L0_DHT_IDENTITY_URL="${L0_DHT_IDENTITY_URL:-}"
L0_DHT_NO_STATIC_PEER="${L0_DHT_NO_STATIC_PEER:-}"
L0_STREAM_ONLY="${L0_STREAM_ONLY:-0}"

if [[ -n "$EXPLICIT_BEACON_PEERS_SET" ]]; then
	EXTRA_BEACON_PEERS="$EXPLICIT_BEACON_PEERS"
fi
if [[ -n "$EXPLICIT_OVERLAY_BEACON_PEER_SET" ]]; then
	L0_OVERLAY_BEACON_PEER="$EXPLICIT_OVERLAY_BEACON_PEER"
fi

resolve_advertise_ip() {
	if [[ -n "${ADVERTISE_IP:-}" ]]; then
		return 0
	fi
	if l0_only_on; then
		ADVERTISE_IP="$L0_OVERLAY_VIP"
	else
		ADVERTISE_IP="$PUBLIC_IP"
	fi
}

DHT_ENDPOINTS=(
	38.102.126.30:4110
	38.102.126.50:4110
	216.225.202.23:4110
	216.225.202.22:4110
	216.225.197.3:4110
	216.225.202.82:4110
)

COLOCATION_WHITELIST=(
	38.102.126.30/32
	38.102.126.50/32
	216.225.202.23/32
	216.225.202.22/32
	216.225.197.3/32
	216.225.202.82/32
	74.208.224.45/32
	198.251.77.98/32
	100.64.0.0/10
)

die() { echo "ERROR: $*" >&2; exit 1; }

require_file() { [[ -f "$1" ]] || die "Missing file: $1"; }
require_dir() { [[ -d "$1" ]] || die "Missing dir: $1"; }
require_exec() { [[ -x "$1" ]] || die "Missing exec: $1"; }

pid_alive() {
	local pid="$1"
	[[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

l0_only_on() {
	[[ "${L0_ONLY}" == "1" || "${L0_ONLY}" == "true" || "${L0_ONLY}" == "yes" ]]
}

l0_dht_on() {
	[[ "${L0_DHT}" == "1" || "${L0_DHT}" == "true" || "${L0_DHT}" == "yes" ]]
}

stream_only_on() {
	[[ "${L0_STREAM_ONLY}" == "1" || "${L0_STREAM_ONLY}" == "true" || "${L0_STREAM_ONLY}" == "yes" ]]
}

l0_dht_no_static_peer() {
	# Explicit 0 keeps overlay --peer even when a bootstrap ENR is set.
	# Needed to recover P1 follow-the-chain if discv5-only cannot ESTAB.
	if [[ "${L0_DHT_NO_STATIC_PEER}" == "0" || "${L0_DHT_NO_STATIC_PEER}" == "false" || "${L0_DHT_NO_STATIC_PEER}" == "no" ]]; then
		return 1
	fi
	if [[ "${L0_DHT_NO_STATIC_PEER}" == "1" || "${L0_DHT_NO_STATIC_PEER}" == "true" || "${L0_DHT_NO_STATIC_PEER}" == "yes" ]]; then
		return 0
	fi
	# Default: if we have a bootstrap ENR, abandon static --peer and use discv5.
	[[ -n "${L0_DHT_BOOTSTRAP_ENR:-}" && "${L0_DHT_BOOTSTRAP_ENR}" == enr:* ]]
}

require_overlay_tun() {
	ip -4 addr show dev "$TUN_IFACE" 2>/dev/null | grep -q '100.64.0.5' \
		|| die "TUN $TUN_IFACE is not up with 100.64.0.5; start conet-l0d first"
	ip route show | grep -q "100.64.0.0/10 dev $TUN_IFACE" \
		|| die "overlay route 100.64.0.0/10 via $TUN_IFACE is missing"
}

# L0_DHT allowlists the hub public IP so Prysm can dial the ENR. Without steer,
# isolate DROPs that public :4200/:4300 and sync stalls. Fail closed.
require_l0_dht_steer() {
	local rules
	rules="$(sudo -n iptables -t nat -S "$L0_DHT_STEER_CHAIN" 2>/dev/null || true)"
	[[ -n "$rules" ]] || die "L0_DHT: missing $L0_DHT_STEER_CHAIN; run overlay-dht-steer.sh first"
	[[ "$rules" == *"-d ${L0_DHT_HUB_PUBLIC_IP}"* ]] \
		|| die "L0_DHT: $L0_DHT_STEER_CHAIN does not match hub $L0_DHT_HUB_PUBLIC_IP; run overlay-dht-steer.sh"
	[[ "$rules" == *"-p udp"* && "$rules" == *"--dport ${PRYSM_BEACON_P2P_UDP_PORT}"* && "$rules" == *"--to-destination ${L0_DHT_HUB_OVERLAY_VIP}:${PRYSM_BEACON_P2P_UDP_PORT}"* ]] \
		|| die "L0_DHT: $L0_DHT_STEER_CHAIN has no UDP :${PRYSM_BEACON_P2P_UDP_PORT} DNAT -> ${L0_DHT_HUB_OVERLAY_VIP}; run overlay-dht-steer.sh"
	[[ "$rules" == *"-p tcp"* && "$rules" == *"--dport ${PRYSM_BEACON_P2P_TCP_PORT}"* && "$rules" == *"--to-destination ${L0_DHT_HUB_OVERLAY_VIP}:${PRYSM_BEACON_P2P_TCP_PORT}"* ]] \
		|| die "L0_DHT: $L0_DHT_STEER_CHAIN has no TCP :${PRYSM_BEACON_P2P_TCP_PORT} DNAT -> ${L0_DHT_HUB_OVERLAY_VIP}; run overlay-dht-steer.sh"
	echo "OK  L0_DHT steer $L0_DHT_HUB_PUBLIC_IP :${PRYSM_BEACON_P2P_UDP_PORT}/udp :${PRYSM_BEACON_P2P_TCP_PORT}/tcp -> $L0_DHT_HUB_OVERLAY_VIP"
}

write_l0_only_env() {
	mkdir -p "$(dirname "$L0_ONLY_ENV")"
	{
		echo "L0_ONLY=1"
		if l0_dht_on; then
			echo "L0_DHT=1"
			if [[ -n "${L0_DHT_BOOTSTRAP_ENR:-}" ]]; then
				printf "L0_DHT_BOOTSTRAP_ENR='%s'\n" "${L0_DHT_BOOTSTRAP_ENR//\'/}"
			fi
			if l0_dht_no_static_peer; then
				echo "L0_DHT_NO_STATIC_PEER=1"
			else
				# Recovery only: keep overlay --peer + discv5. Not the accepted DHT path.
				echo "L0_DHT_NO_STATIC_PEER=0"
				printf "L0_OVERLAY_BEACON_PEER='%s'\n" "${L0_OVERLAY_BEACON_PEER//\'/}"
			fi
		fi
	} > "$L0_ONLY_ENV"
	L0_ONLY=1
	unset ADVERTISE_IP
	resolve_advertise_ip
	echo "Wrote $L0_ONLY_ENV (watchdog start-geth will stay isolated; advertise=$ADVERTISE_IP l0_dht=$(l0_dht_on && echo 1 || echo 0))"
}

write_l0_dht_env() {
	L0_DHT=1
	write_l0_only_env
}

load_l0_dht_bootstrap() {
	BOOTSTRAP_ARGS=()
	local json enr
	if [[ -n "${L0_DHT_BOOTSTRAP_ENR:-}" ]]; then
		enr="$L0_DHT_BOOTSTRAP_ENR"
		if [[ "$enr" == enr:* ]]; then
			echo "OK  L0_DHT bootstrap ENR from env"
			BOOTSTRAP_ARGS+=(--bootstrap-node="$enr")
			return 0
		fi
		echo "WARN L0_DHT_BOOTSTRAP_ENR is not an enr:* value"
	fi
	if [[ -n "${L0_DHT_IDENTITY_URL:-}" ]]; then
		json="$(curl -s --connect-timeout 6 -m 8 "$L0_DHT_IDENTITY_URL" || true)"
		enr="$(printf '%s' "$json" | python3 -c 'import sys,json
try:
 d=json.load(sys.stdin).get("data") or {}
 print(d.get("enr") or "")
except Exception:
 print("")' 2>/dev/null || true)"
		if [[ "$enr" == enr:* ]]; then
			echo "OK  L0_DHT identity $L0_DHT_IDENTITY_URL"
			BOOTSTRAP_ARGS+=(--bootstrap-node="$enr")
			return 0
		fi
		echo "WARN $L0_DHT_IDENTITY_URL: no ENR"
	fi
	echo "L0_DHT: no extra bootstrap ENR; discovery will use the overlay TCP peer after steer"
}

# Dedicated isolate chains. Never flush or jump CONET_L0D (owned by conet-l0d).
apply_p2p_isolate() {
	[[ "$ISOLATE_CHAIN" != "CONET_L0D" ]] || die "refuse to hijack CONET_L0D"
	[[ "$ISOLATE_OUT_CHAIN" != "CONET_L0D" ]] || die "refuse to hijack CONET_L0D"
	require_overlay_tun
	sudo -n iptables -N "$ISOLATE_CHAIN" 2>/dev/null || true
	sudo -n iptables -F "$ISOLATE_CHAIN"
	sudo -n iptables -A "$ISOLATE_CHAIN" -i lo -j RETURN
	sudo -n iptables -A "$ISOLATE_CHAIN" -i "$TUN_IFACE" -j RETURN
	sudo -n iptables -A "$ISOLATE_CHAIN" -d "$L0_NETRESTRICT" -j RETURN
	local port
	for port in 8400 4200 4300 13000; do
		sudo -n iptables -A "$ISOLATE_CHAIN" -p tcp --dport "$port" -j DROP
		sudo -n iptables -A "$ISOLATE_CHAIN" -p udp --dport "$port" -j DROP
	done
	if ! sudo -n iptables -C INPUT -j "$ISOLATE_CHAIN" 2>/dev/null; then
		sudo -n iptables -I INPUT 1 -j "$ISOLATE_CHAIN"
	fi

	sudo -n iptables -N "$ISOLATE_OUT_CHAIN" 2>/dev/null || true
	sudo -n iptables -F "$ISOLATE_OUT_CHAIN"
	sudo -n iptables -A "$ISOLATE_OUT_CHAIN" -o lo -j RETURN
	sudo -n iptables -A "$ISOLATE_OUT_CHAIN" -o "$TUN_IFACE" -j RETURN
	sudo -n iptables -A "$ISOLATE_OUT_CHAIN" -d "$L0_NETRESTRICT" -j RETURN
	for port in 8400 4200 4300 13000; do
		sudo -n iptables -A "$ISOLATE_OUT_CHAIN" -p tcp --dport "$port" -j DROP
		sudo -n iptables -A "$ISOLATE_OUT_CHAIN" -p udp --dport "$port" -j DROP
	done
	if ! sudo -n iptables -C OUTPUT -j "$ISOLATE_OUT_CHAIN" 2>/dev/null; then
		sudo -n iptables -I OUTPUT 1 -j "$ISOLATE_OUT_CHAIN"
	fi
	# Leftover filter OUTPUT DROP of overlay :8400 sits *before* isolate RETURN
	# and kills geth static-nodes (lab 2026-08-18: 8k+ packets). Never touch CONET_L0D.
	local overlay_vip
	for overlay_vip in 100.64.0.5 100.64.0.6; do
		sudo -n iptables -D OUTPUT -d "${overlay_vip}/32" -p tcp --dport 8400 -j DROP 2>/dev/null || true
		sudo -n iptables -D OUTPUT -d "${overlay_vip}/32" -p udp --dport 8400 -j DROP 2>/dev/null || true
	done
	echo "P2P isolate on ($ISOLATE_CHAIN / $ISOLATE_OUT_CHAIN); CONET_L0D untouched"
}

remove_p2p_isolate() {
	sudo -n iptables -D INPUT -j "$ISOLATE_CHAIN" 2>/dev/null || true
	sudo -n iptables -D OUTPUT -j "$ISOLATE_OUT_CHAIN" 2>/dev/null || true
	sudo -n iptables -F "$ISOLATE_CHAIN" 2>/dev/null || true
	sudo -n iptables -X "$ISOLATE_CHAIN" 2>/dev/null || true
	sudo -n iptables -F "$ISOLATE_OUT_CHAIN" 2>/dev/null || true
	sudo -n iptables -X "$ISOLATE_OUT_CHAIN" 2>/dev/null || true
	rm -f "$L0_ONLY_ENV"
	L0_ONLY=0
	if [[ "${ADVERTISE_IP:-}" == "$L0_OVERLAY_VIP" ]]; then
		unset ADVERTISE_IP
	fi
	resolve_advertise_ip
	echo "P2P isolate off; removed $L0_ONLY_ENV; advertise=$ADVERTISE_IP"
}

stop_pid_file() {
	local name="$1"
	local pid_file="$2"
	local wait_secs="${3:-30}"
	[[ -f "$pid_file" ]] || return 0
	local pid
	pid="$(cat "$pid_file" 2>/dev/null || true)"
	if pid_alive "$pid"; then
		echo "Stopping $name pid=$pid (SIGTERM, wait ${wait_secs}s)"
		kill "$pid" 2>/dev/null || true
		local i
		for ((i = 1; i <= wait_secs; i++)); do
			pid_alive "$pid" || { rm -f "$pid_file"; echo "$name exited after ${i}s"; return 0; }
			sleep 1
		done
		echo "WARN $name still alive after SIGTERM; sending SIGKILL"
		kill -9 "$pid" 2>/dev/null || true
		sleep 2
	fi
	rm -f "$pid_file"
}

stop_geth() {
	echo "Stopping geth only (beacon/validator untouched, data preserved)"
	stop_pid_file geth "$NODE_DIR/geth.pid" 90
}

wait_for_port() {
	local host="$1" port="$2" name="$3" retries="${4:-90}"
	echo "Waiting for $name at $host:$port ..."
	for ((i = 1; i <= retries; i++)); do
		if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
			echo "$name is up"
			return 0
		fi
		sleep 1
	done
	echo "Warning: $name did not open $host:$port"
	return 1
}

load_bootstrap_args() {
	BOOTSTRAP_ARGS=()
	local ep json enr
	for ep in "${DHT_ENDPOINTS[@]}"; do
		json="$(curl -s --connect-timeout 6 -m 8 "http://${ep}/eth/v1/node/identity" || true)"
		enr="$(printf '%s' "$json" | python3 -c 'import sys,json
try:
 d=json.load(sys.stdin).get("data") or {}
 print(d.get("enr") or "")
except Exception:
 print("")' 2>/dev/null || true)"
		if [[ "$enr" == enr:* ]]; then
			echo "OK  $ep"
			BOOTSTRAP_ARGS+=(--bootstrap-node="$enr")
		else
			echo "WARN $ep: no ENR"
		fi
	done
	((${#BOOTSTRAP_ARGS[@]} > 0)) || die "No live DHT ENRs from :4110"
}

load_extra_beacon_peers() {
	[[ -n "${EXTRA_BEACON_PEERS:-}" ]] || return 0
	local IFS=','
	local peer
	for peer in $EXTRA_BEACON_PEERS; do
		peer="${peer//[[:space:]]/}"
		[[ -n "$peer" ]] || continue
		if [[ "$peer" == *"/tcp/"*"/udp/"* ]]; then
			die "refusing combined /tcp/.../udp/... --peer ($peer); libp2p has no transport for that multiaddr. Use /ip4/<vip>/tcp/4200/p2p/<id>"
		fi
		echo "OK  extra beacon peer $peer"
		PEER_ARGS+=(--peer="$peer")
	done
}

merge_beacon_overlay_peers() {
	local saved="${EXTRA_BEACON_PEERS:-}"
	PEER_ARGS=()
	[[ -n "${L0_OVERLAY_BEACON_PEER:-}" ]] && PEER_ARGS+=(--peer="$L0_OVERLAY_BEACON_PEER")
	EXTRA_BEACON_PEERS="$saved"
	load_extra_beacon_peers
}

l0_overlay_enode_list() {
	local out=("$L0_OVERLAY_ENODE")
	if [[ -n "${L0_EXTRA_OVERLAY_ENODES:-}" ]]; then
		local IFS=','
		local e
		for e in $L0_EXTRA_OVERLAY_ENODES; do
			e="${e//[[:space:]]/}"
			[[ -n "$e" ]] && out+=("$e")
		done
	fi
	printf '%s\n' "${out[@]}"
}

write_l0_static_nodes() {
	local static_file="$NODE_DIR/execution/geth/static-nodes.json"
	mkdir -p "$(dirname "$static_file")"
	local enodes=()
	while IFS= read -r line; do
		[[ -n "$line" ]] && enodes+=("$line")
	done < <(l0_overlay_enode_list)
	local json='['
	local i
	for i in "${!enodes[@]}"; do
		[[ "$i" -gt 0 ]] && json+=','
		json+="\"${enodes[$i]}\""
	done
	json+=']'
	printf '%s\n' "$json" > "$static_file"
	echo "Wrote $static_file (${#enodes[@]} overlay enode(s))"
}

add_geth_overlay_peers() {
	local enode
	while IFS= read -r enode; do
		[[ -n "$enode" ]] || continue
		curl -s "http://127.0.0.1:${GETH_HTTP_PORT}" -H 'content-type: application/json' \
			-d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_addPeer\",\"params\":[\"$enode\"]}" \
			>/dev/null || true
	done < <(l0_overlay_enode_list)
}

start_geth() {
	local bootnodes extra=()
	if l0_only_on; then
		require_overlay_tun
		apply_p2p_isolate
		write_l0_static_nodes
		# --nodiscover does not dial --bootnodes; persist the overlay peer as static.
		bootnodes="$L0_OVERLAY_ENODE"
		local maxpeers="${L0_GETH_MAXPEERS:-2}"
		if [[ -n "${L0_EXTRA_OVERLAY_ENODES:-}" ]]; then
			maxpeers="${L0_GETH_MAXPEERS:-4}"
		fi
		extra+=(--nodiscover --netrestrict "$L0_NETRESTRICT" --maxpeers "$maxpeers")
		echo "Starting geth L0_ONLY advertise=$ADVERTISE_IP overlay-static=$bootnodes extra=${L0_EXTRA_OVERLAY_ENODES:-none} maxpeers=$maxpeers"
	else
		bootnodes="$EXECUTION_BOOTNODES"
		echo "Starting geth advertise=$ADVERTISE_IP cache=$GETH_CACHE (no wipe)"
	fi
	nohup "$GETH_BINARY" \
		--datadir "$NODE_DIR/execution" \
		--state.scheme=hash \
		--networkid "$CHAIN_ID" \
		--port "$GETH_P2P_PORT" \
		--discovery.port "$GETH_P2P_PORT" \
		--bootnodes "$bootnodes" \
		--nat "extip:$ADVERTISE_IP" \
		--cache "$GETH_CACHE" \
		"${extra[@]}" \
		--http \
		--http.addr 127.0.0.1 \
		--http.port "$GETH_HTTP_PORT" \
		--http.api eth,net,web3,admin \
		--http.vhosts localhost \
		--authrpc.addr 127.0.0.1 \
		--authrpc.port "$GETH_AUTH_RPC_PORT" \
		--authrpc.vhosts localhost \
		--authrpc.jwtsecret "$JWT_SECRET_FILE" \
		--syncmode full \
		--gcmode full \
		> "$NODE_DIR/logs/geth.log" 2>&1 &
	echo $! > "$NODE_DIR/geth.pid"
	wait_for_port 127.0.0.1 "$GETH_AUTH_RPC_PORT" geth-authrpc 120 || true
	wait_for_port 127.0.0.1 "$GETH_HTTP_PORT" geth-http 30 || true
	if l0_only_on; then
		add_geth_overlay_peers
	fi
}

start_beacon() {
	local extra=()
	if stream_only_on; then
		# Duplex stream mode uses the local TCP bridge (for example
		# 127.0.0.1:14200).  It intentionally has no TUN, iptables,
		# discovery bootstrap, or DHT steering dependency.
		BOOTSTRAP_ARGS=()
		PEER_ARGS=()
		load_extra_beacon_peers
		extra+=(--disable-quic --no-discovery --p2p-max-peers=4 --min-sync-peers=1)
		echo "Starting beacon L0_STREAM_ONLY peer=${EXTRA_BEACON_PEERS:-none} (no TUN/iptables/discovery)"
	elif l0_only_on; then
		require_overlay_tun
		apply_p2p_isolate
		BOOTSTRAP_ARGS=()
		if l0_dht_on; then
			if l0_dht_no_static_peer; then
				EXTRA_BEACON_PEERS=""
				PEER_ARGS=()
				echo "L0_DHT: no static --peer; discv5 via bootstrap ENR + overlay steer"
			else
				merge_beacon_overlay_peers
			fi
		else
			merge_beacon_overlay_peers
		fi
		extra+=(--disable-quic --p2p-max-peers=4 --min-sync-peers=1)
		if l0_dht_on; then
			require_l0_dht_steer
			# Prysm v7.1.4 parses one CIDR per --p2p-allowlist (comma is FATAL).
			# Last flag wins. Successful DHT dials the hub public ENR, so hub /32
			# must be last. Steer still DNATs that dest onto L0. Do not --peer the
			# overlay VIP: last-wins would gater-block 100.64.0.6.
			extra+=(--p2p-allowlist="$L0_NETRESTRICT")
			extra+=(--p2p-allowlist="${L0_DHT_HUB_PUBLIC_IP}/32")
			load_l0_dht_bootstrap
			if ((${#BOOTSTRAP_ARGS[@]} == 0)) && l0_dht_no_static_peer; then
				die "L0_DHT abandoned static --peer but has no bootstrap ENR; set L0_DHT_BOOTSTRAP_ENR"
			fi
			echo "Starting beacon L0_ONLY+L0_DHT advertise=$ADVERTISE_IP allowlist=$L0_NETRESTRICT then ${L0_DHT_HUB_PUBLIC_IP}/32 (last wins; dial public ENR) overlay-peer=${EXTRA_BEACON_PEERS:-none} (discv5 on; no public :4110)"
		else
			extra+=(--p2p-allowlist="$L0_NETRESTRICT")
			extra+=(--no-discovery)
			echo "Starting beacon L0_ONLY advertise=$ADVERTISE_IP overlay-peers=${#PEER_ARGS[@]} (no-discovery)"
		fi
	else
		echo "Starting beacon advertise=$ADVERTISE_IP (no validator)"
		load_bootstrap_args
		load_extra_beacon_peers
		extra+=(--p2p-max-peers=40 --min-sync-peers=1)
	fi
	local wl=()
	local cidr
	for cidr in "${COLOCATION_WHITELIST[@]}"; do
		wl+=(--p2p-colocation-whitelist="$cidr")
	done
	nohup "$PRYSM_BEACON_BINARY" \
		--datadir="$NODE_DIR/consensus/beacondata" \
		--accept-terms-of-use \
		--genesis-state="$CONSENSUS_GENESIS" \
		--chain-config-file="$CHAIN_CONFIG_FILE" \
		--execution-endpoint="http://127.0.0.1:${GETH_AUTH_RPC_PORT}" \
		--jwt-secret="$JWT_SECRET_FILE" \
		--chain-id="$CHAIN_ID" \
		"${BOOTSTRAP_ARGS[@]}" \
		"${wl[@]}" \
		"${PEER_ARGS[@]}" \
		"${extra[@]}" \
		--rpc-host=127.0.0.1 \
		--rpc-port="$PRYSM_BEACON_RPC_PORT" \
		--grpc-gateway-host=127.0.0.1 \
		--grpc-gateway-port="$PRYSM_BEACON_GRPC_GATEWAY_PORT" \
		--p2p-tcp-port="$PRYSM_BEACON_P2P_TCP_PORT" \
		--p2p-udp-port="$PRYSM_BEACON_P2P_UDP_PORT" \
		--p2p-host-ip="$ADVERTISE_IP" \
		--p2p-static-id \
		--disable-staking-contract-check \
		--suggested-fee-recipient="$FEE_RECIPIENT" \
		--contract-deployment-block=0 \
		--deposit-contract="$DEPOSIT_CONTRACT_ADDRESS" \
		--eth1-header-req-limit=512 \
		> "$NODE_DIR/logs/beacon.log" 2>&1 &
	echo $! > "$NODE_DIR/beacon.pid"
	wait_for_port 127.0.0.1 "$PRYSM_BEACON_GRPC_GATEWAY_PORT" beacon-gateway 120 || true
}

stop_clients() {
	echo "Stopping geth + beacon only (validator untouched, data preserved)"
	stop_pid_file beacon "$NODE_DIR/beacon.pid"
	stop_pid_file geth "$NODE_DIR/geth.pid"
	# Never pkill leftover validator.
}

show_status() {
	if l0_only_on; then
		echo "mode: L0_ONLY isolate=$ISOLATE_CHAIN advertise=$ADVERTISE_IP"
	else
		echo "mode: public-p2p advertise=$ADVERTISE_IP"
	fi
	for name in geth beacon; do
		local pid_file="$NODE_DIR/${name}.pid"
		if [[ -f "$pid_file" ]]; then
			local pid
			pid="$(cat "$pid_file" 2>/dev/null || true)"
			if pid_alive "$pid"; then
				echo "$name: running pid=$pid"
			else
				echo "$name: pid file stale"
			fi
		else
			echo "$name: not running"
		fi
	done
	if [[ -f "$NODE_DIR/validator.pid" ]]; then
		local vpid
		vpid="$(cat "$NODE_DIR/validator.pid" 2>/dev/null || true)"
		if pid_alive "$vpid"; then
			echo "validator: UNEXPECTED running pid=$vpid (should be off on this host)"
		else
			echo "validator: stopped (stale pid file ok)"
		fi
	else
		echo "validator: not started (expected)"
	fi
	if curl -sf "http://127.0.0.1:${GETH_HTTP_PORT}" >/dev/null 2>&1; then
		curl -s "http://127.0.0.1:${GETH_HTTP_PORT}" -H 'content-type: application/json' \
			-d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}'
		echo
		curl -s "http://127.0.0.1:${GETH_HTTP_PORT}" -H 'content-type: application/json' \
			-d '{"jsonrpc":"2.0","id":2,"method":"net_peerCount","params":[]}'
		echo
	fi
	if curl -sf "http://127.0.0.1:${PRYSM_BEACON_GRPC_GATEWAY_PORT}/eth/v1/node/syncing" >/dev/null 2>&1; then
		curl -s "http://127.0.0.1:${PRYSM_BEACON_GRPC_GATEWAY_PORT}/eth/v1/node/syncing"
		echo
		curl -s "http://127.0.0.1:${PRYSM_BEACON_GRPC_GATEWAY_PORT}/eth/v1/node/peer_count"
		echo
	fi
}

ACTION="${1:-start}"
resolve_advertise_ip
mkdir -p "$NODE_DIR/logs" "$LAB_DIR/run"
require_exec "$GETH_BINARY"
require_exec "$PRYSM_BEACON_BINARY"
require_dir "$NODE_DIR/execution/geth/chaindata"
require_file "$JWT_SECRET_FILE"
require_file "$CONSENSUS_GENESIS"
require_file "$CHAIN_CONFIG_FILE"

case "$ACTION" in
start)
	stop_clients
	start_geth
	start_beacon
	show_status
	echo "Started geth+beacon only. L0_ONLY advertises $ADVERTISE_IP (RPC stays on 127.0.0.1)."
	;;
stop)
	stop_clients
	;;
restart)
	stop_clients
	start_geth
	start_beacon
	show_status
	;;
start-geth)
	stop_geth
	start_geth
	show_status
	;;
stop-geth)
	stop_geth
	show_status
	;;
restart-beacon)
	stop_pid_file beacon "$NODE_DIR/beacon.pid"
	start_beacon
	show_status
	;;
start-l0-only|restart-l0-only)
	write_l0_only_env
	require_overlay_tun
	apply_p2p_isolate
	stop_clients
	start_geth
	start_beacon
	show_status
	;;
stop-isolate)
	remove_p2p_isolate
	echo "Isolate removed. Clients were not restarted; run $0 restart for public P2P."
	;;
status)
	show_status
	;;
enable-l0-dht)
	write_l0_dht_env
	echo "L0_DHT env written. Apply overlay-dht-steer.sh on this host and overlay-beacon-listen-dnat.sh on the public-advertise peer."
	echo "Beacon still has --no-discovery until an authorized restart-beacon. This script did not restart EL/CL."
	echo "If beacon connected later drops: overlay-dht-steer.sh apply first (flush ghost conntrack; do not restart EL/CL)."
	;;
apply-isolate)
	require_overlay_tun
	apply_p2p_isolate
	echo "Isolate refreshed. Clients were not restarted."
	;;
*)
	echo "Usage: $0 {start|stop|restart|status|start-geth|stop-geth|restart-beacon|start-l0-only|restart-l0-only|stop-isolate|enable-l0-dht|apply-isolate}"
	exit 1
	;;
esac
