# geth / beacon advertise flags

These flags **advertise** an overlay IP. They do not bind RPC or Engine to that IP.

Do not run `iptables` yourself. `conet-l0d start` / `stop` owns the chain.

```bash
# Authorized L0_ONLY .45 advertises the overlay vIP.
# .98 and production proposers keep the public IP.

geth \
  --port 8400 \
  --discovery.port 8400 \
  --nat extip:100.64.0.5 \
  --bootnodes "enode://<peer-nodekey>@100.64.0.1:8400" \
  --http --http.addr 127.0.0.1 --http.port 8545 \
  --authrpc.addr 127.0.0.1 --authrpc.port 8551 \
  --authrpc.jwtsecret ./jwtsecret

beacon-chain \
  --p2p-host-ip=100.64.0.5 \
  --p2p-static-id \
  --p2p-tcp-port=4200 \
  --p2p-udp-port=4300 \
  --rpc-host=127.0.0.1 \
  --grpc-gateway-host=127.0.0.1 \
  --execution-endpoint=http://127.0.0.1:8551
```

`--p2p-host-ip` is **advertise only**. Prysm still listens on the host public IP. A peer that stays on the public advertise path (lab `.98`) needs overlay-VIP tcp/udp DNAT/SNAT into that listen (`overlay-beacon-listen-dnat.sh`; any port except geth `:8400`). The TUN needs `accept_local` / `route_localnet` / `rp_filter=0` so DNAT to that local public listen reaches the socket. Do **not** edit daemon-owned `CONET_L0D`.

The 2026-08-18 00:17Z lab: `.45` advertises `100.64.0.5`; overlay geth and beacon TCP are ESTAB; CL initial-sync is running over overlay; EL is still `0x0`. Later crate builds dest-aggregate IPv4 and POST with concurrency 32 / queue 2048; upgrade both lab `conet-l0d` binaries together. After that binary, overlay is not the limiter; Prysm initial-sync is ~3.2 blocks/s (~15 h). Read-only watch: `scripts/watch-l0-follow.sh`. Follow-the-chain is not complete. Lab overlay UDP / DHT-port comms: `scripts/probe-l0-udp.sh`, `overlay-dht-steer.sh` (TCP `:4200` + UDP `:4300`), `L0_DHT=1` via `enable-l0-dht`. After authorized `restart-beacon` on `.45` (geth untouched; **2026-08-18 ~17:28Z**), live discv5 + libp2p TCP from `.45` to the `.98` DHT server rides L0. If `connected` later drops, `overlay-dht-steer.sh apply` first (no EL/CL restart). See [P2.md](./P2.md). Production proposers keep public P2P for the 6-second slot.

## L0_ONLY lab (authorized `.45` only)

Operator script: `scripts/start-geth-beacon-only.sh start-l0-only`. It writes `$LAB_DIR/run/l0-only.env` so the load watchdog keeps the same flags. Isolate chains are `CONET_L0D_P2P_ISOLATE` / `CONET_L0D_P2P_ISOLATE_OUT`. Do **not** edit `CONET_L0D`.

```bash
# .45 advertises overlay. Overlay boot/peer is the peer vIP.
geth --nodiscover --netrestrict 100.64.0.0/10 --maxpeers 2 \
  --nat extip:100.64.0.5 \
  --bootnodes "enode://<peer-nodekey>@100.64.0.6:8400"

beacon-chain --no-discovery --disable-quic \
  --p2p-allowlist=100.64.0.0/10 --p2p-max-peers=4 --min-sync-peers=1 \
  --p2p-host-ip=100.64.0.5 --p2p-static-id \
  --peer /ip4/100.64.0.6/tcp/4200/p2p/<peer-id>
```

Lab DHT-port comms (`L0_DHT=1`): drop `--no-discovery`, keep `--disable-quic`, do **not** pull public `:4110` ENRs. When `L0_DHT_BOOTSTRAP_ENR` is set (`.98` localhost identity after `--p2p-static-id`), the default also drops the static overlay `--peer` so discv5 is the only beacon path. Set `L0_DHT_NO_STATIC_PEER=0` to keep overlay `--peer` **and** discv5 (P1 recovery when listen/SSE was down; not the accepted DHT path). Allowlist is `--p2p-allowlist=100.64.0.0/10` then `--p2p-allowlist=198.251.77.98/32` (Prysm v7.1.4: one CIDR per flag, last wins) so Prysm can dial the public ENR; `overlay-dht-steer.sh` must DNAT hub `:4300`/`:4200` onto `100.64.0.6` (fail-closed if missing). Isolate still DROPs unsteered public P2P. Write env with `enable-l0-dht` (no restart), then authorized `restart-beacon`. Apply steer on `.45` and `overlay-beacon-listen-dnat.sh` on **both** hosts (VIP-wide tcp/udp except `:8400`). If beacon `connected` later drops while overlay geth stays ESTAB, **re-apply `overlay-dht-steer.sh` first** (flushes ghost hub `:4200/:4300` conntrack; **do not** restart geth or beacon for that). Only if `connected` stays 0 is an authorized `.45` `restart-beacon` needed (Prysm dial backoff). After that restart, do **not** re-apply steer immediately (flushes SYN_SENT). `.45` `ss` may show ESTAB to hub public `:4200` (DNAT original dest); overlay proof is TUN `100.64.0.5` ↔ `100.64.0.6:4200` plus isolate `tcp dpt:4200` DROP = 0. First-minute `suitable=0` then `Processing blocks` is expected. EL `0x0` while `head_slot` climbs is CL lag. This is **not** `FOLLOW_OK`. The 2026-08-18 ~17:28Z lab: `.45` `connected=1` after authorized `restart-beacon`; geth pid unchanged. See [P2.md](./P2.md).

Restore public P2P: `./start-geth-beacon-only.sh stop-isolate` then a normal `restart`. Do not wipe. Do not restart `.98` unless that host is authorized.

Optional crate `[[l0.channels]]`: one routing EOA + listen SSE per overlay port (`8400` / `4200` / `4300`). Outbound encrypts to the peer user PGP for that port. Classify return-path TCP by **source** port. `:4300` is overlay IPv4, not SI `udp_relay`. Do not bind two SSEs to the same EOA. Each channel wallet must already `regiestChatRoute`.

Never set `--http.addr`, `--authrpc.addr`, `--p2p-local-ip`, or `--rpc-host` to the overlay vIP. That `bind()` fails if the TUN is down and can take Engine off loopback.

Public how-to: [Applications](https://gitbook.conet.network/applications/conet-l0d.html) · [Developers](https://gitbook.conet.network/developers/conet-l0d.html) · [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html)
