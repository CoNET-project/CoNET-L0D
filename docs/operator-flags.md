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

`--p2p-host-ip` is **advertise only**. Prysm still listens on the host public IP. A peer that stays on the public advertise path (lab `.98`) needs overlay `:4200` DNAT/SNAT into that listen. Do **not** edit daemon-owned `CONET_L0D`.

The 2026-08-18 00:17Z lab: `.45` advertises `100.64.0.5`; overlay geth and beacon TCP are ESTAB; CL initial-sync is running over overlay; EL is still `0x0`. Production proposers keep public P2P for the 6-second slot.

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

Restore public P2P: `./start-geth-beacon-only.sh stop-isolate` then a normal `restart`. Do not wipe. Do not restart `.98` unless that host is authorized.

Never set `--http.addr`, `--authrpc.addr`, `--p2p-local-ip`, or `--rpc-host` to the overlay vIP. That `bind()` fails if the TUN is down and can take Engine off loopback.

Public how-to: [Applications](https://gitbook.conet.network/applications/conet-l0d.html) · [Developers](https://gitbook.conet.network/developers/conet-l0d.html) · [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html)
