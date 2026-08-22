# geth / beacon advertise flags

These flags **advertise** an overlay IP. They do not bind RPC or Engine to that IP.

Do not run `iptables` yourself. `conet-l0d start` / `stop` owns the chain.

```bash
# Authorized L0_ONLY .45 advertises the overlay vIP.
# .98 and production proposers keep the public IP.
# Slot-critical cutover is unpublished until the GitBook publication gate
# (RTT P50/P95/P99, prop, attest delay, missed slots, reorgs, reconnect,
# Guardian failover, discv5 loss) is filled vs public P2P.

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

`--peer` / overlay enode hosts are **overlay VIPs only**. L0 toml uses the wallet locator; Prysm Identify may still list the hub public `/ip4/<public>/tcp/4200` — L0_ONLY allowlist gater deny is expected. Do **not** write `/ip4/<public-ip>/tcp/4200` as `--peer`. Geth `admin_peers` must be `100.64.0.x:8400`, not the public IP. Dual hub: second `--peer` from `scripts/l1-beacon-static-peers.env` (`.82` `/ip4/100.64.0.7/tcp/4200/p2p/16Uiu2HAmDJCHuVkXtkPrrL8YykQ9gFZnQkR9Q6WjZZUrmueohPfd`, `.98` `/ip4/100.64.0.6/tcp/4200/p2p/16Uiu2HAmF1SXGHnne9DQTHGfgGQgje3cBV8pdSLJF25ajYKr2hvS`). Do **not** refresh those IDs from `.98` `:4100` (HTTP 500 / nil ENR when `--no-discovery`). DHT `:4110` IDs are not beacon `--peer`.

Lab DHT-port comms (`L0_DHT=1`): drop `--no-discovery`, keep `--disable-quic`, do **not** pull public `:4110` ENRs. When `L0_DHT_BOOTSTRAP_ENR` is set (read from `.82` `:4100` identity; **do not** curl `.98` `:4100` — HTTP 500 / nil ENR when `--no-discovery`), the default also drops the static overlay `--peer` so discv5 is the only beacon path. Set `L0_DHT_NO_STATIC_PEER=0` to keep overlay `--peer` **and** discv5 (P1 recovery when listen/SSE was down; not the accepted DHT path). Allowlist is `--p2p-allowlist=100.64.0.0/10` then `--p2p-allowlist=198.251.77.98/32` (Prysm v7.1.4: one CIDR per flag, last wins) so Prysm can dial the public ENR; `overlay-dht-steer.sh` must DNAT hub `:4300`/`:4200` onto `100.64.0.6` (fail-closed if missing). Isolate still DROPs unsteered public P2P. Write env with `enable-l0-dht` (no restart), then authorized `restart-beacon`. Apply steer on `.45` and `overlay-beacon-listen-dnat.sh` on **both** hosts (VIP-wide tcp/udp except `:8400`). If beacon `connected` later drops while overlay geth stays ESTAB, **re-apply `overlay-dht-steer.sh` first** (flushes ghost hub `:4200/:4300` conntrack; **do not** restart geth or beacon for that). Only if `connected` stays 0 is an authorized `.45` `restart-beacon` needed (Prysm dial backoff). After that restart, do **not** re-apply steer immediately (flushes SYN_SENT). `.45` `ss` may show ESTAB to hub public `:4200` (DNAT original dest); overlay proof is TUN `100.64.0.5` ↔ `100.64.0.6:4200` plus isolate `tcp dpt:4200` DROP = 0. First-minute `suitable=0` then `Processing blocks` is expected. EL `0x0` while `head_slot` climbs is CL lag. This is **not** `FOLLOW_OK`. The 2026-08-18 ~17:28Z lab: `.45` `connected=1` after authorized `restart-beacon`; geth pid unchanged. See [P2.md](./P2.md).

Restore public P2P: `./start-geth-beacon-only.sh stop-isolate` then a normal `restart`. Do not wipe. Do not restart `.98` unless that host is authorized.

Optional crate `[[l0.channels]]`: one routing EOA + listen SSE per overlay port (`8400` / `4200` / `4300`). Outbound encrypts to the peer user PGP for that port. Classify return-path TCP by **source** port. `:4300` is overlay IPv4, not SI `udp_relay`. Do not bind two SSEs to the same EOA. Each channel wallet must already `regiestChatRoute`.

Never set `--http.addr`, `--authrpc.addr`, `--p2p-local-ip`, or `--rpc-host` to the overlay vIP. That `bind()` fails if the TUN is down and can take Engine off loopback.

## Production hub `.82` — other geth over L0 (`:8400`)

Hub `216.225.202.82` overlay VIP is `100.64.0.7`. Geth **keeps public advertise** (`enode://f1e249c9…@216.225.202.82:8400`). Do **not** set `.82` `--nat` to `100.64.0.7` (that would break public bootnodes). listen-DNAT **excludes** geth `:8400`; overlay TCP to `100.64.0.7:8400` reaches the existing `*:8400` listen.

Overlay beacon identity is **pinned** (`scripts/l1-beacon-static-peers.env`). `.82` `06_restart_node66.sh` `start_beacon` and `.98` `start-shared-beacon-98.sh` pass `--p2p-static-id`. Keys live in `network/node-0/consensus/beacondata/network-keys` (backup **outside** `beacondata`). Overlay `--peer`: `.82` `/ip4/100.64.0.7/tcp/4200/p2p/16Uiu2HAmDJCHuVkXtkPrrL8YykQ9gFZnQkR9Q6WjZZUrmueohPfd`; `.98` `/ip4/100.64.0.6/tcp/4200/p2p/16Uiu2HAmF1SXGHnne9DQTHGfgGQgje3cBV8pdSLJF25ajYKr2hvS`. **Do not** `systemctl restart conet-node66.service` (oneshot would bounce geth+validator). `restart-beacon-clean` wipes `beacondata` and mints a new peer_id. Do **not** curl `.98` `:4100` for identity.

Other overlay geth dial the overlay enode from `scripts/l0-prod82-hub.env`:

```text
enode://f1e249c97ce861441b3bd4832213cc634dd5c23d1a8722cd9c1aea28492779f6b64e012e8d97d56006d69be5224903ea5a787d8af68e9542db82ac1f76491dd5@100.64.0.7:8400
```

1. On **`.82` toml** add a `[[peers]]` row for that spoke: locator + `vip` + `tcp_ports = [8400]` + **that spoke’s** geth user PGP (do **not** reuse hub `self-user.asc`). Route PGP may share mailbox B.
2. On the spoke toml add `.82` geth as a peer (`vip = "100.64.0.7"`, port `8400`, hub user PGP).
3. Bounce **only** `conet-l0d` **hub then spoke**. Re-apply `overlay-beacon-listen-dnat.sh apply`. Do **not** immediately `overlay-dht-steer.sh apply`. Do **not** run `start-l0-only` / `restart` (those restart geth).
4. Geth HTTP on `.82` / `.98` is **`:8889`**. If the spoke is already peered to the **same node id** on the public enode, `admin_removePeer` that public URL first, then `admin_addTrustedPeer` + `admin_addPeer` the overlay enode. Hub may add the spoke overlay enode the same way. **No geth restart.**
5. Proof: `ss` overlay `100.64.x.x` ↔ `100.64.0.7:8400` **ESTAB**; `admin_peers` `remoteAddress` is `100.64.0.7:8400`; both `conet-l0d.log` show duplex AES on `:8400`; **`geth.pid` unchanged**.

**2026-08-20:** `.45` already overlay-ESTAB to `.82`; `.98` moved from public `.82:8400` to overlay `100.64.0.7:8400` (`geth.pid` `.82`=`1222`, `.98`=`3420373`, `.45`=`971773`). This is **not** a claim that every production proposer has left public listen. Overlay ESTAB is **not** the [slot-critical publication gate](https://gitbook.conet.network/developers/l1-node.html#slot-critical-publication-gate). Per-port `[[l0.channels]]` on one mailbox B is **not** multi-Mailbox diversity.

## Lab hub `.98` — DHT-over-L0 toward `.82` (steer-only)

`.98` stays a **public discv5 hub** for `.45` (advertise `198.251.77.98`; keep `fetch_bootstrap_enrs.sh`). Do **not** apply L0_ONLY isolate or last-wins `--p2p-allowlist=216.225.202.82/32` on `.98`.

Steer dest `216.225.202.82:4300` UDP and `:4200` TCP onto overlay VIP `100.64.0.7`:

```bash
PEER_PUBLIC_IP=216.225.202.82 PEER_OVERLAY_VIP=100.64.0.7 ./overlay-dht-steer.sh apply
L0_DHT_BOOTSTRAP_ENR='enr:…' ./start-shared-beacon-98.sh enable-l0-dht
```

`enable-l0-dht` writes `~/conet-l0d-lab/run/l0-dht-82.env` and does **not** restart EL/CL. Steer does not rewrite QUIC. **2026-08-20 ~07:13Z** authorized `.98` `restart-beacon` (geth untouched): extra `--bootstrap-node` `.82` ENR, `--disable-quic`, fail-closed steer. After that restart, re-apply **listen-DNAT**, not steer immediately. Overlay TCP proof is **conntrack** overlay tuple `100.64.0.7` ↔ `100.64.0.6:4200`; `ss` may still show public dest (DNAT original dest, not a leak). REST `last_seen` may still show the `.82` public IP. **`geth.pid` must stay `3420373`.** Hybrid hub, **not** L0_ONLY, **not** `FOLLOW_OK`. Public verdict: GitBook [lab evaluation](https://gitbook.conet.network/applications/conet-l0d.html#lab-evaluation-2026-08-20-98-overlay-local-validator).

Public how-to: [Applications](https://gitbook.conet.network/applications/conet-l0d.html) · [Developers](https://gitbook.conet.network/developers/conet-l0d.html) · [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html)
