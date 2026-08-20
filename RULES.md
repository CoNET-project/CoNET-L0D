# conet-l0d — subproject rules

Independent Linux command. Canonical git remote: [https://github.com/CoNET-project/CoNET-L0D](https://github.com/CoNET-project/CoNET-L0D). Do not `../..` import BeamioContract, SilentPassUI, CoNET-SI, or x402sdk.

## Product

`conet-l0d` is a userspace daemon. It creates a TUN, installs **its own** iptables/ip rules, and tears both down on stop, crash cleanup, or `teardown`. Operators must not be asked to run `iptables` by hand.

It does **not** patch geth, Prysm `beacon-chain`, or `validator`.

## Hard constraints

1. Catch only the overlay prefix (default `100.64.0.0/10`). Never REDIRECT `0.0.0.0/0:8400`.
2. First rule in the owned chain: `RETURN` `127.0.0.0/8` (Engine JWT, beacon gRPC, local RPC).
3. Never mark or capture a configured `validator` uid.
4. Routing wallet ≠ deposit keystore ≠ fee recipient. Do not read validator keys.
5. `web3://` here is a **peer locator**, not ERC-4804 content. `@beamioTag` must match exactly (`CoNET` ≠ `CONET`). No `search-users` `results[0]`.
6. Existing SI UDP forward is **not** raw OS UDP. Phase 1 = static overlay peers. The crate envelope is complete IPv4 (UDP proto 17 included). Lab UDP/DHT comms: `docs/P2.md` (overlay UDP plus live discv5 from L0_ONLY `.45` to the `.98` DHT server over L0; `L0_DHT` allowlist is overlay plus hub public `/32`; packets still DNAT onto overlay; after DNAT `.45` `ss` may show hub public `:4200`; public hub `.98` may also steer dest `.82` `:4300`/`:4200` onto overlay **without** L0_ONLY isolate; not a production product). Do not treat live `udp_relay` as OS UDP.
7. Do not use SilentPass / `SaaS_Sock5` as L1 P2P (that is egress to a public `host:port`).
8. HTTP `/post` **first body** is only `{ "data": "<armor>" }`. No hop-sig headers from this client. Optional `[l0]` defaults to **off**. An authorized lab may enable `[l0]` on host copies. Prefer **L0 occupancy pipe + application duplex**: exclusive SI `l0_listen` / `l0_connect` (or `mining` + `listenKind: "l0"`); `duplex_offer` (AES key + session `listenWallet`) to the peer **long-lived user PGP** on Chat gossip; `duplex_accept` / `duplex_reject` / AES `duplex_frame` as **AES blobs on the occupied pipe** (`payload` = standard base64 of `L0D1||IPv4`). Crate MVP session listen is the per-port channel EOA (Chat SSE **and** `l0_listen` in different pools). SI does **not** implement `duplex_*`. Overlay AES is memory-only; never put it on B-decryptable `l0_listen` / `l0_connect`. `duplex_reject` or missing `duplex_accept` **or** missing occupied pipe keeps P1 gossip. After exclusive `l0_listen` **HTTP 200 while the SSE is still live**, **rebuild** outbound `l0_connect` for already-attached duplex sessions (do **not** rebuild after the listen SSE has already died). Occupy TCP **EOF** (silent close, no `l0_pipe_end` JSON) must **clear** `pipe_tx` and **retry** the same as `Err` — a leftover `pipe_tx` makes TUN `try_send` fail as queue-full and fall to P1, which cannot complete beacon `:4200` TCP. SI replacement `l0_listen` while occupied is **409** unless inbound TCP or listen SSE is already dead/stale (then drop and accept — client restart); if occupy fails, **retry** — do not clear `pipe_tx` once and permanently fall back to P1. Install `pipe_tx` **only after** occupy HTTP 200 keep-alive. SI 409 is a **second `l0_connect`**, not Chat gossip (idle L0 may copy gossip; Chat pool always gets it). Idle `l0_listen` needs SSE comment keepalives; **occupied** L0 must **stop** those comments (AES `data:` traffic keeps the socket; a comment `\n\n` must not truncate a half-received blob). First occupied-pipe AES `duplex_accept` **omits** `listenUserPgp` (Chat accept still includes it). SSE AES frames complete on `\r\n\r\n`. Entry must `sourceSocket.setTimeout(0)` on client→C as well as not 60s-kill C→B. Entry `socketForward` must not kill C→B SSE / L0 pipes on 60s receive-idle (see GitBook peel-hop-listen / duplex-forward). Do not send `mining` + `listenKind: "duplex"`. Do not invent SI `duplex_*` or `p2p_stream_*`. Do not POST unless duplex AES+`peer_attached`+`pipe_tx` **or** the overlay is encrypted to the peer **user PGP** **and** wrapped to mailbox **B route PGP**. Do not POST plaintext JSON as `data`. Inbound decrypt + TUN write-back and listen HTTP+SSE workers may exist in-crate. Listen spawn is fail-closed: enabled plus `listen_entries` (C ≠ B; never fall back to outbound `entries`), `mailbox_route_pgp_file` (this host's B route **public** key), `routing_eoa`, `routing_key_file` (OpenPGP secret), and `routing_eth_key_file` (hex secp256k1; recovered address must match `routing_eoa`; not OpenPGP). Optional `[[l0.channels]]` uses one dedicated routing EOA + listen SSE per overlay port (8400 / 4200 / 4300); outbound encrypts to the peer user PGP for that port (classify by well-known src or dest port). Empty channels keep one EOA. `:4300` is overlay IPv4, not `udp_relay`. Do not bind two SSEs of the **same pool** to the same EOA. Listen is EIP-191 + SI `{ message, signMessage }` base64. Listen ingest must accept SI `forWardPGPMessageToClient` raw JSON `{ "data": "<armor>" }` (Chat `handleInbound`), occupy JSON (`l0_occupied`), teardown JSON (`l0_pipe_end`, `l0_listen_released`), AES blobs, duplex JSON, not only SSE `data: BEGIN PGP` lines. Tests use wiremock only. HTTP 200 on entry A is **not** by itself inbound TUN write-back. After the SI gossip JSON ingest fix, the 2026-08-17 23:30Z lab wrote inbound IPv4 on both TUNs and completed overlay geth TCP (`.45` ↔ `.98` on `100.64.0.5` / `100.64.0.6`). **2026-08-18:** authorized L0_ONLY `.45` advertises overlay vIP `100.64.0.5`; overlay geth + beacon TCP are ESTAB; dest-aggregated IPv4 + POST concurrency 32 / queue 2048 (upgrade both lab binaries together). After that binary, overlay queue-full is 0; remaining follow-the-chain limiter is Prysm initial-sync (~3.2 blocks/s, ~15 h). EL still `0x0`. Read-only watch: `scripts/watch-l0-follow.sh`. The follow-the-chain gate stays open. A separate lab UDP/DHT comms experiment ran (`docs/P2.md`): overlay UDP plus live discv5 from L0_ONLY `.45` to the `.98` DHT server over L0 (allowlist = overlay + hub `/32`; steer DNAT; isolate drops unsteered public P2P). After DNAT, `.45` `ss` may show ESTAB to hub public `:4200` — original dest, not a leak; overlay proof is TUN VIP + isolate DROP=0. If beacon `connected` drops while overlay geth stays ESTAB, re-apply `overlay-dht-steer.sh` first (flush ghost hub conntrack; **do not** restart EL/CL for that). `restart-beacon` is only for Prysm dial backoff after that flush (**2026-08-18 ~17:28Z** on `.45` restored `connected=1` and `Processing blocks`; do not re-apply steer immediately after start). **2026-08-20 ~04:09Z:** lab-only static overlay `--peer` (channels 8400+4200; no prod `.82`, no `:4300` / `L0_DHT` this run) after authorized hub-then-spoke `restart-beacon`: spoke `connected=1` outbound `/ip4/100.64.0.6/tcp/4200`; overlay ESTAB + AES on both ports; `head_slot` rose while `sync_distance` fell. After TUN bounce or a new beacon PID, re-apply **listen-DNAT** (`overlay-beacon-listen-dnat.sh`); do **not** immediately `overlay-dht-steer.sh apply`. Prove geth unchanged via **`geth.pid`**, not `pgrep -n geth` (beacon-chain argv contains the geth path). Hub public `connected` may dip to 0 then recover; `peer_id` stays static. EL `0x0` + `is_optimistic=true` while CL climbs is catch-up, not overlay failure. It does not close that gate. `.98` and production proposers keep the public IP. Production hub `.82` (`100.64.0.7`) can accept **other overlay geth on `:8400`** without changing `--nat` to the VIP; each new spoke needs its own hub `[[peers]]` user PGP and dials `scripts/l0-prod82-hub.env` overlay enode (`admin_removePeer` the public enode first if the same node id is already connected). listen-DNAT excludes `:8400`. **2026-08-20:** `.98` overlay-ESTAB to `.82:8400`; `.45` already overlay to both hubs; `geth.pid` unchanged. See `docs/operator-flags.md`.
9. Do not invent a new public hostname. Reuse existing CoNET / beamio.app paths.
10. The crate must not restart geth / beacon / validator. An authorized **operator** script may restart **only** the named lab host (`.45` L0_ONLY; `.98` `restart-beacon` only when that host is authorized in the same message). After authorized `restart-beacon`, re-apply **listen-DNAT**, not steer. Verify geth via **`geth.pid`**. Never wipe. Never mutate the daemon-owned `CONET_L0D` chain; public-P2P isolate uses `CONET_L0D_P2P_ISOLATE` / `_OUT`. Do not restart `.98` geth or any validator.
11. Do **not** claim L0 as the sole slot-critical path until GitBook [slot-critical publication gate](https://gitbook.conet.network/developers/l1-node.html#slot-critical-publication-gate) is filled **vs public P2P**. Lab overlay RTT snapshots are not that gate. Production overlay must not collapse onto one mailbox / one ASN (`[[l0.channels]]` on the same B is not path diversity).

## 2026-08-20 dual-hub beacon recovery record

The lab spoke `.45` uses overlay VIP `100.64.0.5` and two static hubs:

- production hub `.82`: `100.64.0.7`, geth `:8400`, beacon `:4200`;
- lab hub `.98`: `100.64.0.6`, geth `:8400`, beacon `:4200`.

This run established the following operational facts:

1. Geth and beacon are separate overlay TCP planes. `100.64.0.5 → :8400 ESTAB` does not prove beacon health; always check `:4200` and Prysm `peer_count` separately.
2. A Prysm error dialing `/ip4/100.64.0.7/tcp/4200` with `i/o timeout`, followed by `dial backoff`, means the overlay beacon TCP handshake did not complete. It is not by itself a peer-ID mismatch or a protocol change.
3. A public-advertise hub may bind beacon to its public IP (`216.225.202.82:4200`) while the overlay peer dials `100.64.0.7:4200`. The hub therefore requires `overlay-beacon-listen-dnat.sh apply`; the public listen address alone is not proof that the overlay path works.
4. Repeated `l0_connect HTTP 409 Conflict` indicates an exclusive SI occupy/pipe collision or stale mailbox-B state. `P1 overlay batch flushed` is fallback traffic, not proof of a live duplex pipe or successful HTTP delivery.
5. One healthy beacon peer is sufficient to prove connectivity, but both configured hubs should remain in the static peer list for redundancy. Do not require both peers to be simultaneously `connected`.

### Recovery order

Use this order, from least disruptive to most disruptive:

1. Read-only: query beacon `peer_count` and `identity`, inspect `ss -tn` for overlay `:4200` and `:8400`, verify TUN VIPs, and read the `conet-l0d` logs. Verify the hub peer ID against the spoke `--peer`.
2. Re-apply `overlay-beacon-listen-dnat.sh apply` on the public-advertise hub and the spoke. This installs the local-listen DNAT/SNAT and refreshes beacon `:4200/:4300` conntrack; it must not flush geth `:8400`.
3. If beacon remains `SYN-SENT` and L0 shows 409/404, restart only `conet-l0d`, first hub then spoke. Re-apply listen-DNAT after each TUN or beacon-PID change. Do not immediately run `overlay-dht-steer.sh apply` after a beacon restart.
4. If 409 persists after the ordered daemon bounce, clear the stale occupy on mailbox B (SI-only, operator-authorized), wait for SI to become active, then repeat the hub-then-spoke `conet-l0d` bounce. Do not only bounce the spoke.
5. Only if the overlay TCP path is healthy but Prysm remains in dial backoff, an explicitly authorized operator may restart the named host's beacon only. Re-check `geth.pid`; never infer a geth restart from `pgrep -n geth`.

### Acceptance evidence

The recovery is successful when `.45` has `connected >= 1`, an overlay `:4200 ESTAB` to `.82` or `.98`, and geth still has its expected peer count. For sync progress, observe `head_slot` rising and `sync_distance` falling; `is_syncing=true`, `is_optimistic=true`, or EL `0x0` during CL catch-up is not sufficient evidence of an overlay failure. Repeated 409/404 or persistent `SYN-SENT` is not accepted as healthy even if another hub currently supplies one peer.

The recorded recovery restarted only `.82` and `.45` `conet-l0d`, re-applied listen-DNAT, and restored `.45 → .82:4200 ESTAB` with beacon `connected=1`; geth PID stayed unchanged. This recovery bounce did not restart geth or validator, touch chaindata, or change an SI protocol command. Beacon restarts were separate, explicitly authorized remediation steps.

### Protocol boundary

This is an operational recovery playbook for the existing SI `l0_listen`/`l0_connect` application composition. It does not add an SI command, alter `/post`, or make L0 the production slot-critical path.

## Lifecycle

| Event | Must happen |
| --- | --- |
| `start` | If a dirty state file exists, teardown first. Create TUN → `ip addr` / `ip route` → owned iptables chain + jumps → write state/pid → packet loop. |
| SIGINT / SIGTERM / `stop` | Reverse: delete jumps → flush/delete chain → delete route/addr/TUN → remove state. |
| `teardown` | Same reverse path even if the daemon is dead. |

All net objects must be tagged (`CONET_L0D` chain, comment `conet-l0d`) so teardown never deletes foreign rules.

`gateway` is intentionally outside this lifecycle. It must not create a TUN,
install routes, or touch iptables. It owns only mailbox SSE tasks and
loopback HTTP proxy tasks. Gateway secrets are file inputs with restrictive
permissions; they must never be passed as CLI arguments, environment values,
logs, or committed files. The default gateway policy is GET/HEAD, loopback
upstream only, bounded bodies, and encrypted response POST through Entry
nodes to the requester mailbox.

## Docs

| File | Role |
| --- | --- |
| `whitepaper/conet-l0d.md` | English whitepaper (canonical technical wording) |
| `whitepaper/conet-l0d.zh-CN.md` | Paired Chinese whitepaper |
| `docs/MVP.md` / `docs/MVP.zh-CN.md` | Accepted crate MVP |
| `docs/P1.md` / `docs/P1.zh-CN.md` | Overlay `/post` encrypt + mailbox wrap + POST; inbound decrypt + TUN write-back; EIP-191 listen worker; optional `[[l0.channels]]` per overlay port; SI gossip JSON ingest; `[l0]` default off; authorized lab may enable `[l0]`; 2026-08-18: overlay IPv4 batch + POST 32/512; `.45` advertises overlay vIP; overlay geth + beacon TCP; follow-the-chain Prysm-bound (~3.2 blocks/s); EL still `0x0`; `scripts/watch-l0-follow.sh` |
| `docs/P2.md` / `docs/P2.zh-CN.md` | Lab overlay UDP / DHT-port comms. Drop recovery: steer apply first; authorized `.45` `restart-beacon` only after dial backoff. **2026-08-19:** beacon `connected=0` + SYN-SENT + `l0_connect` **409** → clear mailbox B SI occupy, bounce hub→spoke `conet-l0d`, flush `:4200` conntrack, then `restart-beacon` if still in dial backoff. **2026-08-20:** lab-only static overlay `--peer` (not DHT) after authorized hub+spoke `restart-beacon` → spoke `connected=1`, overlay ESTAB + AES, `head_slot`↑ / `sync_distance`↓; listen-DNAT after restart, not steer; prove geth via `geth.pid`. **~07:13Z** authorized `.98` `restart-beacon` (`--disable-quic`): overlay TCP toward `.82` accepted (conntrack); hybrid hub, not L0_ONLY / FOLLOW_OK |
| `docs/operator-flags.md` | geth/beacon advertise flags (not iptables) |
| `config/conet-l0d.example.toml` | Example overlay table |
| `systemd/conet-l0d.service` | start/stop only; no raw iptables |
| Cursor (global) | `.cursor/rules/conet-l0d-beacon-sync-recovery.mdc` — overlay sync / beacon fault playbook |
| GitBook Applications | `src/docs/gitbook/applications/conet-l0d.md` — operator how-to + troubleshooting |
| GitBook Developers | `src/docs/gitbook/developers/conet-l0d.md` — CLI, config, wire contract |
| GitBook L1 join | `src/docs/gitbook/developers/l1-node.md` — public P2P **and** optional overlay deploy / recovery; [slot-critical publication gate](https://gitbook.conet.network/developers/l1-node.html#slot-critical-publication-gate) vs public P2P; multi-Guardian / multi-Mailbox |

If a whitepaper section changes, update **both** languages in the same task.

### GitBook lockstep (Applications + Developers)

When the **whitepaper**, **`RULES.md`**, or **MVP** changes, the **same task** must update **both**:

1. `src/docs/gitbook/applications/conet-l0d.md` (operator how-to)
2. `src/docs/gitbook/developers/conet-l0d.md` (CLI / config / owned net objects)

Also refresh indexes that already link the product (`SUMMARY.md`, `applications/README.md`, `developers/README.md`, `developers/l0.md`, `developers/l1-node.md`, `l0/using-l0.md`, `applications/silentpass-vpn.md`, `resources.md`) if the maturity, commands, or “what exists today” table changed. Overlay **beacon sync recovery** lives on `developers/l1-node.md` and `applications/conet-l0d.md` (and Cursor `conet-l0d-beacon-sync-recovery.mdc`); keep those three aligned when the playbook changes.

Public URLs after deploy: `https://gitbook.conet.network/applications/conet-l0d.html` and `https://gitbook.conet.network/developers/conet-l0d.html`.

Do **not** run `src/docs/scripts/deployGitbook.sh` unless the user asks.

Do **not** expand the global DePIN protocol sync rule to require L0 protocol pages for a crate-only change. Those L0 pages (`using-l0`, mailbox routing, SI developer guide) update only when a **new SI command** or live `/post` contract change exists.

## L0 protocol changes

This crate is an **application composition on live SI `l0_listen` / `l0_connect`**. Overlay `duplex_*` JSON is **not** an SI command. If you add or change an SI command (`l0_listen` / `l0_connect` included), the same task must update GitBook **L0 protocol + Developers L0 + both conet-l0d pages**. If you change duplex application JSON, update `duplex-forward.md` and using-l0 composition tables — **do not** add SI `duplex_*` rows. Do not treat `p2p_stream_*` / `listenKind: l1p2p` as current SI. Do not treat this README as a substitute.

## Build

```bash
cargo test
cargo build --release
```

`start` / `teardown` require Linux + `CAP_NET_ADMIN`. `resolve` and `check-config` are OS-independent.

## Current opaque transport revision (2026-08-20)

The deterministic wallet/port `sessionId` and SSE-side teardown notices are
retired. New pipe incarnations generate `duplex::new_pipe_handle()`, a random
64-character lowercase hexadecimal value. It is never derived from wallet,
port, IP, or route data.

`l0_pipe_end` is accepted only by `run_occupied_pipe` on the occupied TCP that
already owns the same handle:

```json
{"type":"l0_pipe_end","pipe_handle":"<64 lowercase hex>","reason":"transport_closed"}
```

The current wire object must not contain `wallet`, `connector`, `sessionId`, or
`session_id`. Missing, malformed, or mismatched handles are rejected. The SSE
ingest path must not parse this object and no `l0_listen_released` SSE notice
is used. SI implementations may propagate a transport failure internally with
hop-local opaque handles, but must never expose a cross-hop correlation or
end-to-end AES key.

## Dedicated pipe-PGP handshake

The first `duplex_offer` is a bootstrap message and may be routed to the
receiver's long-lived public user PGP so the mailbox can find the receiver.
The offer carries the initiator's dedicated listen-pipe PGP. Once the receiver
accepts the offer, its `duplex_accept` response is encrypted to that
`listenUserPgp`, not to the initiator's long-lived public PGP. The response
carries the receiver's own dedicated listen-pipe PGP and the negotiated AES
key.

After the accept is received, both sides use their own dedicated listen-pipe
PGP identities for the `l0_connect` / `l0_listen` control path. The initiator
must not continue using the receiver's long-lived public user PGP for duplex
traffic. Each endpoint still owns a separate occupied pipe; the two pipes are
bound by the same `pipe_handle` only at the application layer.
