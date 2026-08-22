# conet-l0d — subproject rules

Independent Linux command. Canonical git remote: [https://github.com/CoNET-project/CoNET-L0D](https://github.com/CoNET-project/CoNET-L0D). Do not `../..` import BeamioContract, SilentPassUI, CoNET-SI, or x402sdk.

## Product

`conet-l0d` is a userspace daemon. It creates a TUN, installs **its own** iptables/ip rules, and tears both down on stop, crash cleanup, or `teardown`. Operators must not be asked to run `iptables` by hand.

It does **not** patch geth, Prysm `beacon-chain`, or `validator`.

## Dynamic proxy lines

`l0.billing_eoa`/`billing_eth_key_file` identify the main paid account. A
duplex line is allocated only by an explicit new-line request addressed to
`mainWallet:port` and signed by the main paid wallet. The temporary
communication identity is allocated and registered during that request, before
any offer is processed; it is never used as the payer.

Each `[[l0.proxies]]` entry is an upstream `host` plus `port`. The port is the
logical L0 port. Every explicit new-line request must have its own temporary
wallet, OpenPGP route identity, AES key, session/pipe handle, and occupied
socket.
Temporary identities are memory-only, are registered before they are used for
routing, and are destroyed on EOF, failed HTTP status headers, timeout, or
socket close. Multiple lines may use the same logical port, but no wallet,
PGP key, AES key, pipe, or socket may be shared.

The occupied pipe is a byte transport only. Proxy data is forwarded to the
configured upstream `host:port` with bounded async bidirectional copying; it
does not use iptables DNAT and it does not save offline data. A failed line is
isolated from other sessions on the same port.

**Proxy-only server:** when `[[l0.proxies]]` or `[[l0.proxy_duplex]]` is set and
no client is configured (`proxy_server_only`), the daemon does **not** create a
TUN, route, or iptables chain. `--proxyDuplex` drains the occupied raw stream to
its configured `host:port`; `--proxy` remains the request/response target table
and never attaches a persistent duplex drain. Do not stuff full IPv4 packets into
the proxy upstream queue. Multi-port proxy (e.g. `:8400` + `:4200`) **must** use a distinct
`[[l0.channels]]` routing EOA per port: SI exclusive occupy is **one pipe per
listen wallet**. Empty channels collapse every port onto `billing_eoa` / identity
locator and cause sustained `l0_connect` **HTTP 409**. Inbound `duplex_offer`
matching uses `billing_eoa` (`mainWallet:port`), not the per-port channel EOA,
but that match is only a routing lookup. It never authorizes allocation:
offers may attach only to a pre-registered `pipe_handle` or temporary
`listenWallet`; unknown, stale, or ambiguous offers are rejected without
creating a session, wallet, or `l0_connect`.

**Client endpoint:** `--client 'web3://<peerMainWallet>:port'` (or
`l0.clients`) maps the peer to the daemon-selected local virtual endpoint
(`local_vip:port`, for example `100.64.0.5:4000`) for request/response P1
traffic. L0d owns the TUN and routing rules; client applications must connect
to the printed local endpoint and do not need separate iptables rules.
Use `--clientDuplex` (or `l0.client_duplex`) to seed an independent pending
occupied bidirectional line. Both target types are included in local mappings,
but only `client_duplex` enables duplex seeding.

### Connection-driven duplex client handles

For `--clientDuplex`, the local TCP `accept()` event is the only connection
handle. The daemon does not pre-create one duplex session per logical port and
does not select a session by port. Each newly accepted socket gets a fresh
temporary wallet, OpenPGP identity, AES key, opaque `pipe_handle`, local
return queue, and occupied `l0_connect` line. The temporary route is
registered before the offer is posted to the peer. `regiestChatRoute` HTTP
200 is not SI `isMyRoute`; wait until AddressPGP `searchKey` shows the
registered `routeKeyID` on CoNET RPC, then open `l0_listen`. Wrap
`duplex_offer` to the destination user PGP for that `mainWallet:port` and
select the inbound decrypt secret from PKESK recipients, not listen-wallet
list order.

All bytes read from that socket stay attached to that handle until EOF or
socket error. Bytes received from the peer are written only to the same local
socket. Concurrent sockets connecting to the same local endpoint therefore
create independent lines; no wallet, PGP key, AES key, queue, pipe, or upstream
socket may be shared. The raw application stream is not prefixed with a
conet-l0d header. Geth/Prysm bytes remain unchanged; the accepted socket and
the encrypted `pipe_handle` provide correlation.

### TUN-less Beacon stream mode

When a Beacon process uses a local L0d TCP listener (for example
`127.0.0.1:14200`), the operator startup script may set
`L0_STREAM_ONLY=1`. This mode uses only the explicitly supplied
`EXTRA_BEACON_PEERS`, enables `--no-discovery` and `--disable-quic`, and does
not require TUN, iptables, DHT steering, or listen-DNAT. Explicit environment
values are captured before host defaults are sourced and restored afterward;
host defaults therefore cannot replace the selected local stream peer.

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

Canonical static `--peer` (both hubs already `--p2p-static-id`): `scripts/l1-beacon-static-peers.env`. Do **not** fetch `.98` `:4100` `/eth/v1/node/identity` (HTTP 500 / nil ENR when `--no-discovery`). DHT sidecar `:4110` IDs are **not** beacon `--peer`. Do not wipe `network-keys` or run `restart-beacon-clean`. Do not `systemctl restart conet-node66`. Pinning the ID is not overlay join (toml + `conet-l0d` + listen-DNAT still required).

```text
--peer=/ip4/100.64.0.7/tcp/4200/p2p/16Uiu2HAmDJCHuVkXtkPrrL8YykQ9gFZnQkR9Q6WjZZUrmueohPfd
--peer=/ip4/100.64.0.6/tcp/4200/p2p/16Uiu2HAmF1SXGHnne9DQTHGfgGQgje3cBV8pdSLJF25ajYKr2hvS
```

Public join uses the same `peer_id` with `216.225.202.82` / `198.251.77.98`. L0_ONLY allowlist refuses those public multiaddrs.

This run established the following operational facts:

1. Geth and beacon are separate overlay TCP planes. `100.64.0.5 → :8400 ESTAB` does not prove beacon health; always check `:4200` and Prysm `peer_count` separately.
2. A Prysm error dialing `/ip4/100.64.0.7/tcp/4200` with `i/o timeout`, followed by `dial backoff`, means the overlay beacon TCP handshake did not complete. It is not by itself a peer-ID mismatch or a protocol change.
3. A public-advertise hub may bind beacon to its public IP (`216.225.202.82:4200`) while the overlay peer dials `100.64.0.7:4200`. The hub therefore requires `overlay-beacon-listen-dnat.sh apply`; the public listen address alone is not proof that the overlay path works.
4. Repeated `l0_connect HTTP 409 Conflict` indicates an exclusive SI occupy/pipe collision or stale mailbox-B state. `P1 overlay batch flushed` is fallback traffic, not proof of a live duplex pipe or successful HTTP delivery. After a daemon bounce, mailbox B may flush older `duplex_offer` armors before any live peer:port pipe exists: the crate rejects offers older than **`DUPLEX_OFFER_MAX_AGE_SECS` (90s)** wall-clock age (plus skew), and also skips stale offers when a live occupy already exists for that peer:port.
5. One healthy beacon peer is sufficient to prove connectivity, but both configured hubs should remain in the static peer list for redundancy. Do not require both peers to be simultaneously `connected`.

6. For a configured duplex session, P1 is not a transport fallback. While the
   session is negotiating or rebuilding `l0_connect`, packets are suppressed;
   a full occupied-pipe queue is also a drop condition. P1 becomes eligible
   only after the duplex session explicitly receives `duplex_reject`.

### Recovery order

Use this order, from least disruptive to most disruptive:

1. Read-only: query beacon `peer_count` (`.98` `:4100` **identity** may 500 — use `scripts/l1-beacon-static-peers.env` or `beacon.log` “Running node with peer id”), inspect `ss -tn` for overlay `:4200` and `:8400`, verify TUN VIPs, and read the `conet-l0d` logs. Verify the hub peer ID against the spoke `--peer` and that env file.
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
| `scripts/l1-beacon-static-peers.env` | Canonical `.82` / `.98` beacon `peer_id` and `--peer` (do not curl `.98` `:4100`). Host backups sit **outside** `beacondata`: `~/ethereum-pos-mainnet/secrets/l1-beacon-network-keys/` |
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

## firstChunk / responseChunk bootstrap

On a client, each newly accepted local TCP socket is the only connection
handle. The client pauses that socket after its first bytes, creates and
registers exactly one temporary route, waits until its temporary `l0_listen`
SSE is ready, and only then sends those bytes as `firstChunk` in
`duplex_offer`. Existing handles never allocate a second line.

A duplex proxy may open a line only when the signed offer's recovered
`billingWallet`, `mainWallet:port`, explicit `--proxyDuplex` target, and
non-empty `firstChunk` all match. It creates and registers its own temporary
route and waits for that route's `l0_listen` SSE before connecting upstream.
The proxy forwards `firstChunk`, pauses the upstream after its first reply,
and returns that reply as `responseChunk` in `duplex_accept`. It
reverse-occupies the initiator listen only if that return pipe is still
empty, then starts upstream-to-pipe forwarding. It does **not** wait for a
second local protocol chunk: geth / beacon often stay paused after Hello
until both occupied pipes are up. The initiator decrypts the accept with its
per-socket temporary PGP key, writes `responseChunk` to the paused local
socket, and occupies immediately (an empty first AES blob is allowed). Later
bytes use the same pipe handle and session. An unrelated, unsigned, stale, or
ambiguous offer is rejected and cannot allocate a route.

## Main-wallet billing for temporary channels (2026-08-21)

`walletAddress` is the communication subject and mailbox route identity for a
channel. It may be a temporary wallet/PGP identity and must be registered with
AddressPGP before the SI entry can route its PGP posts. It is not the account
that pays for the channel.

Every mailbox SI command (`l0_listen`, `l0_connect`, Chat listen) keeps the
temporary communication identity in `walletAddress` and carries the configured
paid account in `billingWallet`. The paid account signs the EIP-191 command.
The deployed CoNET-SI verifier recovers against `billingWallet` while retaining
`walletAddress` for routing and mailbox ownership. Without `billingWallet`, SI
keeps the legacy recover == `walletAddress` rule.

`duplex_offer` / `duplex_accept` (application-layer, peer-verified) are signed by
the configured paid account. When the duplex signer differs from `walletAddress`,
the signed command contains:

```json
{"walletAddress":"<temporary-channel-wallet>","billingWallet":"<main-paid-wallet>"}
```

Peer `conet-l0d` and SI verify the EIP-191 signature against `billingWallet`.
SI routes the outer user-PGP ciphertext using the temporary communication
identity. Billing and communication identities must never be silently conflated.

Each `[[l0.channels]]` entry now owns exactly one `port`; a port cannot be
shared by two channels. Configure `[l0].billing_eoa` and
`[l0].billing_eth_key_file` for the main paid account. The channel
`routing_eth_key_file` signs mailbox listen/connect until SI ships `billingWallet`.
