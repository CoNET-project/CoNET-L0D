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
6. Existing SI UDP forward is **not** raw OS UDP. Phase 1 = static overlay peers. The crate envelope is complete IPv4 (UDP proto 17 included). Lab UDP/DHT comms: `docs/P2.md` (overlay UDP plus live discv5 from L0_ONLY `.45` to the `.98` DHT server over L0; `L0_DHT` allowlist is overlay plus hub public `/32`; packets still DNAT onto overlay; after DNAT `.45` `ss` may show hub public `:4200`; not a production product). Do not treat live `udp_relay` as OS UDP.
7. Do not use SilentPass / `SaaS_Sock5` as L1 P2P (that is egress to a public `host:port`).
8. HTTP `/post` **first body** is only `{ "data": "<armor>" }`. No hop-sig headers from this client. Optional `[l0]` defaults to **off**. An authorized lab may enable `[l0]` on host copies. Prefer **L0 occupancy pipe + application duplex**: exclusive SI `l0_listen` / `l0_connect` (or `mining` + `listenKind: "l0"`); `duplex_offer` (AES key + session `listenWallet`) to the peer **long-lived user PGP** on Chat gossip; `duplex_accept` / `duplex_reject` / AES `duplex_frame` as **AES blobs on the occupied pipe** (`payload` = standard base64 of `L0D1||IPv4`). Crate MVP session listen is the per-port channel EOA (Chat SSE **and** `l0_listen` in different pools). SI does **not** implement `duplex_*`. Overlay AES is memory-only; never put it on B-decryptable `l0_listen` / `l0_connect`. `duplex_reject` or missing `duplex_accept` **or** missing occupied pipe keeps P1 gossip. After exclusive `l0_listen` reconnects successfully, **rebuild** outbound `l0_connect` for already-attached duplex sessions; if occupy fails, **retry** — do not clear `pipe_tx` once and permanently fall back to P1. Entry `socketForward` must not kill C→B SSE / L0 pipes on 60s receive-idle (see GitBook peel-hop-listen / duplex-forward). Do not send `mining` + `listenKind: "duplex"`. Do not invent SI `duplex_*` or `p2p_stream_*`. Do not POST unless duplex AES+`peer_attached`+`pipe_tx` **or** the overlay is encrypted to the peer **user PGP** **and** wrapped to mailbox **B route PGP**. Do not POST plaintext JSON as `data`. Inbound decrypt + TUN write-back and listen HTTP+SSE workers may exist in-crate. Listen spawn is fail-closed: enabled plus `listen_entries` (C ≠ B; never fall back to outbound `entries`), `mailbox_route_pgp_file` (this host's B route **public** key), `routing_eoa`, `routing_key_file` (OpenPGP secret), and `routing_eth_key_file` (hex secp256k1; recovered address must match `routing_eoa`; not OpenPGP). Optional `[[l0.channels]]` uses one dedicated routing EOA + listen SSE per overlay port (8400 / 4200 / 4300); outbound encrypts to the peer user PGP for that port (classify by well-known src or dest port). Empty channels keep one EOA. `:4300` is overlay IPv4, not `udp_relay`. Do not bind two SSEs of the **same pool** to the same EOA. Listen is EIP-191 + SI `{ message, signMessage }` base64. Listen ingest must accept SI `forWardPGPMessageToClient` raw JSON `{ "data": "<armor>" }` (Chat `handleInbound`), occupy JSON (`l0_occupied`), teardown JSON (`l0_pipe_end`, `l0_listen_released`), AES blobs, duplex JSON, not only SSE `data: BEGIN PGP` lines. Tests use wiremock only. HTTP 200 on entry A is **not** by itself inbound TUN write-back. After the SI gossip JSON ingest fix, the 2026-08-17 23:30Z lab wrote inbound IPv4 on both TUNs and completed overlay geth TCP (`.45` ↔ `.98` on `100.64.0.5` / `100.64.0.6`). **2026-08-18:** authorized L0_ONLY `.45` advertises overlay vIP `100.64.0.5`; overlay geth + beacon TCP are ESTAB; dest-aggregated IPv4 + POST concurrency 32 / queue 2048 (upgrade both lab binaries together). After that binary, overlay queue-full is 0; remaining follow-the-chain limiter is Prysm initial-sync (~3.2 blocks/s, ~15 h). EL still `0x0`. Read-only watch: `scripts/watch-l0-follow.sh`. The follow-the-chain gate stays open. A separate lab UDP/DHT comms experiment ran (`docs/P2.md`): overlay UDP plus live discv5 from L0_ONLY `.45` to the `.98` DHT server over L0 (allowlist = overlay + hub `/32`; steer DNAT; isolate drops unsteered public P2P). After DNAT, `.45` `ss` may show ESTAB to hub public `:4200` — original dest, not a leak; overlay proof is TUN VIP + isolate DROP=0. If beacon `connected` drops while overlay geth stays ESTAB, re-apply `overlay-dht-steer.sh` first (flush ghost hub conntrack; **do not** restart EL/CL for that). `restart-beacon` is only for Prysm dial backoff after that flush (**2026-08-18 ~17:28Z** on `.45` restored `connected=1` and `Processing blocks`; do not re-apply steer immediately after start). It does not close that gate. `.98` and production proposers keep the public IP.
9. Do not invent a new public hostname. Reuse existing CoNET / beamio.app paths.
10. The crate must not restart geth / beacon / validator. An authorized **operator** script may restart **only** the named lab host (`.45` L0_ONLY; `.98` `restart-beacon` only when that host is authorized in the same message). Never wipe. Never mutate the daemon-owned `CONET_L0D` chain; public-P2P isolate uses `CONET_L0D_P2P_ISOLATE` / `_OUT`. Do not restart `.98` geth or any validator.

## Lifecycle

| Event | Must happen |
| --- | --- |
| `start` | If a dirty state file exists, teardown first. Create TUN → `ip addr` / `ip route` → owned iptables chain + jumps → write state/pid → packet loop. |
| SIGINT / SIGTERM / `stop` | Reverse: delete jumps → flush/delete chain → delete route/addr/TUN → remove state. |
| `teardown` | Same reverse path even if the daemon is dead. |

All net objects must be tagged (`CONET_L0D` chain, comment `conet-l0d`) so teardown never deletes foreign rules.

## Docs

| File | Role |
| --- | --- |
| `whitepaper/conet-l0d.md` | English whitepaper (canonical technical wording) |
| `whitepaper/conet-l0d.zh-CN.md` | Paired Chinese whitepaper |
| `docs/MVP.md` / `docs/MVP.zh-CN.md` | Accepted crate MVP |
| `docs/P1.md` / `docs/P1.zh-CN.md` | Overlay `/post` encrypt + mailbox wrap + POST; inbound decrypt + TUN write-back; EIP-191 listen worker; optional `[[l0.channels]]` per overlay port; SI gossip JSON ingest; `[l0]` default off; authorized lab may enable `[l0]`; 2026-08-18: overlay IPv4 batch + POST 32/512; `.45` advertises overlay vIP; overlay geth + beacon TCP; follow-the-chain Prysm-bound (~3.2 blocks/s); EL still `0x0`; `scripts/watch-l0-follow.sh` |
| `docs/P2.md` / `docs/P2.zh-CN.md` | Lab overlay UDP / DHT-port comms. Drop recovery: steer apply first; authorized `.45` `restart-beacon` only after dial backoff. **2026-08-19:** beacon `connected=0` + SYN-SENT + `l0_connect` **409** → clear mailbox B SI occupy, bounce hub→spoke `conet-l0d`, flush `:4200` conntrack, then `restart-beacon` if still in dial backoff |
| `docs/operator-flags.md` | geth/beacon advertise flags (not iptables) |
| `config/conet-l0d.example.toml` | Example overlay table |
| `systemd/conet-l0d.service` | start/stop only; no raw iptables |
| Cursor (global) | `.cursor/rules/conet-l0d-beacon-sync-recovery.mdc` — overlay sync / beacon fault playbook |
| GitBook Applications | `src/docs/gitbook/applications/conet-l0d.md` — operator how-to + troubleshooting |
| GitBook Developers | `src/docs/gitbook/developers/conet-l0d.md` — CLI, config, wire contract |
| GitBook L1 join | `src/docs/gitbook/developers/l1-node.md` — public P2P **and** optional overlay deploy / recovery |

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
