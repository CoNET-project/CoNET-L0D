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
6. Existing L0 UDP forward is **not** raw OS UDP. Phase 1 = TCP + static peers.
7. Do not use SilentPass / `SaaS_Sock5` as L1 P2P (that is egress to a public `host:port`).
8. HTTP `/post` body is only `{ "data": "<armor>" }`. No hop-sig headers from this client. Optional `[l0]` defaults to **off**. An authorized lab may enable `[l0]` on host copies. Do not POST unless the overlay is encrypted to the peer **user PGP** **and** wrapped to mailbox **B route PGP**. Do not POST plaintext JSON as `data`. Do not put `Securitykey` in a B-decryptable listen command. Do not invent a live SI `p2p_stream_*` command. Inbound decrypt + TUN write-back and a listen HTTP+SSE worker may exist in-crate. Listen spawn is fail-closed: enabled plus `listen_entries` (C ≠ B; never fall back to outbound `entries`), `mailbox_route_pgp_file` (this host's B route **public** key), `routing_eoa`, `routing_key_file` (OpenPGP secret), and `routing_eth_key_file` (hex secp256k1; recovered address must match `routing_eoa`; not OpenPGP). Listen is EIP-191 + SI `{ message, signMessage }` base64. Listen ingest must accept SI `forWardPGPMessageToClient` raw JSON `{ "data": "<armor>" }` (Chat `handleInbound`), not only SSE `data: BEGIN PGP` lines. Tests use wiremock only. HTTP 200 on entry A is **not** by itself inbound TUN write-back. After the SI gossip JSON ingest fix, the 2026-08-17 23:30Z lab wrote inbound IPv4 on both TUNs and completed overlay geth TCP (`.45` ↔ `.98` on `100.64.0.5` / `100.64.0.6`). **2026-08-18:** authorized L0_ONLY `.45` advertises overlay vIP `100.64.0.5`; overlay geth + beacon TCP are ESTAB; CL initial-sync is in progress; EL still `0x0`. `.98` and production proposers keep the public IP.
9. Do not invent a new public hostname. Reuse existing CoNET / beamio.app paths.
10. The crate must not restart geth / beacon / validator. An authorized **operator** script may restart **only** the named lab host (`.45` L0_ONLY). Never wipe. Never mutate the daemon-owned `CONET_L0D` chain; public-P2P isolate uses `CONET_L0D_P2P_ISOLATE` / `_OUT`. Do not restart `.98` unless that host is authorized in the same message.

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
| `docs/P1.md` / `docs/P1.zh-CN.md` | Overlay `/post` encrypt + mailbox wrap + POST; inbound decrypt + TUN write-back; EIP-191 listen worker; SI gossip JSON ingest; `[l0]` default off; authorized lab may enable `[l0]`; 2026-08-18: `.45` advertises overlay vIP; overlay geth + beacon TCP; CL initial-sync in progress |
| `docs/operator-flags.md` | geth/beacon advertise flags (not iptables) |
| `config/conet-l0d.example.toml` | Example overlay table |
| `systemd/conet-l0d.service` | start/stop only; no raw iptables |
| GitBook Applications | `src/docs/gitbook/applications/conet-l0d.md` — operator how-to |
| GitBook Developers | `src/docs/gitbook/developers/conet-l0d.md` — CLI, config, wire contract |

If a whitepaper section changes, update **both** languages in the same task.

### GitBook lockstep (Applications + Developers)

When the **whitepaper**, **`RULES.md`**, or **MVP** changes, the **same task** must update **both**:

1. `src/docs/gitbook/applications/conet-l0d.md` (operator how-to)
2. `src/docs/gitbook/developers/conet-l0d.md` (CLI / config / owned net objects)

Also refresh indexes that already link the product (`SUMMARY.md`, `applications/README.md`, `developers/README.md`, `developers/l0.md`, `developers/l1-node.md`, `l0/using-l0.md`, `applications/silentpass-vpn.md`, `resources.md`) if the maturity, commands, or “what exists today” table changed.

Public URLs after deploy: `https://gitbook.conet.network/applications/conet-l0d.html` and `https://gitbook.conet.network/developers/conet-l0d.html`.

Do **not** run `src/docs/scripts/deployGitbook.sh` unless the user asks.

Do **not** expand the global DePIN protocol sync rule to require L0 protocol pages for a crate-only change. Those L0 pages (`using-l0`, mailbox routing, SI developer guide) update only when a **new SI command** or live `/post` contract change exists.

## L0 protocol changes

This crate is an **application composition**. If you add a new SI command (`p2p_stream_*`, `listenKind: l1p2p`), the same task must update GitBook **L0 protocol + Developers L0 + both conet-l0d pages**. Do not treat this README as a substitute.

## Build

```bash
cargo test
cargo build --release
```

`start` / `teardown` require Linux + `CAP_NET_ADMIN`. `resolve` and `check-config` are OS-independent.
