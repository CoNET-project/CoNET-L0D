# conet-l0d — L1 overlay on Layer Minus

**Paired translation:** [简体中文](./conet-l0d.zh-CN.md)  
**Revision:** 2026-08-17 (milestone eval 21:50Z: crate MVP accepted; P1 outbound + inbound decrypt/TUN write-back in-crate; live mailbox SSE not opened; lab binary `[l0]` off)  
**Public operator guide:** [Applications — L1 overlay daemon](https://gitbook.conet.network/applications/conet-l0d.html)  
**Public developer guide:** [Developers — conet-l0d](https://gitbook.conet.network/developers/conet-l0d.html)

This whitepaper is an **L1 node overlay + L0 application composition**. It does not amend the CoNET-DLE multi-chain whitepaper and does not add a second IP network to Layer Minus.

When this file or `RULES.md` changes, the same task must update **both** GitBook pages above. Do not leave the public book on a previous revision.

## 1. Problem

CoNET L1 `geth` and Prysm `beacon-chain` speak ordinary TCP/UDP to `IP:port`. Operators who sit behind NAT, lack a stable public address, or want a **wallet-addressed** backup path cannot change those clients’ source. They need a Linux command that:

1. presents a stable overlay locator (`web3://…` → overlay IPv4);
2. **catches** only packets destined to that overlay;
3. carries the byte stream on Layer Minus (wallet + OpenPGP, `POST /post`);
4. **owns** TUN and iptables for the lifetime of the process — start installs, stop/teardown removes, no hand-written `iptables`.

## 2. Non-goals

| Out of scope | Why |
| --- | --- |
| Patch geth / beacon / validator | Product constraint: zero client source change |
| Kernel module | Userspace daemon is enough |
| SilentPass / `SaaS_Sock5` as L1 P2P | Those commands open a public `host:port` egress |
| Treat current L0 UDP forward as OS UDP | AES frames over HTTP/SSE; idle 10 min; not discv4 |
| Capture `127.0.0.0/8` or validator uid | Engine JWT, beacon gRPC, local RPC must stay local |
| Redirect `0.0.0.0/0:8400` | Mixed-mode public P2P must keep working |
| New public hostname | Reuse existing CoNET / beamio.app paths |
| Restart EL / CL / VA | Lifecycle is only this daemon’s net objects |

## 3. Architecture

```text
geth / beacon
  connect(100.64.x.y : 8400|4200)
        │
   kernel route  100.64.0.0/10 → tun conet-l0
        │
   conet-l0d  (owns TUN + iptables chain CONET_L0D)
        │  resolve overlay IP → web3:// wallet | tag.web3
        │  encrypt to peer user PGP; listen/control to mailbox B route PGP
        ▼
   Layer Minus   POST { data: armor }  entry A ≠ B
        │
   peer conet-l0d  injects src=remote-vIP into peer TUN
        ▼
   peer geth / beacon  accept() on 0.0.0.0:port
```

Layer Minus remains a [PGP / wallet forwarding plane](https://gitbook.conet.network/l0/using-l0.html). `conet-l0d` is one application combination, like Chat or SilentPass — not a new L0 protocol.

## 4. Identity (`web3://` locator)

The URI is a **peer locator**, not an ERC-4804 content URI.

```text
web3://<host>/p2p/<service>

host     = 0x + 40 hex                    → EOA
         | <beamioTag>.web3               → exact tag → EOA
service  = geth | beacon
```

Resolution:

1. EOA directly, or **exact** BeamioTag match (`CoNET` ≠ `CONET`). Never `search-users` `results[0]`.
2. `searchKey(EOA)` on AddressPGP `0x684b0ac760cEE9c9b85de36d69746420648Cf9e2`.
3. Require user PGP + mailbox route. An AA without AddressPGP is not a destination.
4. Allocate or look up overlay vIP. geth/beacon only see `vIP:port`.

Routing EOA ≠ deposit keystore ≠ fee recipient. The daemon must not read validator keys.

## 5. Catch path (no client bind to overlay)

Advertise flags are **not** listen addresses:

| Client | Advertise (safe) | Bind (do not set to overlay) |
| --- | --- | --- |
| geth | `--nat=extip=<local-vIP>` | `--http.addr` / `--authrpc.addr` stay `127.0.0.1` |
| beacon | `--p2p-host-ip=<local-vIP>` | `--rpc-host` / `--grpc-gateway-host` stay `127.0.0.1` |

`--port 8400` and `--p2p-tcp-port=4200` still listen on `0.0.0.0`. A missing overlay address does **not** stop client startup. Unreachable overlay bootnodes leave the process up with zero overlay peers.

Phase 1 uses **static** overlay peers. Do not hijack discv4 / discv5 UDP on day one.

## 6. Daemon-owned net objects

On `start` (after optional dirty-state teardown):

1. Create TUN `conet-l0`.
2. `ip addr add <local-vIP>/32 dev conet-l0`.
3. `ip route add 100.64.0.0/10 dev conet-l0`.
4. Create iptables chain `CONET_L0D` (filter + mangle).
5. First rules: `RETURN` `127.0.0.0/8`; optional `owner --uid-owner <validator>` `RETURN`.
6. Jump `OUTPUT` / `PREROUTING` into that chain only.
7. Write state + pid; run the packet loop.

On SIGINT / SIGTERM / `stop` / `teardown`:

1. Delete the jumps (only those that point at `CONET_L0D`).
2. Flush and `-X` `CONET_L0D`.
3. Delete the overlay route, address, and TUN.
4. Remove the state file.

Operators never run `iptables` by hand. Teardown must not delete foreign rules.

## 7. L0 mapping (Phase 1)

| Direction | Encrypt to | HTTP |
| --- | --- | --- |
| Overlay TCP bytes | Peer **user PGP** | Entry **A ≠ B** |
| Listen / control | Mailbox **B route PGP** | Entry **C ≠ B** |

HTTP body is only `{ "data": "<armor>" }`. No hop-sig header from this client. No `NoPush` on HTTP JSON.

A dedicated SI command (`p2p_stream_*`, `listenKind: "l1p2p"`) is **undecided**. Until it exists, do not document it as live SI. If it is added, the same task must update GitBook L0 protocol pages **and** the two public `conet-l0d` pages.

Existing UDP forward is not this path.

## 8. Production posture

Keep **public P2P** for slot-critical gossip (6 s). Use L0 overlay for NAT / no public IP / backup peers. L0-only proposer operation is unmeasured and must not be the default.

L0 extra latency is an **estimate** (tens to hundreds of milliseconds per hop), not a lab measurement in this revision.

## 9. Security

- Do not log private keys, full PGP armor, or session keys.
- Do not capture loopback or validator gRPC.
- Mixed mode: never mark the entire public 8400/4200/4300 space.
- Capability `CAP_NET_ADMIN` is required; drop other privileges where the OS allows.

## 10. Phases

| Phase | Scope |
| --- | --- |
| **MVP** | **Accepted (2026-08-17).** Linux command; TUN + iptables lifecycle; locator parse; static peer table; packet counters; L0 client stub |
| **P1** | **In crate; lab binary may be installed with `[l0]` off.** Wallet-to-wallet TCP byte stream on current L0 primitives; static overlay bootnodes. Crate encrypts the overlay envelope to the peer **user PGP**, wraps `{ data, NoPush: true }` to mailbox **B route PGP**, and POSTs only `{ "data" }` when `[l0].enabled` plus peer user+route PGP files and an entry are present (default **off**). Inbound decrypt of user-PGP armor → overlay envelope → raw IPv4 queued to TUN is **in-crate** when `routing_key_file` is an OpenPGP secret cert. Listen command shape is `command: mining` + `listenKind: "chat"` with **no** `Securitykey`. **Live mailbox SSE is not opened.** This evaluation may install that binary on the two-host lab **without** enabling `[l0]`. Not a live mailbox client. Do not advertise overlay vIPs until a bidirectional frame is proven. |
| **P2** | Datagram adapter if discv4/discv5 must ride L0 |
| **P3** | Hybrid production (public P2P + L0 backup); measured RTT |

## 11. Source of truth

| Artifact | Role |
| --- | --- |
| [github.com/CoNET-project/CoNET-L0D](https://github.com/CoNET-project/CoNET-L0D) | Canonical public crate |
| This pair + `RULES.md` | Design and engineering constraints |
| `docs/MVP.md` | Accepted crate MVP |
| `docs/P1.md` | Next-phase wire and `[l0]` (not a live SI command) |
| `config/conet-l0d.example.toml` | Example overlay table |
| `systemd/conet-l0d.service` | Process owns TUN/iptables; unit must not run raw `iptables` |
| GitBook Applications | Operator how-to (English public book) |
| GitBook Developers | CLI, config, wire contract |
| GitBook L0 | Forwarding plane — do not fork it here |

## Related

- [How to use Layer Minus](https://gitbook.conet.network/l0/using-l0.html)
- [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html)
- [SilentPass](https://gitbook.conet.network/applications/silentpass-vpn.html) — egress, not L1 P2P
- [Wallet-addressed peer identity](https://gitbook.conet.network/l0/wallet-address-p2p.html)
