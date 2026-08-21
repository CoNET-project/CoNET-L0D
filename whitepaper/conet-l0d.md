# conet-l0d — L1 overlay on Layer Minus

**Paired translation:** [简体中文](./conet-l0d.zh-CN.md)  
**Revision:** 2026-08-20 (slot-critical publication gate vs public P2P; multi-Guardian / multi-Mailbox path diversity; SI `l0_listen` / `l0_connect` occupancy pipe; application duplex; optional per-port `[[l0.channels]]`; lab overlay TCP/UDP; not a production discv5 product)  
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

Phase 1 uses **static** overlay peers. The crate envelope already carries complete IPv4, including UDP. A lab may steer beacon `:4300` onto TUN and run discv5 from a L0_ONLY host to a public DHT server over L0 (`docs/P2.md`). That is not a production discv5 product and does not close follow-the-chain.

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
| `duplex_offer` | Peer **long-lived user PGP** | Entry **A ≠ B**. Chat gossip to the existing channel SSE. SI does **not** parse `duplex_*` |
| Exclusive L0 listen | Mailbox **B route PGP** | `l0_listen` or `mining` + `listenKind: "l0"` via **C ≠ B**. No overlay AES. Two owned L0 SSEs; no guest listen on peer B |
| `l0_connect` | **Target** mailbox **B route PGP** | Occupies idle L0 SSE; then AES blobs on the same TCP. Occupied → 409 |
| `duplex_accept` / `duplex_reject` | AES on occupied initiator L0 pipe | First AES blob after responder occupies `W_I` |
| Overlay IPv4 (duplex data plane) | AES of `duplex_frame` JSON; `payload` = standard base64 of `L0D1` \|\| IPv4 | Occupied peer L0 pipe |
| P1 gossip fallback (`duplex_reject` or no accept or no pipe) | Peer **user PGP**, then mailbox-work wrap to **B route PGP** | Entry **A ≠ B** |

HTTP body is only `{ "data": "<armor>" }`. No hop-sig header from this client. No `NoPush` on HTTP JSON.

Duplex is **application JSON** on Chat gossip plus AES on the SI occupancy pipe: `duplex_offer`, `duplex_accept`, `duplex_reject`, `duplex_frame`. Initiator sends the overlay AES key and a **session listen wallet**; responder either occupies that L0 SSE with `duplex_reject` or accepts with a key echo and its own session listen wallet. Spec: [Duplex overlay](https://gitbook.conet.network/l0/duplex-forward.html). Crate MVP reuses the registered per-port channel EOA as the session listen identity. Do **not** send `command: "mining"` with `listenKind: "duplex"`. Do **not** document SI `duplex_*` / `p2p_stream_*` / `listenKind: "l1p2p"` as current SI. Do document live SI `l0_listen` / `l0_connect`.

Existing UDP forward is a different composition (shorter idle; not overlay TCP).

## 8. Production posture

Keep **public P2P** for slot-critical gossip (`SECONDS_PER_SLOT=6`). Use L0 overlay for NAT / no public IP / backup peers. **Do not** default to L0-only proposers until the GitBook [slot-critical publication gate](https://gitbook.conet.network/developers/l1-node.html#slot-critical-publication-gate) is filled **against a public-P2P baseline** (L0 RTT P50/P95/P99; block propagation to 50% and 90%; attestation inclusion delay; missed slots; reorgs; duplex reconnect time; Guardian failover time; UDP/discv5 loss).

A 2026-08-18 ~15 min lab snapshot showed overlay TCP RTT ~475–750 ms vs ~40–55 ms on `.98` public peers. That is **not** P50/P95/P99 and **not** a proposer-set measurement.

If overlay traffic hangs on **few mailboxes**, the risk moves from validator **IP** concentration to **Guardian path** concentration. Production overlay must use several independent entries, several mailboxes, several ASNs, several regions, one routing EOA per overlay port (`[[l0.channels]]`), and automatic reconnect **plus** failover to another B. Per-port EOAs on the **same** mailbox do not remove mailbox concentration. Occupy retry is in-crate; cross-Guardian failover is not a shipped product.

## 9. Security

- Do not log private keys, full PGP armor, or session keys.
- Do not capture loopback or validator gRPC.
- Mixed mode: never mark the entire public 8400/4200/4300 space.
- Capability `CAP_NET_ADMIN` is required; drop other privileges where the OS allows.

## 10. Phases

| Phase | Scope |
| --- | --- |
| **MVP** | **Accepted (2026-08-17).** Linux command; TUN + iptables lifecycle; locator parse; static peer table; packet counters; L0 client stub |
| **P1** | **In crate; `[l0]` default off.** Wallet-to-wallet TCP byte stream. Prefer **application duplex** (offer on long-lived Chat SSE; accept / reject / frames on session listen SSEs) when the peer app sends `duplex_accept`; **P1 gossip** remains the fallback on `duplex_reject` or missing accept. Static overlay bootnodes. Crate encrypts the overlay envelope to the peer **user PGP**, wraps `{ data, NoPush: true }` to mailbox **B route PGP**, and POSTs only `{ "data" }` when `[l0].enabled` plus peer user+route PGP files and an entry are present. Inbound decrypt of user-PGP armor → overlay envelope → raw IPv4 queued to TUN is **in-crate** when `routing_key_file` is an OpenPGP secret cert. Listen HTTP+SSE worker is **in-crate** when enabled plus `listen_entries` (C ≠ B), `mailbox_route_pgp_file` (this host's B route **public** key), `routing_eoa`, `routing_key_file`, and `routing_eth_key_file` (hex secp256k1; recovered address must match `routing_eoa`; not OpenPGP). Optional `[[l0.channels]]` is one EOA + SSE per overlay port 8400 / 4200 / 4300 (encrypt to the peer user PGP for that port; classify by well-known src or dest port). Empty channels keep one EOA. `:4300` is overlay IPv4, not `udp_relay`. Crate MVP session listen **is** that channel Chat SSE (`mining` + `listenKind: "chat"`, no overlay AES). `duplex_reject` or missing `duplex_accept` keeps P1 gossip. Listen is EIP-191-signed as SI `{ message, signMessage }` base64. Listen ingest matches SI `forWardPGPMessageToClient` raw JSON `{ "data": "<armor>" }` (Chat `handleInbound`), not only SSE armor lines. Tests use wiremock only. An **authorized** lab may enable `[l0]`. Do **not** treat SI `duplex_*` / `p2p_stream_*` / `listenKind: "l1p2p"` as current SI. **2026-08-17 23:12Z L0-only:** outbound HTTP 200, no inbound TUN write (old SSE-only parser). **23:30Z** (restart only `conet-l0d`): inbound IPv4 on both TUNs and overlay geth TCP (`.45` `100.64.0.5` ↔ `.98` `100.64.0.6:8400`). **2026-08-18:** authorized L0_ONLY `.45` advertises overlay vIP `100.64.0.5`; overlay geth + beacon TCP ESTAB; dest-aggregated IPv4 + POST concurrency 32 / queue 512 (upgrade both lab binaries together). After that binary, overlay queue-full is 0; remaining follow-the-chain limiter is Prysm initial-sync (~3.2 blocks/s, ~15 h). EL still `0x0`. Operator watch: `scripts/watch-l0-follow.sh`. The follow-the-chain gate stays open. `.98` and production proposers keep the public IP. HTTP 200 ≠ delivery. |
| **P2** | **Lab comms accepted; not a product.** Crate already carries IPv4/UDP — no extra datagram adapter. 2026-08-18 lab: overlay UDP echo and `:4300` (direct + public-ENR steer) arrived on the peer TUN. Live Prysm discv5 on L0_ONLY `.45` then abandoned static `--peer` and connected to the `.98` DHT server over L0 (`--p2p-static-id` on `.98`; bootstrap ENR; allowlist = overlay + hub public `/32`; TCP/UDP steer DNAT; isolate still drops unsteered public P2P). After DNAT, `.45` `ss` may show hub public `:4200` (original dest, not a leak); overlay proof is TUN VIP + isolate DROP=0. If `connected` later drops, re-apply `overlay-dht-steer.sh` first (flush ghost hub conntrack; do not restart EL/CL). `restart-beacon` only if Prysm stays in dial backoff (**2026-08-18 ~17:28Z** on `.45` restored `connected=1` and `Processing blocks`; do not re-apply steer immediately after start). First-minute `suitable=0` is expected. EL `0x0` while `head_slot` climbs is CL lag. See `docs/P2.md`. |
| **P3** | Hybrid production (public P2P + L0 backup); **published** slot-critical metrics vs public P2P; multi-entry / multi-mailbox / multi-ASN diversity |

## 11. Source of truth

| Artifact | Role |
| --- | --- |
| [github.com/CoNET-project/CoNET-L0D](https://github.com/CoNET-project/CoNET-L0D) | Canonical public crate |
| This pair + `RULES.md` | Design and engineering constraints |
| `docs/MVP.md` | Accepted crate MVP |
| `docs/P1.md` | Overlay wire: application duplex plus P1 gossip fallback; `[l0]` |
| `docs/P2.md` | Lab overlay UDP / DHT-port comms + live discv5 via L0 (not a closed P2 / production product) |
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

## 12. Ephemeral listen attachment and transport teardown (2026-08-20 redesign)

The previous deterministic `sessionId` / wallet-and-port correlation model is retired.
It is not a compatibility target. A duplex attachment now uses a fresh 32-byte
opaque `pipe_handle`, generated independently for each pipe incarnation. The
handle is not derived from either wallet, port, IP address, or route.

The first `duplex_offer` is a bootstrap message and may be routed to the
receiver's long-lived public user PGP so the mailbox can find the receiver.
The offer carries the initiator's dedicated listen-pipe PGP. After accepting,
the receiver encrypts `duplex_accept` to that advertised pipe PGP, not to the
initiator's long-lived public PGP. The accept carries the receiver's own
dedicated listen-pipe PGP and the negotiated AES key. After this exchange,
duplex control traffic uses the two dedicated pipe PGP identities; the
initiator does not continue using the receiver's public user PGP.
Mailbox and entry SI components must treat all handles as hop-local opaque
values and must not correlate handles across hops.

The SI knowledge boundary is deliberately narrow:

- a mailbox SI knows only its own waiting pool and its own occupied TCP;
- an entry SI knows only its local transport handle and socket lifecycle;
- neither SI learns the end-to-end AES key or the full path;
- no SSE-side `l0_pipe_end`, wallet, connector, or deterministic session notice
  is emitted.

`l0_pipe_end` is now a strict occupied-TCP control line. It is accepted only on
the TCP connection that is already bound to the same opaque `pipe_handle`:

```json
{
  "type": "l0_pipe_end",
  "pipe_handle": "<64 lowercase hex>",
  "reason": "transport_closed"
}
```

It carries no wallet or connector field. A missing, malformed, or mismatched
handle is rejected. An SSE parser must never interpret this object as a
remote teardown command. The normal failure signal for an entry-to-entry
transport is HTTP `410` before a response is committed, or immediate FIN/RST
after a keep-alive response has been committed. The sender observes that
failure and stops its packet loop; it must not continue writing to a dead
destination.

This design prevents a malicious listener from turning a healthy sender into a
packet amplifier: only the currently bound transport can terminate itself, and
reconnect is subject to the existing bounded retry/backoff and occupancy
limits. Cross-hop teardown forwarding, if implemented by SI, is an internal
opaque-handle operation and is never exposed as an application message.

## 13. Occupied-pipe liveness timeout

The sender of an occupied bidirectional pipe is responsible for sending
application data within every two-minute window. When no overlay IPv4 frame
is available, `conet-l0d` sends an encrypted `duplex_ping` application blob
every 60 seconds. This is ordinary duplex data and never a fabricated IP
packet.

Only the exclusive L0 listen SSE applies this inactivity rule; the normal
Chat SSE keeps its mailbox heartbeat semantics. The L0 listener measures
inbound bytes. If no bytes arrive for 120 seconds, it treats the pipe as
abandoned, closes its SSE, and clears the local occupied writer. The peer
observes EOF and must stop writing to that incarnation.

After its own listening SSE has terminated and a replacement listen has
successfully been established, a bidirectional client may issue a new
`l0_connect`. The replacement uses a fresh request and fresh `pipe_handle`;
stale `pipe_tx` state must not be reused. Reconnect remains bounded by the
existing retry/backoff and occupancy limits.

## 14. Main-wallet billing for temporary channels (2026-08-21)

For a proxy request addressed to `mainWallet:port`, `conet-l0d` creates a
fresh, process-memory-only communication wallet and OpenPGP identity for that
line. It registers the temporary user PGP and route key with the existing
AddressPGP registration API before sending the identity's first mailbox
command. The temporary wallet is therefore routable, but is never the payer.

The mailbox command keeps the temporary wallet in `walletAddress` and carries
the configured paid account in `billingWallet`. Its EIP-191 signature is made
by the paid account. CoNET-SI verifies the signature against
`billingWallet`, while retaining `walletAddress` as the routing and mailbox
subject, and charges hop usage to the billing wallet. If `billingWallet` is
absent, SI preserves the legacy rule that the signer must recover to
`walletAddress`.

Every accepted proxy line has an independent temporary wallet, PGP
registration, AES key, occupied pipe, opaque handle, and upstream socket.
Multiple clients may share a logical proxy port without sharing any of these
identities or transport resources. Registration or billing failure is
fail-closed; it must not silently fall back to an unregistered temporary
route.
