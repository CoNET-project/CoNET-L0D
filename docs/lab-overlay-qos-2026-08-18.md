# Lab overlay quality — both ends (2026-08-18)

**Status:** measurement snapshot, not a protocol change.  
**Window:** `2026-08-18T18:41:31Z` – `18:56:18Z` (~15 min after the last `conet-l0d` start).  
**Interactive canvas:** `l0-overlay-qos-both-ends.canvas.tsx` (Cursor-managed; this Markdown is the git-backed copy).  
**Does not close** [P1](./P1.md) follow-the-chain. **Does not** claim a production discv5 product ([P2](./P2.md)).

Read-only pull from both lab hosts. No geth / beacon / validator restart for this capture.

| Host | Overlay vIP | Role | Log |
| --- | --- | --- | --- |
| `74.208.224.45` | `100.64.0.5` | L0_ONLY spoke | `/home/peter/conet-l0d-lab/conet-l0d.log` (4.24 MB this process) |
| `198.251.77.98` | `100.64.0.6` | public DHT hub | `/home/peter/conet-l0d-lab/conet-l0d.log` (3.24 MB this process) |

Mailbox **B** = `9977E9A45187DD80`. Listen **C** ≠ B. HTTP `/post` is only `{ "data" }`. Overlay ports: geth `:8400`, beacon TCP `:4200`, discv5 UDP `:4300`.

## Verdict

Mailbox path is **healthy** in this window: zero application-layer loss on both ends.

Overlay TCP quality is **high latency + reordering**, not missing bytes. Overlay RTT is ~475–750 ms versus ~40–55 ms on `.98` public peers (mailbox A/B/C hop + batching).

The only kernel endpoint drop signal is **`.98` `tx_dropped=937`** (qlen
500). The spoke endpoint reports zero drops.

Do **not** treat as overlay loss: `.45` isolate INPUT DROP (L0_ONLY public P2P), or EL `eth_blockNumber=0x0` (CL lag; `Processing blocks` ~3.2/s).

## Sources (this capture)

| Source | Type |
| --- | --- |
| `conet-l0d.log` since last `conet-l0d started` | live logs |
| recorded local overlay endpoint counters | inbound / outbound bytes and drops |
| `ss -tni state established` overlay sockets | TCP RTT / retrans / reorder |
| `sudo ss -tnp` listen SSE to C:80 | listen workers |
| geth `net_peerCount`, beacon `/eth/v1/node/peer_count` + `/syncing` | client health |
| host-isolation INPUT counters | rejected public P2P traffic |

`flushed for POST` is **enqueue**, not HTTP 2xx. Inbound queued / POST accepted are **debug** and stay 0 at default `RUST_LOG=info`. Failures are inferred from warn counters.

## Application-layer counters (this l0d process)

| Counter | .45 spoke | .98 hub | Meaning |
| --- | ---: | ---: | --- |
| flushed POST batches | 1,786 | 1,870 | outbound batches to mailbox A |
| flushed IPv4 packets | 2,793 | 5,736 | datagrams in those batches |
| flushed frame bytes | 291,854 | 4,446,511 | envelope bytes in flushed batches |
| POST failed / refused | 0 / 0 | 0 / 0 | HTTP or dest lookup fail |
| queue-full out / in | 0 / 0 | 0 / 0 | would drop before POST / write-back |
| overlay write-back failed | 0 | 0 | inbound decrypt then local delivery |
| armor refused | 0 | 0 | listen SSE payload rejected |
| listen SSE failed / reconnect | 0 / 0 | 0 / 0 | C→B listen workers |
| batch seq gaps | 0 | 0 | no missing flushed seq |

Listen SSE: `.45` 3 ESTAB to C:80 (one per channel). `.98` 4 ESTAB
(expected 3); one had Send-Q 7144 — mailbox backpressure, not a local
endpoint drop.

## Traffic by overlay port (flushed packets)

Classifier is src **or** dest `8400` / `4200` / `4300`. Beacon TCP (`:4200`) starts at **18:48** after the authorized `.45` `restart-beacon`. Hub bytes are larger because `.45` is catching up.

| Port | .45 packets / bytes | .98 packets / bytes | Role |
| --- | ---: | ---: | --- |
| `:8400` | 396 / 33 KB | 717 / 60 KB | geth overlay ESTAB |
| `:4200` | 1,183 / 80 KB | 1,451 / 1.64 MB | beacon sync download to `.45` |
| `:4300` | 1,214 / 178 KB | 3,568 / 2.74 MB | discv5 UDP on overlay |

Client health at capture: `.45` geth `net_peerCount=0x1`, beacon `connected=1`. `.98` geth `0x9`, beacon `connected=15` including overlay inbound `/ip4/100.64.0.5/tcp/4200`. `.45` beacon `head_slot=783295`, `sync_distance=167206`, `is_syncing=true`. `.98` beacon `head_slot=950501`, `sync_distance=0`.

## Packets per minute (flushed IPv4)

Last minute is a **partial** bucket (capture ~18:56). Both hosts stay ~100 POST/min before beacon restart, then ~130–140 after `:4200` comes up.

| minute | .45 :8400 | .45 :4200 | .45 :4300 | .45 posts | .98 :8400 | .98 :4200 | .98 :4300 | .98 posts |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 18:41 | 54 | 0 | 39 | 62 | 370 | 0 | 970 | 179 |
| 18:42 | 32 | 0 | 80 | 105 | 31 | 0 | 185 | 103 |
| 18:43 | 27 | 0 | 83 | 104 | 28 | 0 | 197 | 103 |
| 18:44 | 22 | 0 | 82 | 101 | 23 | 0 | 173 | 100 |
| 18:45 | 23 | 0 | 86 | 105 | 23 | 0 | 186 | 100 |
| 18:46 | 22 | 0 | 83 | 101 | 22 | 0 | 173 | 97 |
| 18:47 | 22 | 0 | 85 | 102 | 22 | 0 | 189 | 99 |
| 18:48 | 23 | 20 | 75 | 98 | 23 | 23 | 162 | 99 |
| 18:49 | 22 | 188 | 83 | 141 | 22 | 211 | 195 | 139 |
| 18:50 | 23 | 163 | 85 | 141 | 23 | 200 | 187 | 138 |
| 18:51 | 24 | 141 | 85 | 137 | 24 | 174 | 189 | 135 |
| 18:52 | 22 | 141 | 81 | 130 | 22 | 189 | 183 | 128 |
| 18:53 | 22 | 152 | 79 | 135 | 22 | 191 | 167 | 127 |
| 18:54 | 29 | 148 | 81 | 143 | 29 | 179 | 175 | 140 |
| 18:55 | 22 | 158 | 83 | 136 | 22 | 198 | 179 | 135 |
| 18:56 | 7 | 72 | 24 | 45 | 11 | 86 | 58 | 48 |

`.98` 18:41 `:8400` 370 / `:4300` 970 is the first-minute burst after l0d start (not a later steady state).

## Overlay TCP quality (`ss -tni`)

Beacon sync stream: `.98` sent **1,667,798** bytes; `.45` acked the **same**. Retrans on that socket is **1 / 1,540** segments. `.45` `rcv_ooopack` 156 of 1,423 data segments (~11%) and `.98` `reord_seen` 345 — out-of-order from parallel POST, **not** missing bytes.

| Socket | RTT / minrtt | Retrans (live/total) | Bytes sent / acked / recv | Reorder |
| --- | ---: | ---: | ---: | --- |
| `.45` `100.64.0.5:43700` → `.6:8400` geth | 501 / 455 ms | 0 / 6 of 379 segs (1.6%) | 8,335 / 8,272 / 22,096 | rcv_ooopack 2 |
| `.98` `[::ffff:100.64.0.6]:8400` ← `.5:43700` | 476 / 451 ms | 0 / 10 of 372 segs (2.7%) | 22,416 / 22,224 / 8,399 | dsack 2, reord_seen 2 |
| `.45` `:4200` → `198.251.77.98:4200` (DNAT original dest) | 516 / 479 ms | none reported | 10,576 / 10,577 / 1,667,798 | rcv_ooopack 156 |
| `.98` `:4200` ← `100.64.0.5:4200` overlay inbound | 750 / 463 ms | 0 / 1 of 1,540 segs | 1,669,246 / 1,667,798 / 10,576 | reordering 29, reord_seen 345 |
| `.98` public beacon (sample `.50:4210`) | 47 / 44 ms | 0 / 69 of 484k segs | 192 MB / 192 MB / 187 MB | public path, not overlay |

After DNAT, `.45` `ss` may show hub **public** `:4200`. That is the original
destination, not a leaked public path. The lab proof used matching overlay
destination traffic plus host-isolation counters for unsteered public P2P.

## Endpoint counter correlation

The recorded local endpoint **outbound** counter represents bytes entering
`conet-l0d` for POST; the **inbound** counter represents local write-back.
Hub outbound bytes match spoke inbound bytes.

| Path | Source | Dest | Delta |
| --- | ---: | ---: | --- |
| Hub → spoke (beacon-heavy) | `.98` outbound 4.42 MB / 5,740 pkt | `.45` inbound 4.42 MB / 5,755 pkt | +15 pkt on spoke inbound |
| Spoke → hub | `.45` outbound 0.59 MB / 6,365 pkt | `.98` inbound 0.51 MB / 6,356 pkt | bytes off ~80 KB; pkt −9 |
| `.98` `tx_dropped` | 937 | qlen 500 fq_codel | 13.6% of 5,740+937 attempted outbound frames |
| `.45` endpoint drops / errors | 0 | 0 | spoke is not queue-bound |

`.45` flushed packets 2,793 versus 6,365 recorded outbound frames:
unknown-port traffic fails closed at **debug** (not in info logs) and is
never posted. `.98` flushed 5,736 versus 5,740 outbound frames, so almost all
hub overlay frames were classified.

UDP `:4300` conntrack `UNREPLIED=2` on both ends (discv5 probes).

## Do not treat as overlay loss

`.45` host-isolation INPUT DROP (L0_ONLY public P2P; never enters the local
overlay data path):

| Rule | Packets | Bytes |
| --- | ---: | ---: |
| tcp dpt:8400 | 192 | 11,520 |
| udp dpt:8400 | 395 | 58,158 |
| tcp dpt:4200 | 61 | 3,660 |
| udp dpt:4200 | 0 | 0 |
| tcp dpt:4300 | 0 | 0 |
| udp dpt:4300 | 76 | 9,980 |

EL `eth_blockNumber=0x0` on `.45` is CL lag (`sync_distance` 167,206). Overlay already delivers beacon bytes (`Processing blocks` 3.2/s at 18:56Z, processed 783232 / tip 950499).

## Next quality lever (not a restart)

1. Hub local endpoint queue / `conet-l0d` read rate (937 `tx_dropped`, likely UDP).
2. Overlay RTT / reorder from mailbox hops.
3. Not a missing listen SSE, not POST fail, not isolate DROP, not EL `0x0`.

Do not restart geth / beacon / validator to “fix” this snapshot.
