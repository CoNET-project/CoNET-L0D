# Lab `:4300` duplex observation (2026-08-18)

**Status:** measurement snapshot — decides **UDP dedicated pipe** vs **batch params**.  
**Window:** `2026-08-18T23:13:45Z` – `23:16:50Z` (~180 s).  
**Method:** bounce **only** `conet-l0d` on `.45` / `.98` (geth / beacon untouched), then `scripts/observe-4300-duplex.sh` UDP bursts to overlay `:4300`.

| Host | Role | Overlay vIP |
| --- | --- | --- |
| `74.208.224.45` | spoke / L0_ONLY | `100.64.0.5` |
| `198.251.77.98` | hub | `100.64.0.6` |

Beacon on `.45` still runs `--no-discovery`; natural discv5 is ~0. Traffic in this window is **synthetic UDP** classified as channel port `4300` (`[[l0.channels]] ports = [4300]`).

## Verdict

1. **Do not build a new “UDP-only occupancy pipe” product now.** `:4300` already has its **own** duplex session (third of three: `8400` / `4200` / `4300`). While pipes were live, `:4300` AES frames were written on that session — TCP and UDP are already isolated at the channel/session layer.
2. **Do not retune `BATCH_MAX_PACKETS` / `BATCH_MAX_BYTES` for UDP now.** Probe bursts (`12` on `.45`, `8` on `.98`) flushed as **exact one-batch-per-burst** on both AES and P1 (`packets=12` / `frame_bytes=2509` every time). `pipe_queue_full=0`. Batch caps are not the bottleneck.
3. **Blocking issue:** all three `l0_connect` pipes die together with **HTTP 404** ~60–70 s after start (`23:13:58Z`), then **all** ports (including `:4300`) fall back to P1 gossip. Fix **pipe durability / reconnect** before any UDP-specific pipe or batch work.

## Window counters

| Metric | `.45` spoke | `.98` hub |
| --- | ---: | ---: |
| duplex AES batches (`:4300`) | **4** | **3** |
| duplex AES packets (`:4300`) | 48 (4×12) | 24 (3×8) |
| P1 batches (`:4300`) | **56** | **33** |
| P1 packets (`:4300`) | 672 | 264 |
| `pipe_queue_full` | 0 | 0 |
| `l0_connect` pipe failed | **3** (all sessions) | **3** |
| POST failed | 0 | 0 |
| TUN `tx_dropped` / `rx_dropped` | 0 / 0 | 0 / 0 |

AES share of `:4300` in the window is tiny (**4/60** spoke batches) because pipes died ~10 s after probes began; the rest is healthy P1 fallback with identical batch shape.

## Timeline

| UTC | Event |
| --- | --- |
| `23:12:51` / `23:12:55` | `conet-l0d` stop/start on `.45` / `.98` (geth/beacon left running) |
| `23:12:57` | duplex offer/accept for **3** sessions (incl. `:4300`) |
| `23:12:57`–`23:13:58` | AES frames on `8400` / `4200` / briefly `4300` |
| `23:13:48` | observation window start; UDP bursts begin |
| `23:13:58`–`23:13:59` | **all** `l0_connect` → `HTTP/1.1 404 Not Found` |
| `23:13:59`–`23:16:50` | `:4300` (and TCP) entirely on **P1** gossip batches |

## Client health after window (no EL/CL restart)

| Host | beacon `connected` | geth `net_peerCount` |
| --- | ---: | ---: |
| `.45` | 1 | `0x1` |
| `.98` | 15 | `0x9` |

## Decision matrix

| Proposal | Data says | Next |
| --- | --- | --- |
| UDP-dedicated pipe (new SI / new occupancy) | **No** — already per-port duplex session | Skip until pipes stay up |
| Raise / lower P1 batch caps for UDP | **No** — burst-sized flushes; no queue full | Skip |
| Fix `l0_connect` 404 + reconnect without full restart | **Yes** — repeated ~60 s death | **Do this first** |
| Re-run this observe after pipe fix | — | Same script; expect AES share ≫ P1 for `:4300` |

## Artifacts

- Script: `scripts/observe-4300-duplex.sh`
- Host outputs: `~/conet-l0d-lab/observe-4300/{t0,t1,window-summary}.txt`

Does **not** close [P1](./P1.md) follow-the-chain. Does **not** claim a production discv5 product ([P2](./P2.md)).
