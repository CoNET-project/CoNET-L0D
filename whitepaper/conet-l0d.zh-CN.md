# conet-l0d — 在 Layer Minus 上的 L1 overlay

**成对译本：** [English](./conet-l0d.md)  
**Revision：** 2026-08-20（slot 关键指标发表门槛 vs 公网 P2P；多 Guardian / 多 Mailbox 路径多样性；SI `l0_listen` / `l0_connect` 占用管道；应用层 duplex；可选按端口 `[[l0.channels]]`；实验室 overlay TCP/UDP；不是生产 discv5 产品）  
**公开操作说明：** [Applications — L1 overlay daemon](https://gitbook.conet.network/applications/conet-l0d.html)  
**公开开发说明：** [Developers — conet-l0d](https://gitbook.conet.network/developers/conet-l0d.html)

本白皮书是 **L1 节点 overlay + L0 应用组合**。它不修改 CoNET-DLE 多链白皮书，也不把 Layer Minus 变成第二套 IP 网。

改本文件或 `RULES.md` 时，**同一任务**必须更新上面两份 GitBook 页面。禁止公开书停留在旧 Revision。

## 1. 问题

CoNET L1 的 `geth` 与 Prysm `beacon-chain` 只对普通 `IP:port` 做 TCP/UDP。坐在 NAT 后、没有稳定公网地址、或需要 **钱包寻址** 备份路径的操作员，不能改这些客户端源码。他们需要一条 Linux 命令：

1. 给出稳定 overlay 定位符（`web3://…` → overlay IPv4）；
2. **只 catch** 发往该 overlay 的包；
3. 用 Layer Minus（钱包 + OpenPGP，`POST /post`）搬运字节流；
4. **自行持有** TUN 与 iptables：启动安装、停止/teardown 拆除，操作员不用手写 `iptables`。

## 2. 非目标

| 不做 | 原因 |
| --- | --- |
| 改 geth / beacon / validator 源码 | 产品约束：零客户端源码改动 |
| 内核模块 | 用户态守护进程足够 |
| 把 SilentPass / `SaaS_Sock5` 当 L1 P2P | 那些命令是出口去连公网 `host:port` |
| 把现有 L0 UDP forward 当 OS UDP | HTTP/SSE 上的 AES 帧；空闲 10 分钟；不是 discv4 |
| 捕获 `127.0.0.0/8` 或 validator uid | Engine JWT、beacon gRPC、本地 RPC 必须留在本机 |
| 对 `0.0.0.0/0:8400` 做 REDIRECT | 混合模式的公网 P2P 必须继续工作 |
| 新建公网域名 | 复用现有 CoNET / beamio.app 路径 |
| 重启 EL / CL / VA | 生命周期只动本守护进程的网络对象 |

## 3. 架构

```text
geth / beacon
  connect(100.64.x.y : 8400|4200)
        │
   内核路由  100.64.0.0/10 → tun conet-l0
        │
   conet-l0d  （持有 TUN + iptables 链 CONET_L0D）
        │  overlay IP → web3:// 钱包 | tag.web3
        │  业务字节加密给对端 user PGP；listen/控制加密给 mailbox B route PGP
        ▼
   Layer Minus   POST { data: armor }  入口 A ≠ B
        │
   对端 conet-l0d  把 src=对端 vIP 写入对端 TUN
        ▼
   对端 geth / beacon  在 0.0.0.0:port 上 accept()
```

Layer Minus 仍是 [PGP / 钱包转发平面](https://gitbook.conet.network/l0/using-l0.html)。`conet-l0d` 与 Chat、SilentPass 一样，是应用组合，不是新的 L0 协议。

## 4. 身份（`web3://` 定位符）

该 URI 是 **对等定位符**，不是 ERC-4804 内容 URI。

```text
web3://<host>/p2p/<service>

host     = 0x + 40 hex                    → EOA
         | <beamioTag>.web3               → 精确 tag → EOA
service  = geth | beacon
```

解析：

1. 直接 EOA，或 **精确** 匹配 BeamioTag（`CoNET` ≠ `CONET`）。禁止 `search-users` 的 `results[0]`。
2. 在 AddressPGP `0x684b0ac760cEE9c9b85de36d69746420648Cf9e2` 上 `searchKey(EOA)`。
3. 必须有 user PGP 与 mailbox route。没有 AddressPGP 的 AA 不是目的地。
4. 分配或查找 overlay vIP。geth/beacon 只看见 `vIP:port`。

routing EOA ≠ deposit keystore ≠ fee recipient。守护进程不得读取 validator 密钥。

## 5. Catch 路径（客户端不要 bind overlay）

广告旗标 **不是** 监听地址：

| 客户端 | 广告（安全） | 绑定（不要写成 overlay） |
| --- | --- | --- |
| geth | `--nat=extip=<本机 vIP>` | `--http.addr` / `--authrpc.addr` 仍为 `127.0.0.1` |
| beacon | `--p2p-host-ip=<本机 vIP>` | `--rpc-host` / `--grpc-gateway-host` 仍为 `127.0.0.1` |

`--port 8400` 与 `--p2p-tcp-port=4200` 仍听 `0.0.0.0`。本机还没有 overlay 地址 **不会** 让客户端启动失败。overlay bootnode 暂时不可达时，进程仍在，只是 overlay 对等为零。

Phase 1 使用 **静态** overlay 对等。crate 信封已是完整 IPv4（含 UDP）。实验室可以把 beacon `:4300` 拐上 TUN，并让 L0_ONLY 主机经 L0 连公网 DHT 服务器跑 discv5（`docs/P2.zh-CN.md`）。这不是生产 discv5 产品，也不关闭追链门。

## 6. 守护进程持有的网络对象

`start`（若有脏状态则先 teardown）：

1. 创建 TUN `conet-l0`。
2. `ip addr add <本机 vIP>/32 dev conet-l0`。
3. `ip route add 100.64.0.0/10 dev conet-l0`。
4. 创建 iptables 链 `CONET_L0D`（filter + mangle）。
5. 首条规则：`RETURN` `127.0.0.0/8`；可选 `owner --uid-owner <validator>` `RETURN`。
6. 只把 `OUTPUT` / `PREROUTING` 跳进该链。
7. 写 state + pid；进入收包循环。

SIGINT / SIGTERM / `stop` / `teardown`：

1. 删除指向 `CONET_L0D` 的 jump。
2. flush 并 `-X` `CONET_L0D`。
3. 删除 overlay 路由、地址与 TUN。
4. 删除 state 文件。

操作员不用手写 `iptables`。teardown 不得删除他人规则。

## 7. L0 映射（Phase 1）

| 方向 | 加密目标 | HTTP |
| --- | --- | --- |
| `duplex_offer` | 对端 **长期 user PGP** | 入口 **A ≠ B**。Chat gossip 到现有通道 SSE。SI **不解析** `duplex_*` |
| 独占 L0 listen | mailbox **B route PGP** | `l0_listen` 或 `mining` + `listenKind: "l0"`，经 **C ≠ B**。不得带 overlay AES。两套自有 L0 SSE；禁止在对端 B 上 guest listen |
| `l0_connect` | **目标** mailbox **B route PGP** | 占用空闲 L0 SSE；随后同一 TCP 上 AES blob。已占用 → 409 |
| `duplex_accept` / `duplex_reject` | 占用发起方 L0 管道上的 AES | 接收方占用 `W_I` 后的首个 AES blob |
| Overlay IPv4（duplex 数据面） | AES 封 `duplex_frame` JSON；`payload` = `L0D1` \|\| IPv4 的 standard base64 | 占用对端 L0 管道 |
| P1 gossip 回退（`duplex_reject` 或无 accept 或无占用管道） | 对端 **user PGP**，再 wrap 给 **B route PGP** | 入口 **A ≠ B** |

HTTP 体只有 `{ "data": "<armor>" }`。本客户端不带 hop-sig 头。HTTP JSON 上不放 `NoPush`。

Duplex 是 Chat gossip 上的 **应用 JSON**，加上 SI 占用管道上的 AES：`duplex_offer`、`duplex_accept`、`duplex_reject`、`duplex_frame`。发起方附 overlay AES 钥与 **会话 listen 钱包**；接收方拒绝则以 `l0_connect` 占用该 L0 SSE 并发送 `duplex_reject`，同意则回钥并附自己的会话 listen 钱包。规范：[Duplex overlay](https://gitbook.conet.network/l0/duplex-forward.html)。crate MVP 用已登记的按端口通道 EOA 作为会话 listen 身份。**禁止**发 `command: "mining"` + `listenKind: "duplex"`。**禁止**把 SI `duplex_*` / `p2p_stream_*` / `listenKind: "l1p2p"` 写成现役 SI。**要**把现役 SI `l0_listen` / `l0_connect` 写进协议页。

现有 UDP forward 是另一条组合（idle 更短；不是 overlay TCP）。

## 8. 生产姿态

slot 关键 gossip（`SECONDS_PER_SLOT=6`）继续走 **公网 P2P**。L0 overlay 用于 NAT / 无公网 IP / 备份对等。**在** GitBook [slot 关键发表门槛](https://gitbook.conet.network/developers/l1-node.html#slot-critical-publication-gate) **对照公网 P2P 基线填齐之前**，不得把 L0-only 提议者当默认（须发布：L0 RTT P50/P95/P99；区块传到 50% 与 90% 节点的时间；attestation inclusion delay；missed slot；reorg；duplex 重连时间；Guardian 故障切换时间；UDP/discv5 丢包率）。

2026-08-18 约 15 分钟实验室快照：overlay TCP RTT 约 475–750 ms，相对 `.98` 公网 peer 约 40–55 ms。这 **不是** P50/P95/P99，也 **不是** 提议者集合实测。

若 overlay 流量挤在 **少数 Mailbox**，风险会从验证者 **IP** 集中变成 **Guardian 路径** 集中。生产 overlay 必须有多个独立入口、多个 Mailbox、多个 ASN、多个地区、每 overlay 端口独立 Routing EOA（`[[l0.channels]]`），以及自动重连 **并** 切到另一个 B。同一 B 上的按端口 EOA **不能** 消除 Mailbox 集中。占用重试已在 crate 内；跨 Guardian 故障切换不是已交付产品。

## 9. 安全

- 不得记录私钥、完整 PGP armor 或会话密钥。
- 不得捕获 loopback 或 validator gRPC。
- 混合模式：不得 mark 全部公网 8400/4200/4300。
- 需要 `CAP_NET_ADMIN`；能降权则降权。

## 10. 分期

| 阶段 | 范围 |
| --- | --- |
| **MVP** | **已验收（2026-08-17）。** Linux 命令；TUN + iptables 生命周期；定位符解析；静态对等表；收包计数；L0 客户端桩 |
| **P1** | **已在 crate；`[l0]` 默认关。** 钱包对钱包 TCP 字节流。对端应用回 `duplex_accept` 时优先 **应用层 duplex**（现有 Chat gossip）；否则保持 **P1 gossip**（user-PGP 信封 + mailbox wrap）。静态 overlay bootnode。crate 把 overlay 信封加密给对端 **user PGP**，再 wrap `{ data, NoPush: true }` 给 mailbox **B route PGP**，仅在 `[l0].enabled` 且对端有 user+route PGP 文件与 entry 时 `POST { "data" }`。入站：解密 user-PGP armor → overlay 信封 → 原始 IPv4 入队写回 TUN（`routing_key_file` 须为 OpenPGP 私钥证书）**已在 crate**。Listen HTTP+SSE worker **已在 crate**：enabled 加上 `listen_entries`（C ≠ B）、`mailbox_route_pgp_file`（本机 B route **公钥**）、`routing_eoa`、`routing_key_file` 与 `routing_eth_key_file`（hex secp256k1；recovered 地址须等于 `routing_eoa`；不是 OpenPGP）。可选 `[[l0.channels]]` 为 overlay 端口 8400 / 4200 / 4300 各用一个 EOA + SSE（出站加密给该端口的对端 user PGP；按知名源或目的端口分类）。未配 channels 时仍是一个 EOA。`:4300` 是 overlay IPv4，不是 `udp_relay`。应用层 host listen **就是**现有 Chat SSE（`mining` + `listenKind: "chat"`，listen **不得**带 overlay AES）。对端不回 `duplex_accept` 则保持 P1 gossip。EIP-191 签成 SI `{ message, signMessage }` base64。Listen 入站对齐 SI `forWardPGPMessageToClient` 的原始 JSON `{ "data": "<armor>" }`（与 Chat `handleInbound` 相同），不再只认 SSE armor 行。测试只用 wiremock。**经授权**的实验室可开 `[l0]`。**禁止**把 SI `duplex_*` / `p2p_stream_*` / `listenKind: "l1p2p"` 写成现役 SI。**2026-08-17 23:12Z L0-only：** 出站 HTTP 200，无入站 TUN 写回（当时只扫 SSE）。**23:30Z**（只重启 `conet-l0d`）：两机 TUN 均有入站 IPv4，且 overlay geth TCP 已通（`.45` `100.64.0.5` ↔ `.98` `100.64.0.6:8400`）。**2026-08-18：** 授权 L0_ONLY `.45` 通告 overlay vIP `100.64.0.5`；overlay geth + beacon TCP 已 ESTAB；IPv4 合批 + POST 并发 32 / 队列 512（两机必须同升二进制）。该二进制之后 overlay queue-full 为 0；追链剩余限速是 Prysm initial-sync（约 3.2 块/秒、约 15 小时）。EL 仍为 `0x0`。只读抽检：`scripts/watch-l0-follow.sh`。追链门仍开。`.98` 与生产 proposer 仍通告公网 IP。HTTP 200 ≠ 投递。 |
| **P2** | **实验室通讯已验收；不是产品。** crate 已运 IPv4/UDP — 不必再做 datagram 适配器。2026-08-18 实验室：overlay UDP 回声与 `:4300`（直发 + 公网 ENR steer）已到对端 TUN。随后 L0_ONLY `.45` 放弃静态 `--peer`，经 L0 连上 `.98` DHT 服务器（`.98` 用 `--p2p-static-id`；bootstrap ENR；allowlist = overlay + 枢纽公网 `/32`；TCP/UDP steer DNAT；隔离链仍丢未 steer 的公网 P2P）。DNAT 之后 `.45` `ss` 可能显示枢纽公网 `:4200`（原目的，不是漏公网）；overlay 证明是 TUN VIP + 隔离 DROP=0。若后来 `connected` 掉线，先重打 `overlay-dht-steer.sh`（清幽灵 conntrack；**不要**为此重启 EL/CL）。仅当 Prysm 仍停在拨号 backoff 时才 `restart-beacon`（**2026-08-18 约 17:28Z** `.45` 恢复 `connected=1` 与 `Processing blocks`；启动后不要立刻再打 steer）。第一分钟 `suitable=0` 属预期。EL 仍为 `0x0` 而 `head_slot` 在涨 = CL 滞后。见 `docs/P2.zh-CN.md`。 |
| **P3** | 混合生产（公网 P2P + L0 备份）；**已发布** slot 关键指标 vs 公网 P2P；多入口 / 多 Mailbox / 多 ASN 多样性 |

## 11. 真相来源

| 产物 | 角色 |
| --- | --- |
| [github.com/CoNET-project/CoNET-L0D](https://github.com/CoNET-project/CoNET-L0D) | 公开 crate 真相来源 |
| 本成对白皮书 + `RULES.md` | 设计与工程约束 |
| `docs/MVP.md` | 已验收的 crate MVP |
| `docs/P1.md` | Overlay 线合同：应用层 duplex + P1 gossip 回退；`[l0]` |
| `docs/P2.md` | 实验室 overlay UDP / DHT 口通讯 + 经 L0 的现役 discv5（不是已关闭的 P2 / 生产产品） |
| `config/conet-l0d.example.toml` | overlay 表示例 |
| `systemd/conet-l0d.service` | 进程持有 TUN/iptables；unit 不得写裸 `iptables` |
| GitBook Applications | 操作员 how-to（公开书英语） |
| GitBook Developers | CLI、配置、线合同 |
| GitBook L0 | 转发平面 — 不要在此分叉 |

## 相关

- [How to use Layer Minus](https://gitbook.conet.network/l0/using-l0.html)
- [Run an L1 node](https://gitbook.conet.network/developers/l1-node.html)
- [SilentPass](https://gitbook.conet.network/applications/silentpass-vpn.html) — 出口，不是 L1 P2P
- [Wallet-addressed peer identity](https://gitbook.conet.network/l0/wallet-address-p2p.html)

## 12. 临时聆听身份与传输拆线（2026-08-20 重设计）

旧的确定性 `sessionId`、钱包/端口关联方式已经废弃，不再作为兼容目标。
每次双向管道建立都生成新的 32 字节随机 opaque `pipe_handle`。它不能由任一
钱包、端口、IP 或路由推导。

首个 `duplex_offer` 是 bootstrap 请求，可以先加密到接收方长期公共用户
PGP，以便 mailbox 找到接收方。请求中携带发起方专用的 listen 管道 PGP。
接收方接受后，`duplex_accept` 必须加密到请求中提及的
`listenUserPgp`，不能再加密到发起方长期公共用户 PGP。响应携带接收方自己
专用的 listen 管道 PGP 和协商出的 AES 密钥。完成交换后，双向控制流只使用
双方各自的专用管道 PGP；发起方不再使用接收方公共用户 PGP。
Mailbox/Entry SI 只能把 handle 当作本跳 opaque 值，不能跨跳关联。

SI 的知识边界严格限制为：

- mailbox SI 只知道自己的等待池和自己持有的 occupied TCP；
- entry SI 只知道本跳 handle 和 socket 生命周期；
- 任一 SI 都不能获得端到端 AES 密钥或完整路径；
- 不再发送 SSE 侧 `l0_pipe_end`、钱包、connector 或确定性 session 通知。

`l0_pipe_end` 现在只允许作为 occupied TCP 控制行。它必须出现在已经绑定
同一个 opaque `pipe_handle` 的 TCP 连接上：

```json
{
  "type": "l0_pipe_end",
  "pipe_handle": "<64 位小写 hex>",
  "reason": "transport_closed"
}
```

不得携带 wallet 或 connector。缺失、格式错误或不匹配的 handle 必须拒绝。
SSE 解析器绝不能把该对象当成远端拆线命令。entry-to-entry 传输在响应提交前
使用 HTTP `410`，响应已经进入 keep-alive 后立即 FIN/RST；发送方收到失败后
必须停止 packet loop，不得继续向失效目标写包。

这样恶意 listener 不能把健康发送方变成 packet 放大器：只有当前绑定的传输
才能结束自身，重连仍受限于已有的有界 retry/backoff 与占用上限。SI 如需
跨跳传递拆线，只能在内部使用 opaque handle，不能暴露为应用消息。

## 13. occupied 管道存活超时

occupied 双向管道的发送方负责在每个两分钟窗口内发送至少一段应用数据。
没有 overlay IPv4 帧时，`conet-l0d` 每 60 秒发送一个加密的
`duplex_ping` 应用 blob。这是普通双工数据，不是伪造的 IP 数据包。

只有专用 L0 listen SSE 适用该无活动规则；普通 Chat SSE 继续使用 mailbox
自己的 heartbeat 语义。L0 聆听方以收到的字节作为存活信号：连续 120 秒没有
任何入站字节，就将管道视为已废弃，关闭自己的 SSE，并清除本地 occupied
writer。对端观察到 EOF 后必须停止向该管道实例继续写入。

双向 client 只有在自己的聆听 SSE 已终止、并且新的 listen 已成功建立后，
才可以发起新的 `l0_connect`。新连接必须使用新的请求和新的 `pipe_handle`；
不得复用旧的 `pipe_tx`。重连仍受现有 retry/backoff 与占用上限约束。

## 14. 临时通道由主钱包计费（2026-08-21）

当 proxy 请求以 `mainWallet:port` 寻址时，`conet-l0d` 为该线路生成仅存在于
进程内存的临时通信钱包与 OpenPGP 身份，并在发送该身份的第一条 mailbox
命令前，通过现有 AddressPGP 注册接口登记临时用户 PGP 与 route key。临时
钱包因此可以被路由，但绝不是付款方。

Mailbox 命令的 `walletAddress` 保留临时钱包，另携带配置的付费账户
`billingWallet`，并由付费账户制作 EIP-191 签名。CoNET-SI 使用
`billingWallet` 验签，同时保留 `walletAddress` 作为路由和 mailbox subject，
并将 hop 用量记到计费钱包。没有 `billingWallet` 时，SI 保留旧规则：签名
恢复地址必须等于 `walletAddress`。

每条 proxy 线路拥有独立的临时钱包、PGP 登记、AES 密钥、occupied pipe、
opaque handle 与上游 socket。多个 client 可以共享逻辑端口，但不得共享
上述任何身份或传输资源。登记或计费失败必须 fail-closed，不能静默使用
未登记的临时路由。
