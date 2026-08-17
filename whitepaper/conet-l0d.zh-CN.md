# conet-l0d — 在 Layer Minus 上的 L1 overlay

**成对译本：** [English](./conet-l0d.md)  
**Revision：** 2026-08-17（里程碑评估 23:30Z：crate MVP 已验收；P1 出站 + 入站解密/TUN 写回 + EIP-191 listen wrap 已在 crate，mock 测过；未打开生产 SI listen；实验室二进制 `[l0]` 关）  
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

Phase 1 使用 **静态** overlay 对等。第一天不要劫持 discv4 / discv5 UDP。

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
| Overlay TCP 字节 | 对端 **user PGP** | 入口 **A ≠ B** |
| Listen / 控制 | mailbox **B route PGP** | 入口 **C ≠ B** |

HTTP 体只有 `{ "data": "<armor>" }`。本客户端不带 hop-sig 头。HTTP JSON 上不放 `NoPush`。

独立 SI 命令（`p2p_stream_*`、`listenKind: "l1p2p"`）**尚未决定**。在落地前不得写成现役 SI。一旦新增，同一任务必须更新 GitBook L0 协议页 **以及** 两份公开 `conet-l0d` 页。

现有 UDP forward 不是这条路径。

## 8. 生产姿态

slot 关键 gossip（6 秒）继续走 **公网 P2P**。L0 overlay 用于 NAT / 无公网 IP / 备份对等。未测时延前，L0-only 提议者不得当默认。

L0 额外时延在本 Revision 中是 **估计**（每跳数十到数百毫秒），不是实验室实测。

## 9. 安全

- 不得记录私钥、完整 PGP armor 或会话密钥。
- 不得捕获 loopback 或 validator gRPC。
- 混合模式：不得 mark 全部公网 8400/4200/4300。
- 需要 `CAP_NET_ADMIN`；能降权则降权。

## 10. 分期

| 阶段 | 范围 |
| --- | --- |
| **MVP** | **已验收（2026-08-17）。** Linux 命令；TUN + iptables 生命周期；定位符解析；静态对等表；收包计数；L0 客户端桩 |
| **P1** | **已在 crate；实验室可装二进制且 `[l0]` 关。** 在现有 L0 原语上做钱包对钱包 TCP 字节流；静态 overlay bootnode。crate 把 overlay 信封加密给对端 **user PGP**，再 wrap `{ data, NoPush: true }` 给 mailbox **B route PGP**，仅在 `[l0].enabled` 且对端有 user+route PGP 文件与 entry 时 `POST { "data" }`（默认 **关**）。入站：解密 user-PGP armor → overlay 信封 → 原始 IPv4 入队写回 TUN（`routing_key_file` 须为 OpenPGP 私钥证书）**已在 crate**。Listen HTTP+SSE worker **已在 crate**：enabled 加上 `listen_entries`（C ≠ B）、`mailbox_route_pgp_file`（本机 B route **公钥**）、`routing_eoa`、`routing_key_file` 与 `routing_eth_key_file`（hex secp256k1；recovered 地址须等于 `routing_eoa`；不是 OpenPGP）。Listen 命令为 `command: mining` + `listenKind: "chat"`，**不得**带 `Securitykey`，EIP-191 签成 SI `{ message, signMessage }` base64。测试只用 wiremock。**未打开生产 SI listen。** 本评估可把该二进制装到两机实验室，**不**开 `[l0]`。不是现役 mailbox 客户端。在证明双向帧之前不要通告 overlay vIP。 |
| **P2** | 若 discv4/discv5 必须走 L0，再做 datagram 适配器 |
| **P3** | 混合生产（公网 P2P + L0 备份）；实测 RTT |

## 11. 真相来源

| 产物 | 角色 |
| --- | --- |
| [github.com/CoNET-project/CoNET-L0D](https://github.com/CoNET-project/CoNET-L0D) | 公开 crate 真相来源 |
| 本成对白皮书 + `RULES.md` | 设计与工程约束 |
| `docs/MVP.md` | 已验收的 crate MVP |
| `docs/P1.md` | 下一阶段线合同与 `[l0]`（不是现役 SI 命令） |
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
