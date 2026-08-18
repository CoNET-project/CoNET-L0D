# MVP — conet-l0d

**成对：** [English](./MVP.md)  
**Revision：** 2026-08-18（crate MVP 仍验收；授权 L0_ONLY `.45` 通告 overlay vIP；overlay geth + beacon TCP 已证明；追链受 Prysm 限速 — 见 [P1.zh-CN.md](./P1.zh-CN.md)；DHT 掉线恢复与约 17:28Z `restart-beacon` 见 [P2.zh-CN.md](./P2.zh-CN.md)）

公开 how-to：[Applications](https://gitbook.conet.network/applications/conet-l0d.html) · [Developers](https://gitbook.conet.network/developers/conet-l0d.html)

## 目标

交付独立 **Linux 命令** `conet-l0d`：启动创建 TUN + iptables，停止/teardown **只**拆除这些对象。操作员不用手写 `iptables`。

## 范围内

| 项 | 验收 |
| --- | --- |
| 二进制 | `cargo build --release` → `conet-l0d` |
| `check-config` / `resolve` | 任意 OS 可跑；精确解析 `web3://` |
| `start` | Linux + `CAP_NET_ADMIN`：TUN `conet-l0`、本机 vIP `/32`、路由 `100.64.0.0/10`、链 `CONET_L0D` 且 loopback `RETURN` |
| `stop` / SIGINT / SIGTERM | 与 start 相反；pid 来自 state 文件 |
| `teardown` | 守护进程已死后仍能走同一反向路径 |
| 收包循环 | 统计 TUN 上的 IPv4；记录目的 vIP（不含密钥） |
| L0 | crate 桩已验收：统计 TUN IPv4 并记录目的 vIP。现役 overlay `/post` 优先 **SI `l0_listen` / `l0_connect` 占用管道 + 应用层 duplex**（要约走 Chat gossip；接受 / 拒绝 / 帧为占用管道上的 AES）；`duplex_reject` 或无 accept 或无占用管道则 P1 gossip — [P1](./P1.zh-CN.md)。不得声称 SI `duplex_*` 或 `p2p_stream_*` |
| 文档 | 成对白皮书 + 本 MVP + GitBook Applications + Developers |
| 示例 + unit | `config/conet-l0d.example.toml` 与 `systemd/conet-l0d.service`（仅 `start`/`stop`） |

## 范围外（不算 MVP 失败）

- 生产 mailbox 投递（P1 crate 可 POST 现役 `/post`，并解析 SI gossip JSON `{ "data": "<armor>" }`；经授权实验室可开 `[l0]`；2026-08-18 实验室 `.45` 通告 overlay vIP，overlay geth + beacon TCP 已通；合批二进制之后限速是 Prysm initial-sync 约 3.2 块/秒；EL 仍为 `0x0`；只读抽检 `scripts/watch-l0-follow.sh` — 见 [P1.zh-CN.md](./P1.zh-CN.md)）
- 生产 discv4 / discv5（实验室 overlay UDP + 经 L0 的现役 discv5 见 [P2.zh-CN.md](./P2.zh-CN.md)；掉线先 `overlay-dht-steer.sh apply` 清幽灵 conntrack；授权 `.45` `restart-beacon` 仅用于拨号 backoff；DNAT 后 `.45` `ss` 可能显示枢纽公网 `:4200`（原目的，不是漏公网）；不是已关闭的 P2 / 生产产品）
- 代理 validator 或读取 keystore
- 新域名。overlay duplex 是 Chat gossip 上的应用 JSON；不得发明 SI `duplex_*` 或 `p2p_stream_*`
- crate 自己重启 geth / beacon / validator（经授权的**操作员**脚本可以只重启 **`.45`** 做 L0_ONLY；未授权不要动 `.98`；禁止 wipe）

## 命令

```bash
conet-l0d check-config --config config/conet-l0d.example.toml
conet-l0d resolve 'web3://0x1111111111111111111111111111111111111111/p2p/geth'
sudo conet-l0d start --config /etc/conet-l0d.toml
sudo conet-l0d stop --config /etc/conet-l0d.toml
sudo conet-l0d teardown --config /etc/conet-l0d.toml
conet-l0d status --config /etc/conet-l0d.toml
```

## 测试

```bash
cargo test
```

`resolve` / 配置单测须在 macOS 通过。`start` 仅 Linux。

## 同步规则

改本文件、白皮书或 `RULES.md` 时，同一任务更新 GitBook **Applications** 与 **Developers** 的 `conet-l0d` 页。
