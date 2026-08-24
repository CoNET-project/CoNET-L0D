# `web3://` 应用运行时 — MVP

对应英文版：[`MVP.md`](MVP.md)

修订：2026-08-22

## 1. 产品边界

`web3://` 是构建于 CoNET Layer Minus（L0）之上的钱包地址化应用协议。
它为应用提供稳定的目标名称，由 L0 提供加密入口路由、mailbox 投递和双向传输。

`conet-l0d` 是该协议的 Linux 运行时：

- Linux 服务器用 `--proxy` 或 `--proxyDuplex` 发布本地服务；
- Linux 客户端用 `--clientDuplex` 访问
  `web3://<wallet-or-tag>:<port>` 目标；
- Windows、macOS、Android、iOS 上的浏览器和原生应用在客户端代码中实现同一应用协议，并使用已有 L0 entry，无需 Linux daemon。

公开 L1 节点加入方式仍是现有公网 P2P 路径。通过 L0 承载部分 L1 数据流，
是同一应用传输的独立实验用途。

## 2. MVP 能力

### 2.1 寻址

运行时接受显式钱包地址化目标：

```text
web3://0x1111111111111111111111111111111111111111:4200
web3://ExactTag.web3:4200
```

EOA 是无歧义目标。BeamioTag 必须按大小写精确匹配；存在歧义的搜索结果必须拒绝。

应用 locator、付费钱包、通信身份、validator 身份和 fee recipient 是彼此独立的角色。

### 2.2 Linux 服务器 profile

请求/响应服务使用：

```bash
conet-l0d start \
  --mainWallet 0x<main-paid-wallet> \
  --proxy 127.0.0.1:8080 \
  --config /etc/conet-l0d.toml
```

持续双向服务使用：

```bash
conet-l0d start \
  --mainWallet 0x<main-paid-wallet> \
  --proxyDuplex 127.0.0.1:4200 \
  --config /etc/conet-l0d.toml
```

`--proxy` 承载有边界的请求/响应交换。
`--proxyDuplex` 承载持续原始字节流，并保持写入顺序。

### 2.3 Linux 客户端 profile

```bash
conet-l0d start \
  --mainWallet 0x<main-paid-wallet> \
  --clientDuplex web3://0x<destination-wallet>:4200 \
  --config /etc/conet-l0d.toml
```

每个 `--clientDuplex` 目标在 `127.0.0.1` 上提供一个本地 TCP
endpoint。同一逻辑口可对应多条远端；每条远端各自一个 loopback 监听。
daemon 向该目标开启付费 L0 line，并在任一侧关闭前持续双向转发字节。

### 2.4 浏览器与原生客户端

浏览器或原生客户端直接执行同一协议步骤：

1. 解析 `web3://` 目标；
2. 解析精确钱包身份；
3. 为出站工作选择已有 Entry A，为 mailbox 工作选择 Entry C；
4. 按要求用 user key 或 route key 加密命令；
5. 验证调用方签名的请求合同，并按 request ID、nonce 与 expiry 关联每个已解密响应；
6. 网络尝试失败时保留最后一次可信状态。

浏览器实现是 Windows、macOS、Android、iOS 的可移植客户端路径。产品代码不得在日志中
暴露私钥、session key、明文 payload 或完整密文。

## 3. Runtime 到 L0 的映射

Linux runtime 用已部署的 Layer Minus attachment 命令与版本化应用消息组合出
应用 profile：

| 应用需求 | Runtime 或 wire 机制 |
|---|---|
| 发布本地请求/响应服务 | `--proxy` / `[[l0.proxies]]` runtime profile |
| 发布持续双向服务 | `--proxyDuplex` / `[[l0.proxy_duplex]]` runtime profile |
| 向目标开启付费 line | 已部署 SI 命令 `l0_connect` |
| 接收 line | 已部署 SI 命令 `l0_listen` |
| 协调 duplex attachment | 应用消息 `duplex_offer` / `duplex_accept` |
| 关闭 occupied line | 该 line 上的 `l0_pipe_end` |

`--proxy`、`--proxyDuplex` 与 `duplex_*` 都不是 SI 命令。它们是建立在
现有 L0 attachment 合同上的 `conet-l0d` runtime profile 或 peer 应用消息。

出站应用工作经已有 Entry A；mailbox listen 与 route 命令经已有 Entry C。两者都不能是
目标 mailbox B。

HTTP body 必须始终只有：

```json
{ "data": "<OpenPGP armor>" }
```

Mailbox 指令必须进入加密工作包，绝不能成为额外 HTTP 明文字段。

## 4. 身份与计费

main paid wallet 签署付费 line 命令。多端口服务器为每个逻辑端口使用独立通信身份，
因为 SI exclusive occupancy 对每个 listen wallet 只允许一条 line。

建议 ownership：

| Secret | 建议 owner |
|---|---|
| main wallet 签名密钥 | 仅 root 可读的服务 secret |
| main wallet PGP key | 仅 root 可读的服务 secret |
| 每端口通信 EOA key | 仅 root 可读的服务 secret |
| 每端口通信 PGP key | 仅 root 可读的服务 secret |
| mailbox route PGP key | 仅 root 可读的服务 secret |

命令输出和日志都不得打印私钥。

## 5. 配置

公开样例是 [`../config/conet-l0d.example.toml`](../config/conet-l0d.example.toml)。
其主 profile 为：

```toml
[l0]
enabled = true
client_duplex = [
  "web3://0x<destination-wallet>:4200",
]

[[l0.proxies]]
host = "127.0.0.1"
port = 8080

[[l0.proxy_duplex]]
host = "127.0.0.1"
port = 4200
```

生产环境应为不同 server/client 角色使用独立配置文件。

## 6. CLI 合同

```bash
conet-l0d check-config --config /etc/conet-l0d.toml
conet-l0d resolve web3://0x1111111111111111111111111111111111111111:4200 \
  --config /etc/conet-l0d.toml
conet-l0d start --config /etc/conet-l0d.toml
conet-l0d status --config /etc/conet-l0d.toml
conet-l0d stop --config /etc/conet-l0d.toml
conet-l0d teardown --config /etc/conet-l0d.toml
```

`check-config` 和 `resolve` 不修改状态。`start`、`stop`、`teardown` 只管理该 daemon
自己的运行时状态。

## 7. 验收条件

满足以下条件即通过 MVP：

1. 样例配置可解析并通过校验；
2. `--proxy` 可转发请求并返回关联响应；
3. `--proxyDuplex` 可转发持续、有序数据流；
4. `--clientDuplex` 可提供本地 endpoint 并到达精确 `web3://` 目标；
5. 强制 Entry A / Entry C 路由并排除 mailbox B；
6. 重复或过期 line 控制帧不会破坏其他 session；
7. `l0_pipe_end` 与 socket close 可确定性释放 line ownership；
8. daemon 重启不要求重启被发布的应用；
9. 日志包含 route/session metadata，但不包含 secret material；
10. 英中公开文档描述同一协议。

## 8. 非目标

- 替换公开 L1 节点加入路径；
- 在已有 primitive 足够时另造 L0 wire protocol；
- 发明新域名或 SI 命令；
- 把 billing、validator 或 fee-recipient 角色嵌入应用 locator；
- 从 TCP 应用 profile 承诺通用 UDP 语义。

## 9. 交付顺序

1. 精确 `web3://` 解析与配置校验；
2. 请求/响应 server profile；
3. duplex server profile；
4. duplex Linux client profile；
5. 浏览器/原生客户端互操作；
6. replay、reconnect、close 与失败路径测试；
7. 应用路径稳定后再添加可选 L1 研究 profile。

## GuardianNodesInfoV6 SI 池
L0 默认启用 `si_pool_from_contract = true`：通过配置的 RPC 分页读取 GuardianNodesInfoV6，随机选择 TCP `:80` 可达的 SI，并对失败节点冷却。静态 entries 仅作可选回退；该机制不改变现有 duplex 角色或多远端本地绑定语义。
