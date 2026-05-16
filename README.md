# tproxy-core

基于 [Singa](https://github.com/singa) 防火墙逻辑实现的 Linux TProxy 管理工具，用于透明代理 TCP/UDP 流量（含 IPv6），支持 DNS 劫持和 FakeIP 模式。

## 工作原理

```
本机进程发出流量
    │
    ▼
output_mangle (hook output, priority mangle-5)
    └─ proxy_out
           │  skgid tproxy_core → return（代理自身流量直接放行）
           └─ proxy_rule
                  │  私有/保留地址段 → return
                  │  本机接口地址 @interface → return
                  │  代理 DNS 端口 → return（防 DNS 环路）
                  └─ tp_mark（打 fwmark 0x40，存入 ct mark）
    │
    ▼
ip rule: fwmark 0x40/0xc0 → table 100
ip route table 100: local 0.0.0.0/0 dev lo
    │
    ▼
prerouting_mangle (hook prerouting, priority mangle-5)
    └─ proxy_pre
           └─ tproxy → 127.0.0.1:<tport>  （代理 tproxy 入站端口）

DNS 查询（可选）
    │
    ▼
output_nat / prerouting_nat
    └─ dns_redirect
           │  skgid tproxy_core → return
           └─ :53 → :<dport>  （NAT 重定向到代理 DNS 端口）
```

代理进程以 `uid=0 gid=tproxy_core` 运行，nft 规则对该 GID 全程豁免，避免流量循环。

## 环境要求

- Linux 内核 ≥ 5.2（nftables tproxy 支持）
- `nft`（nftables）
- `iproute2`（`ip rule` / `ip route`）
- 以 **root** 运行（需要 `CAP_NET_ADMIN`）

## 安装

从 [Releases](../../releases) 下载对应架构的二进制文件：

```bash
# amd64
curl -Lo /usr/local/bin/trun https://github.com/.../t-linux-amd64
chmod +x /usr/local/bin/trun

# arm64
curl -Lo /usr/local/bin/trun https://github.com/.../t-linux-arm64
chmod +x /usr/local/bin/trun
```

## 使用

```
trun --tport <端口> --run "<命令>" [选项]
```

### 参数说明

| 参数 | 类型 | 必须 | 说明 |
|---|---|---|---|
| `--tport` | int | ✅ | 代理的 tproxy 入站端口 |
| `--run` | string | ✅ | 启动代理的完整命令 |
| `--dport` | int | — | 代理的 DNS 监听端口，设置后开启 DNS 劫持（:53 → :dport） |
| `--ipv6` | bool | — | 启用 IPv6 规则，默认 false |
| `--fakeip` | bool | — | 启用 FakeIP 模式，默认 false |

### 示例

```bash
# 最简：只做 TCP/UDP tproxy，不劫持 DNS
trun --tport 7897 --run "/usr/bin/sing-box -c /etc/sing-box/config.json"

# 完整：tproxy + DNS 劫持 + IPv6 + FakeIP
trun --tport 7897 --dport 5353 --ipv6 --fakeip \
     --run "/usr/bin/sing-box -c /etc/sing-box/config.json"
```

## 功能说明

### DNS 劫持（`--dport`）

不设置时 DNS 流量自由通行。设置后，所有发往 `:53` 的 TCP/UDP 请求（代理进程自身除外）通过 NAT 重定向到代理的 DNS 端口。

### IPv6（`--ipv6`）

关闭时只生成 IPv4 的 nft 规则和 ip rule/route。开启后同时配置：
- `ip6 daddr` 私有段绕过规则
- `tproxy ip6 to [::1]:<tport>`
- `ip -6 rule` / `ip -6 route`

### FakeIP（`--fakeip`）

开启后豁免以下地址段，使 FakeIP 流量能正常到达代理，而不被当作私有地址丢弃：

| 协议 | 地址段 | 说明 |
|---|---|---|
| IPv4 | `198.18.0.0/15` | sing-box FakeIP 默认范围 |
| IPv6 | `fc00::/18` | sing-box FakeIP IPv6 默认范围 |

私有段规则加 `ip daddr != 198.18.0.0/15` 前置条件，使 FakeIP 地址无法命中 return 规则，继续向下走到 `tp_mark`。

### 本机地址绕过

启动时遍历所有网卡，将当前地址填入 nft `@interface` / `@interface6` 集合。命中集合的目标地址直接 return，不进代理。此操作仅在启动时执行一次。

### 组隔离

首次运行时自动创建 `tproxy_core` 系统组（优先使用 `groupadd --system`，不可用时直接写 `/etc/group`）。代理进程以该组启动，nft 的 `skgid` 匹配确保其流量始终绕过所有重定向规则。

## nft 表结构

```
table inet tproxy_core
├── set interface          # 本机 IPv4 地址（启动时填充）
├── set interface6         # 本机 IPv6 地址（启动时填充，--ipv6 时）
├── chain tp_mark          # 打 fwmark 0x40，写入 ct mark
├── chain proxy_rule       # 决策链：私有段/本机地址/DNS 端口 → return，其余打 mark
├── chain proxy_pre        # prerouting mangle：执行 tproxy redirect
├── chain proxy_out        # output mangle：跳过代理 GID，其余进 proxy_rule
├── chain prerouting_mangle→ hook prerouting mangle-5
├── chain output_mangle    → hook output mangle-5
├── chain dns_redirect     # DNS NAT（--dport 时生成）
├── chain prerouting_nat   → hook prerouting dstnat-5（--dport 时）
└── chain output_nat       → hook output -105（--dport 时）
```

## 退出清理

收到 `SIGINT` / `SIGTERM` 时自动：
1. 向代理进程发送 `SIGTERM`
2. 删除 `ip rule` / `ip route`
3. 删除 `nft table inet tproxy_core`
4. 删除临时 nft 配置文件

## 构建

```bash
# 本地构建
go build -o trun .

# 交叉编译
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o t-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o t-linux-arm64 .
```

无外部依赖，纯 Go 标准库。
