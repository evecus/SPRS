# sprs

Linux 透明代理管理工具，基于 [Singa](https://github.com/singa) 防火墙逻辑实现。支持多种代理模式、DNS 劫持、FakeIP、IPv6、局域网代理、进程保活、资源限制和定时重启。

## 环境要求

- Linux 内核 ≥ 5.2（tproxy/mixed/tun 模式）；redir 模式兼容更旧内核
- `nft`（优先）或 `iptables`（自动降级）
- `iproute2`（`ip rule` / `ip route`）
- 以 **root** 运行

## 安装

从 Releases 下载对应架构的二进制：

```bash
install -m 755 sprs-linux-amd64 /usr/local/bin/sprs
# 或 arm64
install -m 755 sprs-linux-arm64 /usr/local/bin/sprs
```

## 使用

```bash
# 正常运行
sprs -c /etc/sprs/config.toml

# 仅下发规则和路由，然后退出（先清理旧规则再重新配置）
sprs -c /etc/sprs/config.toml --start

# 仅删除规则和路由，然后退出
sprs -c /etc/sprs/config.toml --stop

# 生成示例配置
sprs -example > /etc/sprs/config.toml

# 查看版本
sprs -v
```

## 配置文件

支持 `.toml`（推荐）和 `.json` 格式，由 `-c` 参数指定路径。

### 完整字段说明

| 字段 | 类型 | 必填 | 默认 | 说明 |
|---|---|---|---|---|
| `run` | string | ✅ | — | 代理核心启动命令 |
| `mode` | string | ✅ | — | 代理模式：`redir` / `tproxy` / `mixed` / `tun` |
| `tproxy_port` | int | mode=tproxy/mixed | — | tproxy 入站端口 |
| `redirect_port` | int | mode=redir | — | redir 入站端口 |
| `dns_port` | int | hijack_dns=true | — | 代理 DNS 端口 |
| `tun_name` | string | mode=tun/mixed | `tun0` | TUN 网卡名 |
| `hijack_dns` | bool | — | false | 劫持 :53 → dns_port |
| `ipv6` | bool | — | false | 启用 IPv6 规则 |
| `lan` | bool | — | false | 代理局域网设备，自动开启 ip_forward |
| `fakeip` | bool | — | false | FakeIP 模式 |
| `fakeip_v4_range` | string | — | `198.18.0.0/15` | FakeIP IPv4 地址池 |
| `fakeip_v6_range` | string | — | `fc00::/18` | FakeIP IPv6 地址池 |
| `mark` | uint32 | — | 0（不启用） | 带此 fwmark 的流量跳过代理，支持 `0xff` 十六进制 |
| `start_wait_time` | int | — | 0（不等待） | 启动后等待 N 秒再配规则和启核心 |
| `wait_process` | []string | — | 不等待 | 等待这些进程全部出现后再启动，完整名称精确匹配 |
| `wait_process_timeout` | int | — | 0（永久等待） | wait_process 超时秒数，超时则退出 |
| `restart_on_fail` | bool | — | false | 核心异常退出时自动重启 |
| `max_restarts` | int | — | 0（不限） | 最大重启次数 |
| `keepalive` | bool | — | false | 进程被意外杀死时自动拉起 |
| `watch_interval` | int | — | 5 | 保活探测间隔（秒） |
| `start_timeout` | int | — | 3 | 启动确认秒数，进程在此时间内崩溃视为启动失败并清理规则 |
| `max_memory_mb` | int | — | 0（不限） | 内存上限 MB，超限重启核心 |
| `max_cpu_percent` | float | — | 0（不限） | CPU 上限 %，超限重启核心，例如 `90.0` |
| `resource_check_interval` | int | — | 10 | 资源检查间隔（秒） |
| `cron_restart` | bool | — | false | 启用定时重启 |
| `cron_expr` | string | cron_restart=true | — | cron 表达式，5 字段：`分 时 日 月 周` |

### 代理模式对比

| 模式 | TCP | UDP | 内核要求 | 说明 |
|---|---|---|---|---|
| `redir` | NAT redirect | ✗ | 任意 | 兼容性最好，仅 TCP |
| `tproxy` | TPROXY | TPROXY | ≥ 5.2 | 推荐，TCP+UDP |
| `mixed` | TPROXY | TUN | ≥ 5.2 | TCP 走 tproxy，UDP 走 TUN |
| `tun` | TUN | TUN | ≥ 5.2 | 全走 TUN 虚拟网卡 |

### 常见配置示例

**最简 tproxy**
```toml
run  = "/usr/bin/sing-box -c /etc/sing-box/config.json"
mode = "tproxy"
tproxy_port = 7893
```

**tproxy + DNS 劫持 + FakeIP**
```toml
run  = "/usr/bin/sing-box -c /etc/sing-box/config.json"
mode = "tproxy"
tproxy_port = 7893
dns_port    = 5353
hijack_dns  = true
fakeip      = true
```

**完整配置**
```toml
run  = "/usr/bin/sing-box -c /etc/sing-box/config.json"
mode = "tproxy"
tproxy_port = 7893
dns_port    = 5353
hijack_dns  = true
ipv6        = true
lan         = true
fakeip      = true

mark            = 0xff
start_wait_time = 5
wait_process    = ["mosdns"]
wait_process_timeout = 30

restart_on_fail = true
max_restarts    = 5
keepalive       = true
watch_interval  = 5
start_timeout   = 3

max_memory_mb           = 512
max_cpu_percent         = 90.0
resource_check_interval = 10

cron_restart = true
cron_expr    = "0 3 * * *"
```

## 启动顺序

```
sprs 启动
  │
  ├─ start_wait_time > 0 → sleep N 秒
  │
  ├─ wait_process 不为空 → 轮询 /proc/*/comm，每 5 秒检测一次
  │     超时 → 退出
  │
  ├─ 下发 nft/iptables 规则 + ip rule/route
  │     失败 → 清理已添加内容，退出
  │
  ├─ 启动代理核心（uid=0, gid=sprs）
  │     start_timeout 秒内崩溃 → 清理规则路由，退出
  │
  ├─ keepalive goroutine（可选）
  ├─ 资源监控 goroutine（可选）
  └─ cron 调度 goroutine（可选）
```

## 保护措施

| 场景 | 行为 |
|---|---|
| ip rule/route 命令失败 | 回滚已添加路由，核心不启动，退出 |
| nft -f 失败 | 清理路由，核心不启动，退出 |
| 核心在 start_timeout 内崩溃 | 清理所有规则路由，退出 |
| 核心运行中异常退出（restart_on_fail） | 仅重启进程，规则路由不动 |
| keepalive 检测到进程消失 | 仅重启进程，规则路由不动 |
| 内存/CPU 超限 | 仅重启进程，规则路由不动 |
| cron 定时触发 | 仅重启进程，规则路由不动 |
| SIGTERM / SIGINT | 停进程 → 清规则 → 清路由 |

## nft 规则结构

```
table inet sprs
├── set interface          本机 IPv4 地址（启动时填充）
├── set interface6         本机 IPv6 地址（--ipv6 时）
├── chain tp_mark          打 fwmark 0x40，写 ct mark（tproxy/mixed）
├── chain tun_mark         打 fwmark 0x41，写 ct mark（tun/mixed）
├── chain proxy_rule       决策链：私有段 / 本机地址 / mark 豁免 → return
├── chain proxy_pre        prerouting mangle：tproxy redirect / LAN 转发
├── chain proxy_out        output mangle：跳过 sprs GID 和 bypass mark
├── chain prerouting_mangle  hook prerouting mangle-5
├── chain output_mangle      hook output mangle-5
├── chain dns_redirect     DNS NAT（hijack_dns 时）
├── chain prerouting_nat   hook prerouting dstnat-5
└── chain output_nat       hook output -105
```

## 手动清理

如果 sprs 被 `kill -9` 强杀，规则不会自动清理，手动执行：

```bash
sprs -c config.toml --stop
# 或手动
nft delete table inet sprs 2>/dev/null
ip rule del fwmark 0x40/0xc0 table 100 2>/dev/null
ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null
ip -6 rule del fwmark 0x40/0xc0 table 100 2>/dev/null
ip -6 route del local ::/0 dev lo table 100 2>/dev/null
```

## 构建

```bash
# 本地
go build -o sprs .

# 交叉编译
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o sprs-linux-amd64 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o sprs-linux-arm64 .
```

无外部依赖，纯 Go 标准库。
