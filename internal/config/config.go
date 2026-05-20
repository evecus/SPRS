package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type TCPMode string
type UDPMode string

const (
	TCPModeOff    TCPMode = "off"
	TCPModeRedir  TCPMode = "redir"
	TCPModeTProxy TCPMode = "tproxy"
	TCPModeTun    TCPMode = "tun"
)

const (
	UDPModeOff    UDPMode = "off"
	UDPModeTProxy UDPMode = "tproxy"
	UDPModeTun    UDPMode = "tun"
)

type ProxyModes struct {
	TCP TCPMode
	UDP UDPMode
}

func (pm ProxyModes) NeedsTProxyInbound() bool   { return pm.TCP == TCPModeTProxy || pm.UDP == UDPModeTProxy }
func (pm ProxyModes) NeedsRedirectInbound() bool  { return pm.TCP == TCPModeRedir }
func (pm ProxyModes) NeedsTunInbound() bool       { return pm.TCP == TCPModeTun || pm.UDP == UDPModeTun }
func (pm ProxyModes) NeedsAnyInbound() bool {
	return pm.NeedsTProxyInbound() || pm.NeedsRedirectInbound() || pm.NeedsTunInbound()
}

type Config struct {
	// 必填
	Run  string `json:"run"`
	Mode string `json:"mode"`

	// 端口
	DNSPort      int    `json:"dns_port"`
	RedirectPort int    `json:"redirect_port"`
	TProxyPort   int    `json:"tproxy_port"`
	TunName      string `json:"tun_name"`

	// 功能开关
	HijackDNS bool `json:"hijack_dns"`
	IPv6      bool `json:"ipv6"`
	LAN       bool `json:"lan"`
	FakeIP    bool `json:"fakeip"`

	FakeIPv4Range string `json:"fakeip_v4_range"`
	FakeIPv6Range string `json:"fakeip_v6_range"`

	// 额外 mark 豁免（可选，不影响 group 豁免）
	// 带此 mark 的流量在 nft 规则和路由中均被跳过
	BypassMark uint32 `json:"mark"`

	// 额外豁免 GID（数值，与 mark 豁免完全独立）
	// 这些 GID 的进程流量不走代理，等同于 sprs 组
	BypassGIDs []uint32 `json:"bypass_gids"`

	// 启动等待
	StartWaitTime        int      `json:"start_wait_time"`   // 启动后等待 N 秒再配规则/启核心，0=不等
	WaitProcess          []string `json:"wait_process"`      // 等待这些完整进程名全部出现后再启动
	WaitProcessTimeout   int      `json:"wait_process_timeout"` // 等待超时秒数，0=永久等待

	// 进程管理
	RestartOnFail bool `json:"restart_on_fail"`
	MaxRestarts   int  `json:"max_restarts"`
	Keepalive     bool `json:"keepalive"`
	WatchInterval int  `json:"watch_interval"`
	StartTimeout  int  `json:"start_timeout"`

	// 资源限制
	MaxMemoryMB           int     `json:"max_memory_mb"`
	MaxCPUPct             float64 `json:"max_cpu_percent"`
	ResourceCheckInterval int     `json:"resource_check_interval"`

	// 定时重启
	CronRestart bool   `json:"cron_restart"`
	CronExpr    string `json:"cron_expr"`
}

func (c Config) Filled() Config {
	if c.Mode == "" {
		c.Mode = "tproxy"
	}
	if c.TunName == "" {
		c.TunName = "tun0"
	}
	if c.FakeIPv4Range == "" {
		c.FakeIPv4Range = "198.18.0.0/15"
	}
	if c.FakeIPv6Range == "" {
		c.FakeIPv6Range = "fc00::/18"
	}
	if c.WatchInterval <= 0 {
		c.WatchInterval = 5
	}
	if c.StartTimeout <= 0 {
		c.StartTimeout = 3
	}
	if c.ResourceCheckInterval <= 0 {
		c.ResourceCheckInterval = 10
	}
	return c
}

func (c Config) Modes() ProxyModes {
	switch strings.ToLower(c.Mode) {
	case "redir":
		return ProxyModes{TCP: TCPModeRedir, UDP: UDPModeOff}
	case "tproxy":
		return ProxyModes{TCP: TCPModeTProxy, UDP: UDPModeTProxy}
	case "mixed":
		return ProxyModes{TCP: TCPModeTProxy, UDP: UDPModeTun}
	case "tun":
		return ProxyModes{TCP: TCPModeTun, UDP: UDPModeTun}
	default:
		return ProxyModes{TCP: TCPModeTProxy, UDP: UDPModeTProxy}
	}
}

func (c Config) Validate() error {
	if c.Run == "" {
		return fmt.Errorf("run is required")
	}
	switch strings.ToLower(c.Mode) {
	case "redir", "tproxy", "mixed", "tun", "":
	default:
		return fmt.Errorf("unknown mode %q (valid: redir, tproxy, mixed, tun)", c.Mode)
	}
	modes := c.Modes()
	if modes.NeedsTProxyInbound() && c.TProxyPort == 0 {
		return fmt.Errorf("tproxy_port is required for mode %q", c.Mode)
	}
	if modes.NeedsRedirectInbound() && c.RedirectPort == 0 {
		return fmt.Errorf("redirect_port is required for mode %q", c.Mode)
	}
	if modes.NeedsTunInbound() && c.TunName == "" {
		return fmt.Errorf("tun_name is required for mode %q", c.Mode)
	}
	if c.HijackDNS && c.DNSPort == 0 {
		return fmt.Errorf("dns_port is required when hijack_dns = true")
	}
	if c.CronRestart && c.CronExpr == "" {
		return fmt.Errorf("cron_expr is required when cron_restart = true")
	}
	if c.MaxMemoryMB < 0 {
		return fmt.Errorf("max_memory_mb must be >= 0")
	}
	if c.MaxCPUPct < 0 || c.MaxCPUPct > 100 {
		return fmt.Errorf("max_cpu_percent must be between 0 and 100")
	}
	if c.WaitProcessTimeout < 0 {
		return fmt.Errorf("wait_process_timeout must be >= 0")
	}
	if c.StartWaitTime < 0 {
		return fmt.Errorf("start_wait_time must be >= 0")
	}
	return nil
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}
	var cfg Config
	switch {
	case strings.HasSuffix(strings.ToLower(path), ".toml"):
		if err := parseTOML(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse toml: %w", err)
		}
	default:
		if err := json.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse json: %w", err)
		}
	}
	filled := cfg.Filled()
	if err := filled.Validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}
	return &filled, nil
}

// ── TOML parser ───────────────────────────────────────────────────────────

func parseTOML(data []byte, cfg *Config) error {
	lines := strings.Split(string(data), "\n")
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		// strip inline comment
		if ci := strings.Index(val, " #"); ci >= 0 {
			val = strings.TrimSpace(val[:ci])
		}
		if err := setField(cfg, key, val); err != nil {
			return fmt.Errorf("key %q: %w", key, err)
		}
	}
	return nil
}

func setField(cfg *Config, key, val string) error {
	// strip surrounding quotes for strings
	unquote := func(s string) string {
		if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
			return s[1 : len(s)-1]
		}
		return s
	}

	b, berr := boolVal(val)
	i, ierr := intVal(val)
	f, ferr := floatVal(val)
	u, uerr := uintVal(val)

	switch key {
	// strings
	case "run":              cfg.Run = unquote(val)
	case "mode":             cfg.Mode = unquote(val)
	case "tun_name":         cfg.TunName = unquote(val)
	case "fakeip_v4_range":  cfg.FakeIPv4Range = unquote(val)
	case "fakeip_v6_range":  cfg.FakeIPv6Range = unquote(val)
	case "cron_expr":        cfg.CronExpr = unquote(val)
	// string array: wait_process = ["sing-box", "mosdns"]
	case "wait_process":
		cfg.WaitProcess = parseStringArray(val)
	// ints
	case "dns_port":                if ierr == nil { cfg.DNSPort = i };               return ierr
	case "redirect_port":           if ierr == nil { cfg.RedirectPort = i };           return ierr
	case "tproxy_port":             if ierr == nil { cfg.TProxyPort = i };             return ierr
	case "max_restarts":            if ierr == nil { cfg.MaxRestarts = i };            return ierr
	case "watch_interval":          if ierr == nil { cfg.WatchInterval = i };          return ierr
	case "start_timeout":           if ierr == nil { cfg.StartTimeout = i };           return ierr
	case "max_memory_mb":           if ierr == nil { cfg.MaxMemoryMB = i };            return ierr
	case "resource_check_interval": if ierr == nil { cfg.ResourceCheckInterval = i };  return ierr
	case "start_wait_time":         if ierr == nil { cfg.StartWaitTime = i };          return ierr
	case "wait_process_timeout":    if ierr == nil { cfg.WaitProcessTimeout = i };     return ierr
	// uint32
	case "mark":                    if uerr == nil { cfg.BypassMark = u };             return uerr
	// uint32 array: bypass_gids = [1000, 65534]
	case "bypass_gids":
		cfg.BypassGIDs = parseUint32Array(val)
		return nil
	// float
	case "max_cpu_percent":         if ferr == nil { cfg.MaxCPUPct = f };              return ferr
	// bools
	case "hijack_dns":     if berr == nil { cfg.HijackDNS = b };     return berr
	case "ipv6":           if berr == nil { cfg.IPv6 = b };           return berr
	case "lan":            if berr == nil { cfg.LAN = b };            return berr
	case "fakeip":         if berr == nil { cfg.FakeIP = b };         return berr
	case "restart_on_fail": if berr == nil { cfg.RestartOnFail = b }; return berr
	case "keepalive":      if berr == nil { cfg.Keepalive = b };      return berr
	case "cron_restart":   if berr == nil { cfg.CronRestart = b };    return berr
	}
	return nil
}

// parseStringArray parses TOML inline arrays: ["a", "b", "c"] or ["a"]
func parseStringArray(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		// single bare value
		v := strings.Trim(s, `"`)
		if v == "" {
			return nil
		}
		return []string{v}
	}
	s = s[1 : len(s)-1]
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"`)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

// parseUint32Array parses TOML inline arrays of integers/hex: [1000, 0xff, 65534]
func parseUint32Array(s string) []uint32 {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		// single bare value
		if v, err := uintVal(strings.TrimSpace(s)); err == nil {
			return []uint32{v}
		}
		return nil
	}
	s = s[1 : len(s)-1]
	var result []uint32
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if v, err := uintVal(part); err == nil {
			result = append(result, v)
		}
	}
	return result
}

func boolVal(s string) (bool, error) {
	switch strings.ToLower(s) {
	case "true", "yes", "1":
		return true, nil
	case "false", "no", "0":
		return false, nil
	}
	return false, fmt.Errorf("invalid bool %q", s)
}

func intVal(s string) (int, error) {
	var v int
	_, err := fmt.Sscan(s, &v)
	return v, err
}

func uintVal(s string) (uint32, error) {
	// support hex (0x...) and decimal
	s = strings.TrimSpace(s)
	var v uint64
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		_, err := fmt.Sscanf(s, "%v", &v)
		return uint32(v), err
	}
	_, err := fmt.Sscan(s, &v)
	return uint32(v), err
}

func floatVal(s string) (float64, error) {
	var v float64
	_, err := fmt.Sscan(s, &v)
	return v, err
}

// ── Example config ────────────────────────────────────────────────────────

func ExampleTOML() string {
	return `# sprs 配置文件
# 布尔值不填写默认为 false

# 代理核心启动命令（必填）
run = "/usr/bin/sing-box -c /etc/sing-box/config.json"

# 透明代理模式（必填）
# redir  → 仅 TCP，NAT redirect，兼容最旧内核
# tproxy → TCP + UDP，需内核 >= 5.2
# mixed  → TCP 走 tproxy，UDP 走 TUN
# tun    → TCP + UDP 全走 TUN
mode = "tproxy"

# ── 端口 ──────────────────────────────────────────────────────
tproxy_port   = 7893    # tproxy 入站端口（mode = tproxy/mixed 时必填）
# redirect_port = 7892  # redir 入站端口（mode = redir 时必填）
# dns_port      = 5353  # 代理 DNS 端口（hijack_dns = true 时必填）
# tun_name      = "tun0"  # TUN 网卡名（mode = tun/mixed 时必填）

# ── 功能开关 ──────────────────────────────────────────────────
hijack_dns = false   # 劫持 :53 → dns_port
ipv6       = false   # 启用 IPv6 规则
lan        = false   # 代理局域网设备（自动开启 ip_forward）
fakeip     = false   # FakeIP 模式

# FakeIP 地址池（不填使用 sing-box 默认值）
# fakeip_v4_range = "198.18.0.0/15"
# fakeip_v6_range = "fc00::/18"

# ── mark 豁免（可选）─────────────────────────────────────────
# 带此 fwmark 的流量跳过所有代理规则和路由，不依赖 group
# 不填则不开启此功能（group 豁免始终有效）
# mark = 0xff

# ── GID 豁免（可选）──────────────────────────────────────────
# 额外指定的 GID，这些 GID 的进程流量不走代理，等同于 sprs 组
# 与 mark 豁免完全独立，互不影响
# bypass_gids = [1000, 65534]

# ── 启动等待 ──────────────────────────────────────────────────
# sprs 启动后先等待 N 秒再配置规则和路由（0 或不填 = 不等待）
# start_wait_time = 5

# 等待指定完整进程名全部出现后再启动（不填 = 不等待）
# 进程名为完整名称，不支持模糊匹配
# wait_process = ["mosdns", "NetworkManager"]

# 等待进程超时秒数（0 或不填 = 永久等待）
# wait_process_timeout = 30

# ── 进程管理 ──────────────────────────────────────────────────
restart_on_fail = true   # 异常退出时自动重启
max_restarts    = 5      # 最大重启次数（0 = 不限）
keepalive       = true   # 进程被意外杀死时自动拉起
watch_interval  = 5      # 保活探测间隔（秒）
start_timeout   = 3      # 启动确认：进程启动后等待 N 秒确认没有立即崩溃

# ── 资源限制（超限则重启核心，规则/路由不动）─────────────────
# 两项都为 0 时不启动资源监控
max_memory_mb           = 0     # 内存上限 MB（0 = 不限）
max_cpu_percent         = 0     # CPU 上限 %（0 = 不限，例如 90.0）
resource_check_interval = 10    # 资源检查间隔（秒）

# ── 定时重启 ──────────────────────────────────────────────────
# 按 cron 定时重启核心（规则和路由保持不变，只重启进程）
cron_restart = false
# cron_expr  = "0 3 * * *"   # 每天凌晨 3 点
`
}
