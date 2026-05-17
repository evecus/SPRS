package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// ── Proxy modes (mirrors Singa's config.ProxyModes) ───────────────────────

type TCPMode string
type UDPMode string

const (
	TCPModeOff    TCPMode = "off"
	TCPModeRedir  TCPMode = "redir"   // NAT redirect, most compatible
	TCPModeTProxy TCPMode = "tproxy"  // TPROXY, needs kernel >= 5.2
	TCPModeTun    TCPMode = "tun"     // TUN virtual NIC
)

const (
	UDPModeOff    UDPMode = "off"
	UDPModeTProxy UDPMode = "tproxy"
	UDPModeTun    UDPMode = "tun"
)

// ProxyModes bundles independent TCP and UDP mode choices.
// Mirrors Singa's config.ProxyModes exactly.
type ProxyModes struct {
	TCP TCPMode
	UDP UDPMode
}

func (pm ProxyModes) NeedsTProxyInbound() bool {
	return pm.TCP == TCPModeTProxy || pm.UDP == UDPModeTProxy
}
func (pm ProxyModes) NeedsRedirectInbound() bool {
	return pm.TCP == TCPModeRedir
}
func (pm ProxyModes) NeedsTunInbound() bool {
	return pm.TCP == TCPModeTun || pm.UDP == UDPModeTun
}
func (pm ProxyModes) NeedsAnyInbound() bool {
	return pm.NeedsTProxyInbound() || pm.NeedsRedirectInbound() || pm.NeedsTunInbound()
}

// ── Config schema ──────────────────────────────────────────────────────────

// Config is the top-level config file structure.
// All bool fields default to false when absent.
type Config struct {
	// Mode selects the transparent proxy method.
	// "redir"  → TCP only, NAT redirect (widest compat)
	// "tproxy" → TCP + UDP via TPROXY
	// "mixed"  → TCP via TPROXY, UDP via TUN
	// "tun"    → TCP + UDP via TUN
	Mode string `json:"mode"` // required

	// Ports
	DNSPort      int `json:"dns_port"`      // proxy DNS listener port (enables DNS hijack when set)
	RedirectPort int `json:"redirect_port"` // redir inbound port (redir / mixed mode)
	TProxyPort   int `json:"tproxy_port"`   // tproxy inbound port
	TunName      string `json:"tun_name"`   // TUN interface name, default "tun0"

	// Feature flags (absent = false)
	HijackDNS bool `json:"hijack_dns"` // redirect :53 → dns_port
	IPv6      bool `json:"ipv6"`
	LAN       bool `json:"lan"`    // proxy LAN devices, enables ip_forward
	FakeIP    bool `json:"fakeip"`

	// FakeIP address pools (Singa defaults when empty)
	FakeIPv4Range string `json:"fakeip_v4_range"` // default: 198.18.0.0/15
	FakeIPv6Range string `json:"fakeip_v6_range"` // default: fc00::/18

	// Process management
	Run            string `json:"run"`              // required: proxy command
	RestartOnFail  bool   `json:"restart_on_fail"`  // restart on non-zero exit
	MaxRestarts    int    `json:"max_restarts"`      // 0 = unlimited
	Keepalive      bool   `json:"keepalive"`         // restart if process dies unexpectedly
	WatchInterval  int    `json:"watch_interval"`    // keepalive poll interval seconds, default 5

	// Scheduled restart
	CronRestart bool   `json:"cron_restart"`
	CronExpr    string `json:"cron_expr"` // e.g. "0 3 * * *"
}

// Filled returns a copy of c with defaults applied.
func (c Config) Filled() Config {
	if c.Mode == "" {
		c.Mode = "tproxy"
	}
	if c.TunName == "" {
		c.TunName = "tun0"
	}
	if c.FakeIPv4Range == "" {
		c.FakeIPv4Range = "198.18.0.0/15" // Singa default
	}
	if c.FakeIPv6Range == "" {
		c.FakeIPv6Range = "fc00::/18" // Singa default
	}
	if c.WatchInterval <= 0 {
		c.WatchInterval = 5
	}
	if c.MaxRestarts == 0 && c.RestartOnFail {
		c.MaxRestarts = 0 // 0 = unlimited
	}
	return c
}

// Modes derives ProxyModes from Mode string.
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

// Validate returns an error if the config is missing required fields.
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
	return nil
}

// ── Loader ─────────────────────────────────────────────────────────────────

// Load reads and parses a config file. Supports .toml, .json.
// Format is detected from file extension; falls back to JSON.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	ext := strings.ToLower(path)
	switch {
	case strings.HasSuffix(ext, ".toml"):
		if err := parseTOML(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse toml: %w", err)
		}
	default: // .json or unknown
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

// ── Minimal TOML parser (no external deps) ────────────────────────────────
// Supports: string, int, bool scalar values (no arrays/tables needed here).

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
		// strip quotes
		if len(val) >= 2 && val[0] == '"' && val[len(val)-1] == '"' {
			val = val[1 : len(val)-1]
		}
		if err := setField(cfg, key, val); err != nil {
			return fmt.Errorf("key %q: %w", key, err)
		}
	}
	return nil
}

func setField(cfg *Config, key, val string) error {
	b, err := boolVal(val)
	switch key {
	// strings
	case "mode":
		cfg.Mode = val
	case "run":
		cfg.Run = val
	case "tun_name":
		cfg.TunName = val
	case "fakeip_v4_range":
		cfg.FakeIPv4Range = val
	case "fakeip_v6_range":
		cfg.FakeIPv6Range = val
	case "cron_expr":
		cfg.CronExpr = val
	// ints
	case "dns_port":
		cfg.DNSPort, err = intVal(val)
	case "redirect_port":
		cfg.RedirectPort, err = intVal(val)
	case "tproxy_port":
		cfg.TProxyPort, err = intVal(val)
	case "max_restarts":
		cfg.MaxRestarts, err = intVal(val)
	case "watch_interval":
		cfg.WatchInterval, err = intVal(val)
	// bools
	case "hijack_dns":
		if err == nil {
			cfg.HijackDNS = b
		}
	case "ipv6":
		if err == nil {
			cfg.IPv6 = b
		}
	case "lan":
		if err == nil {
			cfg.LAN = b
		}
	case "fakeip":
		if err == nil {
			cfg.FakeIP = b
		}
	case "restart_on_fail":
		if err == nil {
			cfg.RestartOnFail = b
		}
	case "keepalive":
		if err == nil {
			cfg.Keepalive = b
		}
	case "cron_restart":
		if err == nil {
			cfg.CronRestart = b
		}
	}
	return err
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

// ── Example config generator ───────────────────────────────────────────────

// ExampleTOML returns a commented example config.toml string.
func ExampleTOML() string {
	return `# tproxyng config — https://github.com/tproxyng
# All boolean fields default to false when absent.

# Proxy mode: redir | tproxy | mixed | tun
# redir  → TCP only via NAT redirect (widest kernel compat)
# tproxy → TCP + UDP via TPROXY (kernel >= 5.2)
# mixed  → TCP via TPROXY, UDP via TUN
# tun    → TCP + UDP via TUN
mode = "tproxy"

# Command to launch the proxy core (required)
run = "/usr/bin/sing-box -c /etc/sing-box/config.json"

# Ports
tproxy_port   = 7893   # tproxy inbound port (required for tproxy/mixed)
redirect_port = 7892   # redirect inbound port (required for redir)
dns_port      = 5353   # proxy DNS port (required when hijack_dns = true)
# tun_name    = "tun0" # TUN interface name (required for tun/mixed)

# Feature flags
hijack_dns = true    # redirect :53 → dns_port
ipv6       = false   # enable IPv6 rules
lan        = false   # proxy LAN devices (enables ip_forward)
fakeip     = false   # enable FakeIP bypass

# FakeIP address pools (Singa defaults — change only if your proxy uses different ranges)
# fakeip_v4_range = "198.18.0.0/15"
# fakeip_v6_range = "fc00::/18"

# Process management
restart_on_fail = true  # restart proxy on non-zero exit
max_restarts    = 5     # 0 = unlimited
keepalive       = true  # restart if process is killed unexpectedly
watch_interval  = 5     # keepalive poll interval in seconds

# Scheduled restart (cron)
cron_restart = false
# cron_expr  = "0 3 * * *"  # restart at 03:00 every day
`
}
