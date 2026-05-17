// Package firewall manages nftables rules and ip rules/routes.
// Rule generation logic ported directly from Singa's internal/firewall/nft.go.
package firewall

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/tproxyng/internal/config"
)

const (
	nftTable = "tproxyng"
	nftConf  = "/tmp/tproxyng.nft"

	// TProxy mark/mask (Singa: 0x40/0xc0)
	tpFwMark = "0x40"
	tpFwMask = "0xc0"
	tpTable  = 100

	// TUN mark/mask (Singa: 0x41/0xc1)
	tunFwMark = "0x41"
	tunFwMask = "0xc1"
	tunTable  = 101
)

// ── Singa's fakeip-aware private range functions ───────────────────────────

// privateRangesV4 — copied verbatim from Singa nft.go.
// When fakeip=true, 198.18.0.0/15 is exempted so fakeip traffic reaches
// the proxy instead of being short-circuited.
func privateRangesV4(fakeip bool, fakeIPv4Range string) string {
	if fakeip {
		return "" +
			"        fib daddr type { local, broadcast, anycast, multicast } return\n" +
			"        ip daddr != " + fakeIPv4Range + " ip daddr { 0.0.0.0/8, 10.0.0.0/8, " +
			"100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, " +
			"192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, 192.168.0.0/16, " +
			"198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/3 } return\n"
	}
	return "" +
		"        fib daddr type { local, broadcast, anycast, multicast } return\n" +
		"        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, " +
		"169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24, 192.88.99.0/24, " +
		"192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24, 203.0.113.0/24, 224.0.0.0/3 } return\n"
}

// privateRangesV6 — copied verbatim from Singa nft.go.
// When fakeip=true, fc00::/18 is exempted (it is the fakeip IPv6 range).
func privateRangesV6(fakeip bool, fakeIPv6Range string) string {
	if fakeip {
		return "        ip6 daddr != " + fakeIPv6Range + " ip6 daddr { ::/127, fc00::/7, fe80::/10, ff00::/8 } return\n"
	}
	return "        ip6 daddr { ::/127, fc00::/7, fe80::/10, ff00::/8 } return\n"
}

// ── Main table builder (mirrors Singa buildTable) ─────────────────────────

func buildTable(cfg *config.Config, modes config.ProxyModes, gid uint32) string {
	var s strings.Builder

	s.WriteString(fmt.Sprintf("table inet %s {\n", nftTable))

	// Interface address sets — populated after nft -f by SyncLocalIPs
	s.WriteString("    set interface {\n        type ipv4_addr\n        flags interval\n        auto-merge\n    }\n")
	if cfg.IPv6 {
		s.WriteString("    set interface6 {\n        type ipv6_addr\n        flags interval\n        auto-merge\n    }\n")
	}

	// Mark chains — only defined when the mode needs them
	if modes.NeedsTProxyInbound() {
		s.WriteString(`
    chain tp_mark {
        tcp flags & (fin | syn | rst | ack) == syn meta mark set mark | 0x40
        meta l4proto udp ct state new meta mark set mark | 0x40
        ct mark set mark
    }
`)
	}
	if modes.NeedsTunInbound() {
		s.WriteString(fmt.Sprintf(`
    chain tun_mark {
        meta mark set meta mark | %s
        ct mark set meta mark
    }
`, tunFwMark))
	}

	s.WriteString(buildProxyRuleChain(cfg, modes))
	s.WriteString(buildManglePrerouting(cfg, modes, gid))
	s.WriteString(buildMangleOutput(cfg, modes, gid))

	s.WriteString(fmt.Sprintf(`
    chain prerouting_mangle {
        type filter hook prerouting priority mangle - 5; policy accept;
        jump proxy_pre
    }

    chain output_mangle {
        type route hook output priority mangle - 5; policy accept;
        jump proxy_out
    }
`))

	s.WriteString(buildNATChains(cfg, modes, gid))
	s.WriteString("}\n")
	return s.String()
}

// buildProxyRuleChain mirrors Singa's buildProxyRuleChain.
func buildProxyRuleChain(cfg *config.Config, modes config.ProxyModes) string {
	var s strings.Builder
	s.WriteString("\n    chain proxy_rule {\n")

	// Restore ct mark for established flows
	if modes.NeedsTProxyInbound() {
		s.WriteString("        meta mark set ct mark\n")
		s.WriteString(fmt.Sprintf("        meta mark & %s == %s return\n", tpFwMask, tpFwMark))
	}
	if modes.NeedsTunInbound() {
		s.WriteString("        meta mark set ct mark\n")
		s.WriteString(fmt.Sprintf("        meta mark & %s == %s return\n", tunFwMask, tunFwMark))
	}

	// Private / reserved ranges (fakeip-aware, Singa logic)
	s.WriteString(privateRangesV4(cfg.FakeIP, cfg.FakeIPv4Range))
	if cfg.IPv6 {
		s.WriteString(privateRangesV6(cfg.FakeIP, cfg.FakeIPv6Range))
	}

	// Local interface addresses
	s.WriteString("        ip daddr @interface return\n")
	if cfg.IPv6 {
		s.WriteString("        ip6 daddr @interface6 return\n")
	}

	// Skip proxy's DNS port to prevent redirect loops
	if cfg.HijackDNS && cfg.DNSPort > 0 {
		s.WriteString(fmt.Sprintf("        meta l4proto { tcp, udp } th dport %d return\n", cfg.DNSPort))
	}

	// Jump to mark chain based on mode
	switch modes.TCP {
	case config.TCPModeTProxy:
		s.WriteString("        meta l4proto tcp jump tp_mark\n")
	case config.TCPModeTun:
		s.WriteString("        meta l4proto tcp jump tun_mark\n")
	}
	switch modes.UDP {
	case config.UDPModeTProxy:
		s.WriteString("        meta l4proto udp jump tp_mark\n")
	case config.UDPModeTun:
		s.WriteString("        meta l4proto udp jump tun_mark\n")
	}

	s.WriteString("    }\n")
	return s.String()
}

// buildManglePrerouting mirrors Singa's buildManglePrerouting.
func buildManglePrerouting(cfg *config.Config, modes config.ProxyModes, gid uint32) string {
	var s strings.Builder
	s.WriteString("\n    chain proxy_pre {\n")

	// Skip traffic from TUN device (proxy's own packets)
	if modes.NeedsTunInbound() {
		s.WriteString(fmt.Sprintf("        iifname \"%s\" return\n", cfg.TunName))
	}
	// Skip unmarked loopback (proxy's own tproxy packets)
	if modes.NeedsTProxyInbound() {
		s.WriteString(fmt.Sprintf("        iifname \"lo\" mark & %s != %s return\n", tpFwMask, tpFwMark))
	}

	// LAN: intercept forwarded traffic (src != local AND dst != local)
	if cfg.LAN {
		if cfg.IPv6 {
			s.WriteString("        meta nfproto { ipv4, ipv6 } meta l4proto { tcp, udp } fib saddr type != local fib daddr type != local jump proxy_rule\n")
		} else {
			s.WriteString("        meta nfproto ipv4 meta l4proto { tcp, udp } fib saddr type != local fib daddr type != local jump proxy_rule\n")
		}
	}

	// TProxy redirect for marked packets
	if modes.NeedsTProxyInbound() {
		s.WriteString(fmt.Sprintf("        meta nfproto ipv4 meta l4proto { tcp, udp } mark & %s == %s tproxy ip to 127.0.0.1:%d\n",
			tpFwMask, tpFwMark, cfg.TProxyPort))
		if cfg.IPv6 {
			s.WriteString(fmt.Sprintf("        meta nfproto ipv6 meta l4proto { tcp, udp } mark & %s == %s tproxy ip6 to [::1]:%d\n",
				tpFwMask, tpFwMark, cfg.TProxyPort))
		}
	}

	s.WriteString("    }\n")
	return s.String()
}

// buildMangleOutput mirrors Singa's buildMangleOutput.
func buildMangleOutput(cfg *config.Config, modes config.ProxyModes, gid uint32) string {
	var s strings.Builder
	s.WriteString("\n    chain proxy_out {\n")
	s.WriteString(fmt.Sprintf("        skgid %d return\n", gid))
	nfproto := "meta nfproto ipv4"
	if cfg.IPv6 {
		nfproto = "meta nfproto { ipv4, ipv6 }"
	}
	s.WriteString(fmt.Sprintf("        %s meta l4proto { tcp, udp } fib saddr type local fib daddr type != local jump proxy_rule\n", nfproto))
	s.WriteString("    }\n")
	return s.String()
}

// buildNATChains mirrors Singa's buildNATChains.
func buildNATChains(cfg *config.Config, modes config.ProxyModes, gid uint32) string {
	var s strings.Builder

	// DNS redirect chain (only when hijack_dns + dns_port set)
	if cfg.HijackDNS && cfg.DNSPort > 0 {
		dnsV4 := fmt.Sprintf("        ip daddr != 127.0.0.1 meta l4proto { tcp, udp } th dport 53 redirect to :%d\n", cfg.DNSPort)
		dnsV6 := ""
		if cfg.IPv6 {
			dnsV6 = fmt.Sprintf("        ip6 daddr != ::1 meta l4proto { tcp, udp } th dport 53 redirect to :%d\n", cfg.DNSPort)
		}
		s.WriteString(fmt.Sprintf(`
    chain dns_redirect {
        skgid %d return
        meta l4proto { tcp, udp } th dport %d return
%s%s    }
`, gid, cfg.DNSPort, dnsV4, dnsV6))
	}

	// TCP redirect chain for redir mode
	if modes.TCP == config.TCPModeRedir {
		nfproto := "meta nfproto ipv4"
		if cfg.IPv6 {
			nfproto = "meta nfproto { ipv4, ipv6 }"
		}
		v6ranges := ""
		if cfg.IPv6 {
			v6ranges = privateRangesV6(cfg.FakeIP, cfg.FakeIPv6Range)
		}
		s.WriteString(fmt.Sprintf(`
    chain tcp_redirect {
        skgid %d return
%s%s        ip daddr @interface return
        %s meta l4proto tcp redirect to :%d
    }
`, gid, privateRangesV4(cfg.FakeIP, cfg.FakeIPv4Range), v6ranges, nfproto, cfg.RedirectPort))
	}

	// Hook chains
	s.WriteString("\n    chain prerouting_nat {\n")
	s.WriteString("        type nat hook prerouting priority dstnat - 5; policy accept;\n")
	if cfg.HijackDNS && cfg.DNSPort > 0 {
		s.WriteString("        jump dns_redirect\n")
	}
	if modes.TCP == config.TCPModeRedir {
		s.WriteString("        jump tcp_redirect\n")
	}
	s.WriteString("    }\n")

	s.WriteString("\n    chain output_nat {\n")
	s.WriteString("        type nat hook output priority -105; policy accept;\n")
	if cfg.HijackDNS && cfg.DNSPort > 0 {
		s.WriteString("        jump dns_redirect\n")
	}
	if modes.TCP == config.TCPModeRedir {
		s.WriteString("        jump tcp_redirect\n")
	}
	s.WriteString("    }\n")

	return s.String()
}

// ── Routes (mirrors Singa setupRoutes) ────────────────────────────────────

func setupRoutes(cfg *config.Config, modes config.ProxyModes) {
	if modes.NeedsTProxyInbound() {
		setupTProxyRoutes(cfg.IPv6)
	}
	if modes.NeedsTunInbound() {
		setupTunRoutes(cfg)
	}
}

func setupTProxyRoutes(ipv6 bool) {
	cmds := []string{
		fmt.Sprintf("ip rule add fwmark %s/%s table %d", tpFwMark, tpFwMask, tpTable),
		fmt.Sprintf("ip route add local 0.0.0.0/0 dev lo table %d", tpTable),
	}
	if ipv6 {
		cmds = append(cmds,
			fmt.Sprintf("ip -6 rule add fwmark %s/%s table %d", tpFwMark, tpFwMask, tpTable),
			fmt.Sprintf("ip -6 route add local ::/0 dev lo table %d", tpTable),
		)
	}
	for _, c := range cmds {
		if err := runCmd(c); err != nil {
			log.Printf("firewall: tproxy route: %v", err)
		}
	}
}

// setupTunRoutes mirrors Singa's setupTunRoutes exactly.
func setupTunRoutes(cfg *config.Config) {
	dev := cfg.TunName
	cmds := []string{
		fmt.Sprintf("ip rule add fwmark %s/%s table %d", tunFwMark, tunFwMask, tunTable),
		fmt.Sprintf("ip route add default dev %s table %d", dev, tunTable),
	}
	if cfg.FakeIP {
		cmds = append(cmds, fmt.Sprintf("ip route add %s dev %s", cfg.FakeIPv4Range, dev))
	}
	if cfg.IPv6 {
		cmds = append(cmds,
			fmt.Sprintf("ip -6 rule add fwmark %s/%s table %d", tunFwMark, tunFwMask, tunTable),
			fmt.Sprintf("ip -6 route add default dev %s table %d", dev, tunTable),
		)
		if cfg.FakeIP {
			cmds = append(cmds, fmt.Sprintf("ip -6 route add %s dev %s", cfg.FakeIPv6Range, dev))
		}
	}
	for _, c := range cmds {
		if err := runCmd(c); err != nil {
			log.Printf("firewall: tun route: %v", err)
		}
	}
}

func cleanupTProxyRoutes(ipv6 bool) {
	cmds := []string{
		fmt.Sprintf("ip rule del fwmark %s/%s table %d", tpFwMark, tpFwMask, tpTable),
		fmt.Sprintf("ip route del local 0.0.0.0/0 dev lo table %d", tpTable),
	}
	if ipv6 {
		cmds = append(cmds,
			fmt.Sprintf("ip -6 rule del fwmark %s/%s table %d", tpFwMark, tpFwMask, tpTable),
			fmt.Sprintf("ip -6 route del local ::/0 dev lo table %d", tpTable),
		)
	}
	for _, c := range cmds {
		_ = runCmd(c)
	}
}

func cleanupTunRoutes(cfg *config.Config) {
	dev := cfg.TunName
	if dev == "" {
		dev = "tun0"
	}
	cmds := []string{
		fmt.Sprintf("ip rule del fwmark %s/%s table %d", tunFwMark, tunFwMask, tunTable),
		fmt.Sprintf("ip route del default dev %s table %d", dev, tunTable),
		fmt.Sprintf("ip route del %s dev %s", cfg.FakeIPv4Range, dev),
	}
	if cfg.IPv6 {
		cmds = append(cmds,
			fmt.Sprintf("ip -6 rule del fwmark %s/%s table %d", tunFwMark, tunFwMask, tunTable),
			fmt.Sprintf("ip -6 route del default dev %s table %d", dev, tunTable),
			fmt.Sprintf("ip -6 route del %s dev %s", cfg.FakeIPv6Range, dev),
		)
	}
	for _, c := range cmds {
		_ = runCmd(c)
	}
}

// ── IP forward ────────────────────────────────────────────────────────────

func enableIPForward(ipv6 bool) {
	if err := runCmd("sysctl -w net.ipv4.ip_forward=1"); err != nil {
		log.Printf("firewall: ip_forward: %v", err)
	}
	if ipv6 {
		if err := runCmd("sysctl -w net.ipv6.conf.all.forwarding=1"); err != nil {
			log.Printf("firewall: ipv6 forward: %v", err)
		}
	}
}

// ── Interface IP sync (mirrors Singa watcher.go + AddInterfaceIP) ─────────

// SyncLocalIPs adds all current interface CIDRs to the nft sets.
// Called once after nft -f (same as Singa).
func SyncLocalIPs(ipv6 bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("firewall: interface addrs: %v", err)
		return
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		isV6 := ipnet.IP.To4() == nil
		if isV6 && !ipv6 {
			continue
		}
		set := "interface"
		if isV6 {
			set = "interface6"
		}
		cidr := ipnet.String()
		if err := runCmd(fmt.Sprintf("nft add element inet %s %s { %s }", nftTable, set, cidr)); err != nil {
			log.Printf("firewall: sync %s: %v", cidr, err)
		}
	}
}

// ── Apply / Stop (mirrors Singa firewall/manager.go) ──────────────────────

var (
	activeCfg   *config.Config
	activeModes config.ProxyModes
)

// Apply sets up nftables + routes for cfg.
func Apply(cfg *config.Config, gid uint32) error {
	// Clean up any previous state first
	Stop()

	modes := cfg.Modes()
	activeCfg = cfg
	activeModes = modes

	conf := buildTable(cfg, modes, gid)
	if err := os.WriteFile(nftConf, []byte(conf), 0644); err != nil {
		return fmt.Errorf("write nft conf: %w", err)
	}

	setupRoutes(cfg, modes)

	if cfg.LAN {
		enableIPForward(cfg.IPv6)
	}

	if err := runCmd("nft -f " + nftConf); err != nil {
		return fmt.Errorf("nft -f: %w", err)
	}

	SyncLocalIPs(cfg.IPv6)

	// For tun/mixed: routes are applied after the tun device appears.
	// ApplyTunRoutes() is called by the process manager once the device is up.
	return nil
}

// ApplyTunRoutes re-adds tun ip rules/routes after the TUN device appears.
// Mirrors Singa's firewall.ApplyTunRoutes.
func ApplyTunRoutes() {
	if activeCfg == nil {
		return
	}
	setupTunRoutes(activeCfg)
}

// Stop tears down nftables and routes.
func Stop() {
	_ = runCmd(fmt.Sprintf("nft delete table inet %s", nftTable))
	_ = os.Remove(nftConf)

	if activeModes.NeedsTProxyInbound() {
		ipv6 := false
		if activeCfg != nil {
			ipv6 = activeCfg.IPv6
		}
		cleanupTProxyRoutes(ipv6)
	}
	if activeModes.NeedsTunInbound() && activeCfg != nil {
		cleanupTunRoutes(activeCfg)
	}

	activeCfg = nil
	activeModes = config.ProxyModes{}
}

// ── iptables fallback ─────────────────────────────────────────────────────

// UseIPTables returns true when nft is unavailable but iptables is.
func UseIPTables() bool {
	_, nftErr := exec.LookPath("nft")
	_, iptErr := exec.LookPath("iptables")
	return nftErr != nil && iptErr == nil
}

// ApplyIPTables sets up iptables rules as a fallback for older kernels.
// Supports redir (TCP only via REDIRECT) and DNS hijack.
func ApplyIPTables(cfg *config.Config, gid uint32) error {
	modes := cfg.Modes()
	activeCfg = cfg
	activeModes = modes

	// Flush existing rules in our chains
	_ = runCmd("iptables -t mangle -F TPROXYNG_MANGLE 2>/dev/null")
	_ = runCmd("iptables -t nat -F TPROXYNG_NAT 2>/dev/null")
	_ = runCmd("iptables -t mangle -X TPROXYNG_MANGLE 2>/dev/null")
	_ = runCmd("iptables -t nat -X TPROXYNG_NAT 2>/dev/null")

	// DNS hijack via NAT REDIRECT
	if cfg.HijackDNS && cfg.DNSPort > 0 {
		cmds := []string{
			"iptables -t nat -N TPROXYNG_NAT",
			// skip proxy group
			fmt.Sprintf("iptables -t nat -A TPROXYNG_NAT -m owner --gid-owner %d -j RETURN", gid),
			// skip already-redirected DNS
			fmt.Sprintf("iptables -t nat -A TPROXYNG_NAT -p tcp --dport %d -j RETURN", cfg.DNSPort),
			fmt.Sprintf("iptables -t nat -A TPROXYNG_NAT -p udp --dport %d -j RETURN", cfg.DNSPort),
			// redirect :53
			fmt.Sprintf("iptables -t nat -A TPROXYNG_NAT -p tcp --dport 53 -j REDIRECT --to-port %d", cfg.DNSPort),
			fmt.Sprintf("iptables -t nat -A TPROXYNG_NAT -p udp --dport 53 -j REDIRECT --to-port %d", cfg.DNSPort),
			// hook
			"iptables -t nat -A OUTPUT -j TPROXYNG_NAT",
			"iptables -t nat -A PREROUTING -j TPROXYNG_NAT",
		}
		for _, c := range cmds {
			if err := runCmd(c); err != nil {
				log.Printf("firewall(iptables): %v", err)
			}
		}
	}

	// TCP redir via NAT REDIRECT
	if modes.TCP == config.TCPModeRedir {
		setupTProxyRoutes(cfg.IPv6)
		cmds := []string{
			"iptables -t nat -N TPROXYNG_REDIR",
			fmt.Sprintf("iptables -t nat -A TPROXYNG_REDIR -m owner --gid-owner %d -j RETURN", gid),
			// private ranges
			"iptables -t nat -A TPROXYNG_REDIR -d 127.0.0.0/8 -j RETURN",
			"iptables -t nat -A TPROXYNG_REDIR -d 10.0.0.0/8 -j RETURN",
			"iptables -t nat -A TPROXYNG_REDIR -d 172.16.0.0/12 -j RETURN",
			"iptables -t nat -A TPROXYNG_REDIR -d 192.168.0.0/16 -j RETURN",
			fmt.Sprintf("iptables -t nat -A TPROXYNG_REDIR -p tcp -j REDIRECT --to-port %d", cfg.RedirectPort),
			"iptables -t nat -A OUTPUT -p tcp -j TPROXYNG_REDIR",
			"iptables -t nat -A PREROUTING -p tcp -j TPROXYNG_REDIR",
		}
		for _, c := range cmds {
			if err := runCmd(c); err != nil {
				log.Printf("firewall(iptables): %v", err)
			}
		}
	}

	if cfg.LAN {
		enableIPForward(cfg.IPv6)
	}

	return nil
}

// StopIPTables removes iptables rules.
func StopIPTables() {
	cmds := []string{
		"iptables -t nat -D OUTPUT -j TPROXYNG_NAT",
		"iptables -t nat -D PREROUTING -j TPROXYNG_NAT",
		"iptables -t nat -F TPROXYNG_NAT",
		"iptables -t nat -X TPROXYNG_NAT",
		"iptables -t nat -D OUTPUT -p tcp -j TPROXYNG_REDIR",
		"iptables -t nat -D PREROUTING -p tcp -j TPROXYNG_REDIR",
		"iptables -t nat -F TPROXYNG_REDIR",
		"iptables -t nat -X TPROXYNG_REDIR",
	}
	for _, c := range cmds {
		_ = runCmd(c)
	}
	if activeModes.NeedsTProxyInbound() {
		ipv6 := false
		if activeCfg != nil {
			ipv6 = activeCfg.IPv6
		}
		cleanupTProxyRoutes(ipv6)
	}
	activeCfg = nil
	activeModes = config.ProxyModes{}
}

// ── Helper ────────────────────────────────────────────────────────────────

func runCmd(command string) error {
	parts := strings.Fields(command)
	if len(parts) == 0 {
		return nil
	}
	out, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (output: %s)", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}
