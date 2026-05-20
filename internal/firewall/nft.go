package firewall

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/sprs/internal/config"
)

const (
	nftTable  = "sprs"
	nftConf   = "/tmp/sprs.nft"
	tpFwMark  = "0x40"
	tpFwMask  = "0xc0"
	tpTable   = 100
	tunFwMark = "0x41"
	tunFwMask = "0xc1"
	tunTable  = 101
)

// privateRangesV4 — Singa logic verbatim.
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

// privateRangesV6 — Singa logic verbatim.
func privateRangesV6(fakeip bool, fakeIPv6Range string) string {
	if fakeip {
		return "        ip6 daddr != " + fakeIPv6Range + " ip6 daddr { ::/127, fc00::/7, fe80::/10, ff00::/8 } return\n"
	}
	return "        ip6 daddr { ::/127, fc00::/7, fe80::/10, ff00::/8 } return\n"
}

func buildTable(cfg *config.Config, modes config.ProxyModes, gid uint32) string {
	var s strings.Builder
	s.WriteString(fmt.Sprintf("table inet %s {\n", nftTable))

	s.WriteString("    set interface {\n        type ipv4_addr\n        flags interval\n        auto-merge\n    }\n")
	if cfg.IPv6 {
		s.WriteString("    set interface6 {\n        type ipv6_addr\n        flags interval\n        auto-merge\n    }\n")
	}

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
	s.WriteString(buildManglePrerouting(cfg, modes))
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

func buildProxyRuleChain(cfg *config.Config, modes config.ProxyModes) string {
	var s strings.Builder
	s.WriteString("\n    chain proxy_rule {\n")
	if modes.NeedsTProxyInbound() {
		s.WriteString("        meta mark set ct mark\n")
		s.WriteString(fmt.Sprintf("        meta mark & %s == %s return\n", tpFwMask, tpFwMark))
	}
	if modes.NeedsTunInbound() {
		s.WriteString("        meta mark set ct mark\n")
		s.WriteString(fmt.Sprintf("        meta mark & %s == %s return\n", tunFwMask, tunFwMark))
	}
	// bypass mark: skip proxy for traffic with this mark (independent of group)
	if cfg.BypassMark > 0 {
		s.WriteString(fmt.Sprintf("        meta mark 0x%x return\n", cfg.BypassMark))
	}
	s.WriteString(privateRangesV4(cfg.FakeIP, cfg.FakeIPv4Range))
	if cfg.IPv6 {
		s.WriteString(privateRangesV6(cfg.FakeIP, cfg.FakeIPv6Range))
	}
	s.WriteString("        ip daddr @interface return\n")
	if cfg.IPv6 {
		s.WriteString("        ip6 daddr @interface6 return\n")
	}
	if cfg.HijackDNS && cfg.DNSPort > 0 {
		s.WriteString(fmt.Sprintf("        meta l4proto { tcp, udp } th dport %d return\n", cfg.DNSPort))
	}
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

func buildManglePrerouting(cfg *config.Config, modes config.ProxyModes) string {
	var s strings.Builder
	s.WriteString("\n    chain proxy_pre {\n")
	if modes.NeedsTunInbound() {
		s.WriteString(fmt.Sprintf("        iifname \"%s\" return\n", cfg.TunName))
		// loopback protection: skip lo packets without tun mark
		s.WriteString(fmt.Sprintf("        iifname \"lo\" meta mark & %s != %s return\n", tunFwMask, tunFwMark))
	}
	if modes.NeedsTProxyInbound() {
		s.WriteString(fmt.Sprintf("        iifname \"lo\" meta mark & %s != %s return\n", tpFwMask, tpFwMark))
	}
	if cfg.LAN {
		if cfg.IPv6 {
			s.WriteString("        meta nfproto { ipv4, ipv6 } meta l4proto { tcp, udp } fib saddr type != local fib daddr type != local jump proxy_rule\n")
		} else {
			s.WriteString("        meta nfproto ipv4 meta l4proto { tcp, udp } fib saddr type != local fib daddr type != local jump proxy_rule\n")
		}
	}
	if modes.NeedsTProxyInbound() {
		s.WriteString(fmt.Sprintf("        meta nfproto ipv4 meta l4proto { tcp, udp } mark & %s == %s tproxy ip to 127.0.0.1:%d\n", tpFwMask, tpFwMark, cfg.TProxyPort))
		if cfg.IPv6 {
			s.WriteString(fmt.Sprintf("        meta nfproto ipv6 meta l4proto { tcp, udp } mark & %s == %s tproxy ip6 to [::1]:%d\n", tpFwMask, tpFwMark, cfg.TProxyPort))
		}
	}
	s.WriteString("    }\n")
	return s.String()
}

func buildMangleOutput(cfg *config.Config, modes config.ProxyModes, gid uint32) string {
	var s strings.Builder
	s.WriteString("\n    chain proxy_out {\n")
	s.WriteString(fmt.Sprintf("        %s\n", nftSkgidExpr(gid, cfg.BypassGIDs)))
	nfproto := "meta nfproto ipv4"
	if cfg.IPv6 {
		nfproto = "meta nfproto { ipv4, ipv6 }"
	}
	s.WriteString(fmt.Sprintf("        %s meta l4proto { tcp, udp } fib saddr type local fib daddr type != local jump proxy_rule\n", nfproto))
	s.WriteString("    }\n")
	return s.String()
}

func buildNATChains(cfg *config.Config, modes config.ProxyModes, gid uint32) string {
	var s strings.Builder
	skgid := nftSkgidExpr(gid, cfg.BypassGIDs)
	if cfg.HijackDNS && cfg.DNSPort > 0 {
		dnsV4 := fmt.Sprintf("        ip daddr != 127.0.0.1 meta l4proto { tcp, udp } th dport 53 redirect to :%d\n", cfg.DNSPort)
		dnsV6 := ""
		if cfg.IPv6 {
			dnsV6 = fmt.Sprintf("        ip6 daddr != ::1 meta l4proto { tcp, udp } th dport 53 redirect to :%d\n", cfg.DNSPort)
		}
		s.WriteString(fmt.Sprintf("\n    chain dns_redirect {\n        %s\n        meta l4proto { tcp, udp } th dport %d return\n%s%s    }\n",
			skgid, cfg.DNSPort, dnsV4, dnsV6))
	}
	if modes.TCP == config.TCPModeRedir {
		nfproto := "meta nfproto ipv4"
		if cfg.IPv6 {
			nfproto = "meta nfproto { ipv4, ipv6 }"
		}
		v6 := ""
		if cfg.IPv6 {
			v6 = privateRangesV6(cfg.FakeIP, cfg.FakeIPv6Range)
		}
		s.WriteString(fmt.Sprintf("\n    chain tcp_redirect {\n        %s\n%s%s        ip daddr @interface return\n        %s meta l4proto tcp redirect to :%d\n    }\n",
			skgid, privateRangesV4(cfg.FakeIP, cfg.FakeIPv4Range), v6, nfproto, cfg.RedirectPort))
	}
	s.WriteString("\n    chain prerouting_nat {\n        type nat hook prerouting priority dstnat - 5; policy accept;\n")
	if cfg.HijackDNS && cfg.DNSPort > 0 {
		s.WriteString("        jump dns_redirect\n")
	}
	if modes.TCP == config.TCPModeRedir {
		s.WriteString("        jump tcp_redirect\n")
	}
	s.WriteString("    }\n")
	s.WriteString("\n    chain output_nat {\n        type nat hook output priority -105; policy accept;\n")
	if cfg.HijackDNS && cfg.DNSPort > 0 {
		s.WriteString("        jump dns_redirect\n")
	}
	if modes.TCP == config.TCPModeRedir {
		s.WriteString("        jump tcp_redirect\n")
	}
	s.WriteString("    }\n")
	return s.String()
}

// nftSkgidExpr builds a nft skgid match expression that exempts the sprs gid
// and any additional bypass_gids. When there is more than one gid, nft set
// syntax is used: skgid { gid1, gid2, ... } return
func nftSkgidExpr(sprsGID uint32, bypassGIDs []uint32) string {
	// deduplicate: collect all gids, sprs gid first
	seen := map[uint32]bool{sprsGID: true}
	all := []uint32{sprsGID}
	for _, g := range bypassGIDs {
		if !seen[g] {
			seen[g] = true
			all = append(all, g)
		}
	}
	if len(all) == 1 {
		return fmt.Sprintf("skgid %d return", all[0])
	}
	parts := make([]string, len(all))
	for i, g := range all {
		parts[i] = fmt.Sprintf("%d", g)
	}
	return fmt.Sprintf("skgid { %s } return", strings.Join(parts, ", "))
}


func Apply(cfg *config.Config, gid uint32) error {
	Stop() // clean previous state first

	modes := cfg.Modes()
	activeCfg = cfg
	activeModes = modes

	conf := buildTable(cfg, modes, gid)
	if err := os.WriteFile(nftConf, []byte(conf), 0644); err != nil {
		return fmt.Errorf("write nft conf: %w", err)
	}

	// Routes: strict — return error on failure
	if err := setupRoutes(cfg, modes); err != nil {
		_ = os.Remove(nftConf)
		activeCfg = nil
		activeModes = config.ProxyModes{}
		return err
	}

	if cfg.LAN {
		enableIPForward(cfg.IPv6)
	}

	if err := runCmd("nft -f " + nftConf); err != nil {
		// Rules failed — clean up routes we just added
		cleanupRoutes(cfg, modes)
		_ = os.Remove(nftConf)
		activeCfg = nil
		activeModes = config.ProxyModes{}
		return fmt.Errorf("nft -f: %w", err)
	}

	SyncLocalIPs(cfg.IPv6)

	// bypass mark ip rule (independent of nft group exemption)
	if cfg.BypassMark > 0 {
		setupBypassMarkRoute(cfg.BypassMark, cfg.IPv6)
	}

	return nil
}

func ApplyTunRoutes() {
	if activeCfg == nil {
		return
	}
	setupTunRoutes(activeCfg)
}

func Stop() {
	_ = runCmd(fmt.Sprintf("nft delete table inet %s", nftTable))
	_ = os.Remove(nftConf)
	if activeCfg != nil {
		cleanupRoutes(activeCfg, activeModes)
	}
	activeCfg = nil
	activeModes = config.ProxyModes{}
}

// StopWithConfig tears down rules/routes using an explicit config.
// Used by --stop flag (activeCfg may not be set if sprs never ran Apply).
func StopWithConfig(cfg *config.Config) {
	_ = runCmd(fmt.Sprintf("nft delete table inet %s", nftTable))
	_ = os.Remove(nftConf)
	modes := cfg.Modes()
	cleanupRoutes(cfg, modes)
	activeCfg = nil
	activeModes = config.ProxyModes{}
}

var (
	activeCfg   *config.Config
	activeModes config.ProxyModes
)

// setupRoutes returns error if a critical route command fails.
func setupRoutes(cfg *config.Config, modes config.ProxyModes) error {
	if modes.NeedsTProxyInbound() {
		if err := setupTProxyRoutes(cfg.IPv6); err != nil {
			return err
		}
	}
	if modes.NeedsTunInbound() {
		setupTunRoutes(cfg) // best-effort, tun device may not exist yet
	}
	return nil
}

func cleanupRoutes(cfg *config.Config, modes config.ProxyModes) {
	if modes.NeedsTProxyInbound() {
		cleanupTProxyRoutes(cfg.IPv6)
	}
	if modes.NeedsTunInbound() {
		cleanupTunRoutes(cfg)
	}
	if cfg.BypassMark > 0 {
		cleanupBypassMarkRoute(cfg.BypassMark, cfg.IPv6)
	}
}

// setupTProxyRoutes returns error: if ip rule/route fail, tproxy won't work at all.
func setupTProxyRoutes(ipv6 bool) error {
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
			return fmt.Errorf("tproxy route: %w", err)
		}
	}
	return nil
}

// setupBypassMarkRoute adds an ip rule so traffic with bypassMark is routed
// via the main table (i.e. bypasses tproxy/tun routing tables).
func setupBypassMarkRoute(mark uint32, ipv6 bool) {
	// Priority 100 — before tproxy rule (priority ~32765)
	cmds := []string{
		fmt.Sprintf("ip rule add fwmark 0x%x/0x%x table main priority 100", mark, mark),
	}
	if ipv6 {
		cmds = append(cmds,
			fmt.Sprintf("ip -6 rule add fwmark 0x%x/0x%x table main priority 100", mark, mark),
		)
	}
	for _, c := range cmds {
		if err := runCmd(c); err != nil {
			log.Printf("firewall: bypass mark route: %v", err)
		}
	}
}

func cleanupBypassMarkRoute(mark uint32, ipv6 bool) {
	cmds := []string{
		fmt.Sprintf("ip rule del fwmark 0x%x/0x%x table main priority 100", mark, mark),
	}
	if ipv6 {
		cmds = append(cmds,
			fmt.Sprintf("ip -6 rule del fwmark 0x%x/0x%x table main priority 100", mark, mark),
		)
	}
	for _, c := range cmds { _ = runCmd(c) }
}

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
	for _, c := range cmds { _ = runCmd(c) }
}

func cleanupTunRoutes(cfg *config.Config) {
	dev := cfg.TunName
	if dev == "" { dev = "tun0" }
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
	for _, c := range cmds { _ = runCmd(c) }
}

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

func SyncLocalIPs(ipv6 bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		log.Printf("firewall: interface addrs: %v", err)
		return
	}
	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok { continue }
		isV6 := ipnet.IP.To4() == nil
		if isV6 && !ipv6 { continue }
		set := "interface"
		if isV6 { set = "interface6" }
		if err := runCmd(fmt.Sprintf("nft add element inet %s %s { %s }", nftTable, set, ipnet.String())); err != nil {
			log.Printf("firewall: sync %s: %v", ipnet.String(), err)
		}
	}
}

func UseIPTables() bool {
	_, nftErr := exec.LookPath("nft")
	_, iptErr := exec.LookPath("iptables")
	return nftErr != nil && iptErr == nil
}

func ApplyIPTables(cfg *config.Config, gid uint32) error {
	StopIPTables()
	modes := cfg.Modes()
	activeCfg = cfg
	activeModes = modes

	// allExemptGIDs = sprs gid + bypass_gids (deduplicated)
	allExemptGIDs := gidList(gid, cfg.BypassGIDs)

	if cfg.HijackDNS && cfg.DNSPort > 0 {
		cmds := []string{
			"iptables -t nat -N SPRS_NAT",
		}
		for _, g := range allExemptGIDs {
			cmds = append(cmds, fmt.Sprintf("iptables -t nat -A SPRS_NAT -m owner --gid-owner %d -j RETURN", g))
		}
		cmds = append(cmds,
			fmt.Sprintf("iptables -t nat -A SPRS_NAT -p tcp --dport %d -j RETURN", cfg.DNSPort),
			fmt.Sprintf("iptables -t nat -A SPRS_NAT -p udp --dport %d -j RETURN", cfg.DNSPort),
			fmt.Sprintf("iptables -t nat -A SPRS_NAT -p tcp --dport 53 -j REDIRECT --to-port %d", cfg.DNSPort),
			fmt.Sprintf("iptables -t nat -A SPRS_NAT -p udp --dport 53 -j REDIRECT --to-port %d", cfg.DNSPort),
			"iptables -t nat -A OUTPUT -j SPRS_NAT",
			"iptables -t nat -A PREROUTING -j SPRS_NAT",
		)
		for _, c := range cmds {
			if err := runCmd(c); err != nil {
				log.Printf("firewall(iptables): %v", err)
			}
		}
	}
	if modes.TCP == config.TCPModeRedir {
		if err := setupTProxyRoutes(cfg.IPv6); err != nil {
			StopIPTables()
			return err
		}
		cmds := []string{
			"iptables -t nat -N SPRS_REDIR",
		}
		for _, g := range allExemptGIDs {
			cmds = append(cmds, fmt.Sprintf("iptables -t nat -A SPRS_REDIR -m owner --gid-owner %d -j RETURN", g))
		}
		cmds = append(cmds,
			"iptables -t nat -A SPRS_REDIR -d 127.0.0.0/8 -j RETURN",
			"iptables -t nat -A SPRS_REDIR -d 10.0.0.0/8 -j RETURN",
			"iptables -t nat -A SPRS_REDIR -d 172.16.0.0/12 -j RETURN",
			"iptables -t nat -A SPRS_REDIR -d 192.168.0.0/16 -j RETURN",
			fmt.Sprintf("iptables -t nat -A SPRS_REDIR -p tcp -j REDIRECT --to-port %d", cfg.RedirectPort),
			"iptables -t nat -A OUTPUT -p tcp -j SPRS_REDIR",
			"iptables -t nat -A PREROUTING -p tcp -j SPRS_REDIR",
		)
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

// gidList returns a deduplicated slice starting with sprsGID followed by any
// additional bypass_gids that differ from it.
func gidList(sprsGID uint32, bypassGIDs []uint32) []uint32 {
	seen := map[uint32]bool{sprsGID: true}
	all := []uint32{sprsGID}
	for _, g := range bypassGIDs {
		if !seen[g] {
			seen[g] = true
			all = append(all, g)
		}
	}
	return all
}

func StopIPTables() {
	cmds := []string{
		"iptables -t nat -D OUTPUT -j SPRS_NAT",
		"iptables -t nat -D PREROUTING -j SPRS_NAT",
		"iptables -t nat -F SPRS_NAT",
		"iptables -t nat -X SPRS_NAT",
		"iptables -t nat -D OUTPUT -p tcp -j SPRS_REDIR",
		"iptables -t nat -D PREROUTING -p tcp -j SPRS_REDIR",
		"iptables -t nat -F SPRS_REDIR",
		"iptables -t nat -X SPRS_REDIR",
	}
	for _, c := range cmds { _ = runCmd(c) }
	if activeCfg != nil {
		cleanupTProxyRoutes(activeCfg.IPv6)
	}
	activeCfg = nil
	activeModes = config.ProxyModes{}
}

func runCmd(command string) error {
	parts := strings.Fields(command)
	if len(parts) == 0 { return nil }
	out, err := exec.Command(parts[0], parts[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (output: %s)", command, err, strings.TrimSpace(string(out)))
	}
	return nil
}
