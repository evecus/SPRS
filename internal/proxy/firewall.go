package proxy

// firewall.go — nftables 规则生成 + ip rule/route 管理
// 逻辑与 Singa firewall/nft.go 保持一致。

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

const (
	tproxyMark   = "0x40"
	tproxyMask   = "0xc0"
	tproxyTable  = 100
	nftTableName = "tproxy_core"

	// FakeIP 地址段（与 Singa / sing-box 默认值一致）
	fakeIPv4Range = "198.18.0.0/15"
	fakeIPv6Range = "fc00::/18"
)

// privateRangesV4 返回 IPv4 私有/保留段的 nft bypass 规则。
// fakeip=true 时豁免 198.18.0.0/15，让 fakeip 流量能到达代理。
func privateRangesV4(fakeip bool) string {
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

// privateRangesV6 返回 IPv6 私有/保留段的 nft bypass 规则。
// fakeip=true 时豁免 fc00::/18。
func privateRangesV6(fakeip bool) string {
	if fakeip {
		return "        ip6 daddr != " + fakeIPv6Range + " ip6 daddr { ::/127, fc00::/7, fe80::/10, ff00::/8 } return\n"
	}
	return "        ip6 daddr { ::/127, fc00::/7, fe80::/10, ff00::/8 } return\n"
}

// buildNFTConf 生成完整的 nft 配置文本。
//
//   cfg.DNSPort    — 代理 DNS 监听端口（0 = 不做 DNS 劫持）
//   cfg.TProxyPort — tproxy 入站端口
//   cfg.IPv6       — 是否生成 IPv6 规则
//   cfg.FakeIP     — 是否开启 FakeIP 豁免
//   gid            — 代理进程的 GID（此 GID 的流量跳过所有重定向）
func buildNFTConf(cfg Config, gid uint32) string {
	var s strings.Builder

	s.WriteString(fmt.Sprintf("table inet %s {\n", nftTableName))

	// ── 本机地址集合 ────────────────────────────────────────────────────────
	s.WriteString("    set interface {\n        type ipv4_addr\n        flags interval\n        auto-merge\n    }\n")
	if cfg.IPv6 {
		s.WriteString("    set interface6 {\n        type ipv6_addr\n        flags interval\n        auto-merge\n    }\n")
	}

	// ── tp_mark 链：给新连接打 fwmark ────────────────────────────────────
	s.WriteString(fmt.Sprintf(`
    chain tp_mark {
        tcp flags syn / fin,syn,rst,ack meta mark set meta mark | %s
        meta l4proto udp ct state new meta mark set meta mark | %s
        ct mark set meta mark
    }

`, tproxyMark, tproxyMark))

	// ── proxy_rule 链：决定是否打 mark ───────────────────────────────────
	s.WriteString("    chain proxy_rule {\n")
	s.WriteString("        meta mark set ct mark\n")
	s.WriteString(fmt.Sprintf("        meta mark & %s == %s return\n", tproxyMask, tproxyMark))
	s.WriteString(privateRangesV4(cfg.FakeIP))
	if cfg.IPv6 {
		s.WriteString(privateRangesV6(cfg.FakeIP))
	}
	s.WriteString("        ip daddr @interface return\n")
	if cfg.IPv6 {
		s.WriteString("        ip6 daddr @interface6 return\n")
	}
	// 如果开了 DNS 劫持，跳过代理自己的 DNS 端口（防环路）
	if cfg.DNSPort > 0 {
		s.WriteString(fmt.Sprintf("        meta l4proto { tcp, udp } th dport %d return\n", cfg.DNSPort))
	}
	s.WriteString("        meta l4proto tcp jump tp_mark\n")
	s.WriteString("        meta l4proto udp jump tp_mark\n")
	s.WriteString("    }\n\n")

	// ── proxy_pre 链：prerouting mangle，执行 tproxy redirect ───────────
	s.WriteString("    chain proxy_pre {\n")
	s.WriteString(fmt.Sprintf("        iifname \"lo\" meta mark & %s != %s return\n", tproxyMask, tproxyMark))
	s.WriteString(fmt.Sprintf(
		"        meta nfproto ipv4 meta l4proto { tcp, udp } meta mark & %s == %s tproxy ip to 127.0.0.1:%d\n",
		tproxyMask, tproxyMark, cfg.TProxyPort))
	if cfg.IPv6 {
		s.WriteString(fmt.Sprintf(
			"        meta nfproto ipv6 meta l4proto { tcp, udp } meta mark & %s == %s tproxy ip6 to [::1]:%d\n",
			tproxyMask, tproxyMark, cfg.TProxyPort))
	}
	s.WriteString("    }\n\n")

	// ── proxy_out 链：output mangle，本机发出的流量 ──────────────────────
	s.WriteString("    chain proxy_out {\n")
	s.WriteString(fmt.Sprintf("        skgid %d return\n", gid))
	nfproto := "meta nfproto ipv4"
	if cfg.IPv6 {
		nfproto = "meta nfproto { ipv4, ipv6 }"
	}
	s.WriteString(fmt.Sprintf(
		"        %s meta l4proto { tcp, udp } fib saddr type local fib daddr type != local jump proxy_rule\n",
		nfproto))
	s.WriteString("    }\n\n")

	// ── Hook 链 ─────────────────────────────────────────────────────────
	s.WriteString(`    chain prerouting_mangle {
        type filter hook prerouting priority mangle - 5; policy accept;
        jump proxy_pre
    }

    chain output_mangle {
        type route hook output priority mangle - 5; policy accept;
        jump proxy_out
    }

`)

	// ── DNS 劫持（可选）────────────────────────────────────────────────
	if cfg.DNSPort > 0 {
		dnsV4 := fmt.Sprintf(
			"        ip daddr != 127.0.0.1 meta l4proto { tcp, udp } th dport 53 redirect to :%d\n",
			cfg.DNSPort)
		dnsV6 := ""
		if cfg.IPv6 {
			dnsV6 = fmt.Sprintf(
				"        ip6 daddr != ::1 meta l4proto { tcp, udp } th dport 53 redirect to :%d\n",
				cfg.DNSPort)
		}
		s.WriteString(fmt.Sprintf(`    chain dns_redirect {
        skgid %d return
        meta l4proto { tcp, udp } th dport %d return
%s%s    }

    chain prerouting_nat {
        type nat hook prerouting priority dstnat - 5; policy accept;
        jump dns_redirect
    }

    chain output_nat {
        type nat hook output priority -105; policy accept;
        jump dns_redirect
    }

`, gid, cfg.DNSPort, dnsV4, dnsV6))
	}

	s.WriteString("}\n")
	return s.String()
}

// applyNFT 写入配置文件并执行 nft -f。
func applyNFT(conf, confPath string) error {
	if err := os.WriteFile(confPath, []byte(conf), 0644); err != nil {
		return fmt.Errorf("write nft conf: %w", err)
	}
	if err := runCmd("nft -f " + confPath); err != nil {
		return fmt.Errorf("nft -f: %w", err)
	}
	return nil
}

// setupTProxyRoutes 添加 ip rule + ip route，让带 fwmark 的包走 loopback。
func setupTProxyRoutes(ipv6 bool) {
	cmds := []string{
		fmt.Sprintf("ip rule add fwmark %s/%s table %d", tproxyMark, tproxyMask, tproxyTable),
		fmt.Sprintf("ip route add local 0.0.0.0/0 dev lo table %d", tproxyTable),
	}
	if ipv6 {
		cmds = append(cmds,
			fmt.Sprintf("ip -6 rule add fwmark %s/%s table %d", tproxyMark, tproxyMask, tproxyTable),
			fmt.Sprintf("ip -6 route add local ::/0 dev lo table %d", tproxyTable),
		)
	}
	for _, c := range cmds {
		if err := runCmd(c); err != nil {
			log.Printf("firewall: route setup: %v", err)
		}
	}
}

// cleanupTProxyRoutes 删除 ip rule + ip route。
func cleanupTProxyRoutes(ipv6 bool) {
	cmds := []string{
		fmt.Sprintf("ip rule del fwmark %s/%s table %d", tproxyMark, tproxyMask, tproxyTable),
		fmt.Sprintf("ip route del local 0.0.0.0/0 dev lo table %d", tproxyTable),
	}
	if ipv6 {
		cmds = append(cmds,
			fmt.Sprintf("ip -6 rule del fwmark %s/%s table %d", tproxyMark, tproxyMask, tproxyTable),
			fmt.Sprintf("ip -6 route del local ::/0 dev lo table %d", tproxyTable),
		)
	}
	for _, c := range cmds {
		if err := runCmd(c); err != nil {
			log.Printf("firewall: route cleanup: %v", err)
		}
	}
}

// cleanupNFT 删除 nft 表和配置文件。
func cleanupNFT(confPath string) {
	if err := runCmd(fmt.Sprintf("nft delete table inet %s", nftTableName)); err != nil {
		log.Printf("firewall: nft delete table: %v", err)
	}
	if confPath != "" {
		_ = os.Remove(confPath)
	}
}

// syncLocalIPs 把所有网卡地址加入 nft interface/interface6 集合。
func syncLocalIPs(ipv6 bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Printf("firewall: list interfaces: %v", err)
		return
	}
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			isV6 := ip.To4() == nil
			if isV6 && !ipv6 {
				continue
			}
			setName := "interface"
			if isV6 {
				setName = "interface6"
			}
			cidr := addr.String()
			if err := runCmd(fmt.Sprintf("nft add element inet %s %s { %s }", nftTableName, setName, cidr)); err != nil {
				log.Printf("firewall: sync IP %s: %v", cidr, err)
			}
		}
	}
}

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
