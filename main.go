package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/tproxyng/internal/config"
	"github.com/tproxyng/internal/firewall"
	"github.com/tproxyng/internal/group"
	"github.com/tproxyng/internal/process"
)

const version = "1.0.0"

func main() {
	var (
		cfgPath    string
		genExample bool
		showVer    bool
	)

	flag.StringVar(&cfgPath, "c", "", "config file path (.toml or .json)")
	flag.BoolVar(&genExample, "example", false, "print example config.toml and exit")
	flag.BoolVar(&showVer, "v", false, "print version and exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "tproxyng %s — transparent proxy manager\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  tproxyng -c config.toml\n")
		fmt.Fprintf(os.Stderr, "  tproxyng -example > config.toml\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if showVer {
		fmt.Printf("tproxyng %s\n", version)
		return
	}
	if genExample {
		fmt.Print(config.ExampleTOML())
		return
	}
	if cfgPath == "" {
		fmt.Fprintln(os.Stderr, "error: -c <config file> is required")
		flag.Usage()
		os.Exit(1)
	}

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetPrefix("[tproxyng] ")

	// ── Load config ──────────────────────────────────────────────────────
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	logConfig(cfg)

	// ── Ensure proxy group ───────────────────────────────────────────────
	gid, err := group.Ensure()
	if err != nil {
		log.Fatalf("group: %v", err)
	}
	log.Printf("group: %q gid=%d", group.GroupName, gid)

	// ── Detect firewall backend ──────────────────────────────────────────
	// nft preferred; iptables fallback for older kernels.
	useIPT := false
	if _, err := exec.LookPath("nft"); err != nil {
		if _, err2 := exec.LookPath("iptables"); err2 != nil {
			log.Fatalf("firewall: neither nft nor iptables found in PATH")
		}
		log.Println("firewall: nft not found, falling back to iptables")
		useIPT = true
	}

	// ── Apply firewall rules ─────────────────────────────────────────────
	if useIPT {
		if err := firewall.ApplyIPTables(cfg, gid); err != nil {
			log.Fatalf("firewall(iptables): %v", err)
		}
	} else {
		if err := firewall.Apply(cfg, gid); err != nil {
			log.Fatalf("firewall(nft): %v", err)
		}
	}
	log.Println("firewall: rules applied")

	// ── Start proxy process ──────────────────────────────────────────────
	mgr := process.New(cfg, gid, useIPT)
	if err := mgr.Start(); err != nil {
		if useIPT {
			firewall.StopIPTables()
		} else {
			firewall.Stop()
		}
		log.Fatalf("process: %v", err)
	}

	// ── Wait for signal ──────────────────────────────────────────────────
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("received %s, shutting down", s)

	mgr.Stop()
}

func logConfig(cfg *config.Config) {
	log.Printf("config: mode=%s tproxy_port=%d redirect_port=%d dns_port=%d tun=%s",
		cfg.Mode, cfg.TProxyPort, cfg.RedirectPort, cfg.DNSPort, cfg.TunName)
	log.Printf("config: ipv6=%v lan=%v fakeip=%v hijack_dns=%v",
		cfg.IPv6, cfg.LAN, cfg.FakeIP, cfg.HijackDNS)
	log.Printf("config: keepalive=%v restart_on_fail=%v max_restarts=%d watch_interval=%ds",
		cfg.Keepalive, cfg.RestartOnFail, cfg.MaxRestarts, cfg.WatchInterval)
	log.Printf("config: cron_restart=%v cron_expr=%q",
		cfg.CronRestart, cfg.CronExpr)
}
