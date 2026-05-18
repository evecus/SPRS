package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/sprs/internal/config"
	"github.com/sprs/internal/firewall"
	"github.com/sprs/internal/group"
	"github.com/sprs/internal/process"
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
		fmt.Fprintf(os.Stderr, "sprs %s\n\nUsage:\n  sprs -c config.toml\n  sprs -example > config.toml\n\n", version)
		flag.PrintDefaults()
	}
	flag.Parse()

	if showVer {
		fmt.Printf("sprs %s\n", version)
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
	log.SetPrefix("[sprs] ")

	// ── Load + validate config ───────────────────────────────────────────
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
	useIPT := false
	if _, err := exec.LookPath("nft"); err != nil {
		if _, err2 := exec.LookPath("iptables"); err2 != nil {
			log.Fatalf("firewall: neither nft nor iptables found in PATH")
		}
		log.Println("firewall: nft not found, falling back to iptables")
		useIPT = true
	}

	// ── Apply firewall rules ─────────────────────────────────────────────
	// If this fails, we exit immediately — proxy is NOT started.
	if useIPT {
		if err := firewall.ApplyIPTables(cfg, gid); err != nil {
			log.Fatalf("firewall(iptables): %v — proxy will NOT be started", err)
		}
	} else {
		if err := firewall.Apply(cfg, gid); err != nil {
			log.Fatalf("firewall(nft): %v — proxy will NOT be started", err)
		}
	}
	log.Println("firewall: rules applied")

	// ── Start proxy process ──────────────────────────────────────────────
	// If startup confirmation fails (process crashes within start_timeout),
	// firewall rules are cleaned up and we exit.
	mgr := process.New(cfg, gid, useIPT)
	if err := mgr.Start(); err != nil {
		log.Printf("process: startup failed: %v", err)
		log.Println("process: cleaning up firewall rules")
		if useIPT {
			firewall.StopIPTables()
		} else {
			firewall.Stop()
		}
		log.Fatalf("process: aborting")
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
	log.Printf("config: hijack_dns=%v ipv6=%v lan=%v fakeip=%v",
		cfg.HijackDNS, cfg.IPv6, cfg.LAN, cfg.FakeIP)
	log.Printf("config: keepalive=%v restart_on_fail=%v max_restarts=%d watch_interval=%ds start_timeout=%ds",
		cfg.Keepalive, cfg.RestartOnFail, cfg.MaxRestarts, cfg.WatchInterval, cfg.StartTimeout)
	if cfg.MaxMemoryMB > 0 {
		log.Printf("config: max_memory=%dMB check_interval=%ds", cfg.MaxMemoryMB, cfg.ResourceCheckInterval)
	}
	if cfg.MaxCPUPct > 0 {
		log.Printf("config: max_cpu=%.1f%% check_interval=%ds", cfg.MaxCPUPct, cfg.ResourceCheckInterval)
	}
	if cfg.CronRestart {
		log.Printf("config: cron_restart=%q", cfg.CronExpr)
	}
}
