package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

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
		doStart    bool
		doStop     bool
	)
	flag.StringVar(&cfgPath, "c", "", "config file path (.toml or .json)")
	flag.BoolVar(&genExample, "example", false, "print example config.toml and exit")
	flag.BoolVar(&showVer, "v", false, "print version and exit")
	flag.BoolVar(&doStart, "start", false, "apply firewall rules and routes only, then exit")
	flag.BoolVar(&doStop, "stop", false, "remove firewall rules and routes only, then exit")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "sprs %s\n\nUsage:\n", version)
		fmt.Fprintf(os.Stderr, "  sprs -c config.toml            # run normally\n")
		fmt.Fprintf(os.Stderr, "  sprs -c config.toml --start    # apply rules/routes only, then exit\n")
		fmt.Fprintf(os.Stderr, "  sprs -c config.toml --stop     # remove rules/routes only, then exit\n")
		fmt.Fprintf(os.Stderr, "  sprs -example > config.toml    # generate example config\n\n")
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
	if doStart && doStop {
		fmt.Fprintln(os.Stderr, "error: --start and --stop are mutually exclusive")
		os.Exit(1)
	}

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetPrefix("[sprs] ")

	// ── Load config ──────────────────────────────────────────────────────
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	// ── Detect firewall backend ──────────────────────────────────────────
	useIPT := false
	if _, err := exec.LookPath("nft"); err != nil {
		if _, err2 := exec.LookPath("iptables"); err2 != nil {
			log.Fatalf("firewall: neither nft nor iptables found in PATH")
		}
		log.Println("firewall: nft not found, falling back to iptables")
		useIPT = true
	}

	// ── --stop ───────────────────────────────────────────────────────────
	if doStop {
		log.Println("mode: --stop, removing rules and routes")
		if useIPT {
			firewall.StopIPTables()
		} else {
			// Pass cfg so Stop() knows which routes to clean
			firewall.StopWithConfig(cfg)
		}
		log.Println("done")
		return
	}

	// ── Ensure proxy group ───────────────────────────────────────────────
	gid, err := group.Ensure()
	if err != nil {
		log.Fatalf("group: %v", err)
	}
	log.Printf("group: %q gid=%d", group.GroupName, gid)

	// ── --start ──────────────────────────────────────────────────────────
	if doStart {
		log.Println("mode: --start, applying rules and routes")
		if useIPT {
			if err := firewall.ApplyIPTables(cfg, gid); err != nil {
				log.Fatalf("firewall(iptables): %v", err)
			}
		} else {
			// --start always cleans first, then reapplies
			if useIPT {
				firewall.StopIPTables()
			} else {
				firewall.StopWithConfig(cfg)
			}
			if err := firewall.Apply(cfg, gid); err != nil {
				log.Fatalf("firewall(nft): %v", err)
			}
		}
		log.Println("done")
		return
	}

	// ── Normal mode ──────────────────────────────────────────────────────
	logConfig(cfg)

	// Step 1: start_wait_time — sleep before doing anything
	if cfg.StartWaitTime > 0 {
		log.Printf("startup: waiting %ds (start_wait_time)", cfg.StartWaitTime)
		time.Sleep(time.Duration(cfg.StartWaitTime) * time.Second)
	}

	// Step 2: wait_process — wait until all required processes are running
	if len(cfg.WaitProcess) > 0 {
		if err := process.WaitForProcesses(cfg.WaitProcess, cfg.WaitProcessTimeout); err != nil {
			log.Fatalf("startup: %v", err)
		}
	}

	// Step 3: apply firewall rules (always clean first in normal mode too)
	if useIPT {
		if err := firewall.ApplyIPTables(cfg, gid); err != nil {
			log.Fatalf("firewall(iptables): %v", err)
		}
	} else {
		if err := firewall.Apply(cfg, gid); err != nil {
			log.Fatalf("firewall(nft): %v — proxy will NOT be started", err)
		}
	}
	log.Println("firewall: rules applied")

	// Step 4: start proxy process
	mgr := process.New(cfg, gid, useIPT)
	if err := mgr.Start(); err != nil {
		log.Printf("process: startup failed: %v", err)
		log.Println("process: cleaning up firewall rules")
		if useIPT {
			firewall.StopIPTables()
		} else {
			firewall.StopWithConfig(cfg)
		}
		log.Fatalf("process: aborting")
	}

	// Step 5: wait for signal
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
	if cfg.BypassMark > 0 {
		log.Printf("config: bypass mark=0x%x", cfg.BypassMark)
	}
	if cfg.StartWaitTime > 0 {
		log.Printf("config: start_wait_time=%ds", cfg.StartWaitTime)
	}
	if len(cfg.WaitProcess) > 0 {
		log.Printf("config: wait_process=%v timeout=%ds", cfg.WaitProcess, cfg.WaitProcessTimeout)
	}
	log.Printf("config: keepalive=%v restart_on_fail=%v max_restarts=%d watch_interval=%ds start_timeout=%ds",
		cfg.Keepalive, cfg.RestartOnFail, cfg.MaxRestarts, cfg.WatchInterval, cfg.StartTimeout)
	if cfg.MaxMemoryMB > 0 || cfg.MaxCPUPct > 0 {
		log.Printf("config: max_memory=%dMB max_cpu=%.1f%% check_interval=%ds",
			cfg.MaxMemoryMB, cfg.MaxCPUPct, cfg.ResourceCheckInterval)
	}
	if cfg.CronRestart {
		log.Printf("config: cron_restart=%q", cfg.CronExpr)
	}
}
