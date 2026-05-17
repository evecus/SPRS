// Package process manages the proxy subprocess lifecycle:
// keepalive, restart-on-failure, scheduled restart (cron).
// Scheduler logic mirrors Singa's core/manager.go startScheduler.
package process

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/tproxyng/internal/config"
	"github.com/tproxyng/internal/cronrestart"
	"github.com/tproxyng/internal/firewall"
)

// Manager runs the proxy command and handles all restart logic.
type Manager struct {
	cfg       *config.Config
	gid       uint32
	useIPT    bool // using iptables fallback instead of nft

	mu         sync.Mutex
	cmd        *exec.Cmd
	stopped    bool  // true after explicit Stop()
	restarts   int   // failure restart counter
	schedStop  chan struct{}
	watchStop  chan struct{}
}

// New creates a Manager. gid is the proxy group id. useIPT selects iptables backend.
func New(cfg *config.Config, gid uint32, useIPT bool) *Manager {
	return &Manager{cfg: cfg, gid: gid, useIPT: useIPT}
}

// Start launches the proxy and all background goroutines.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.stopped = false
	m.restarts = 0

	if err := m.launch(); err != nil {
		return err
	}

	// For tun/mixed: wait for tun device to appear, then apply tun routes.
	modes := m.cfg.Modes()
	if modes.NeedsTunInbound() {
		go m.waitForTun()
	}

	if m.cfg.Keepalive {
		m.startWatcher()
	}
	if m.cfg.CronRestart && m.cfg.CronExpr != "" {
		m.startCron()
	}

	return nil
}

// Stop signals the proxy to exit and tears down the firewall.
func (m *Manager) Stop() {
	m.mu.Lock()
	m.stopped = true
	cmd := m.cmd
	m.mu.Unlock()

	m.stopWatcher()
	m.stopCron()

	if cmd != nil && cmd.Process != nil {
		log.Printf("process: stopping pid=%d", cmd.Process.Pid)
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
		}
	}

	if m.useIPT {
		firewall.StopIPTables()
	} else {
		firewall.Stop()
	}
	log.Println("process: stopped")
}

// RestartCore restarts only the proxy process, keeping firewall rules intact.
// Used by the cron scheduler — mirrors Singa's scheduled restart behavior.
func (m *Manager) RestartCore() {
	m.mu.Lock()
	cmd := m.cmd
	m.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		log.Println("process: cron restart — stopping core")
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_ = cmd.Wait()
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return
	}
	if err := m.launch(); err != nil {
		log.Printf("process: cron restart failed: %v", err)
	}
}

// ── Internal launch ───────────────────────────────────────────────────────

func (m *Manager) launch() error {
	parts := splitCmd(m.cfg.Run)
	if len(parts) == 0 {
		return fmt.Errorf("run command is empty")
	}

	cmd := exec.Command(parts[0], parts[1:]...)
	// Run proxy under gid=tproxyng so nft skgid rule exempts its traffic.
	// uid stays 0 (root) to retain CAP_NET_ADMIN etc.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:         0,
			Gid:         m.gid,
			Groups:      []uint32{m.gid},
			NoSetGroups: false,
		},
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("exec %q: %w", parts[0], err)
	}
	log.Printf("process: started pid=%d cmd=%q", cmd.Process.Pid, m.cfg.Run)

	go streamLog("core/out", stdout)
	go streamLog("core/err", stderr)

	// Watch for unexpected exit (for keepalive / restart-on-fail)
	go m.onExit(cmd)

	m.cmd = cmd
	return nil
}

// onExit is called when the proxy process exits.
func (m *Manager) onExit(cmd *exec.Cmd) {
	err := cmd.Wait()

	m.mu.Lock()
	if m.cmd != cmd {
		m.mu.Unlock()
		return // already replaced by cron restart
	}
	m.cmd = nil
	stopped := m.stopped
	m.mu.Unlock()

	if stopped {
		return // explicit Stop() — don't restart
	}

	if err != nil {
		log.Printf("process: exited with error: %v", err)
		if m.cfg.RestartOnFail {
			m.maybeRestart("restart_on_fail")
			return
		}
	} else {
		log.Println("process: exited cleanly")
	}
}

// maybeRestart restarts the proxy respecting max_restarts.
func (m *Manager) maybeRestart(reason string) {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	if m.cfg.MaxRestarts > 0 && m.restarts >= m.cfg.MaxRestarts {
		log.Printf("process: max_restarts=%d reached, not restarting", m.cfg.MaxRestarts)
		m.mu.Unlock()
		return
	}
	m.restarts++
	attempt := m.restarts
	m.mu.Unlock()

	log.Printf("process: restarting (%s, attempt %d)", reason, attempt)
	time.Sleep(time.Duration(attempt) * time.Second) // backoff

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return
	}
	if err := m.launch(); err != nil {
		log.Printf("process: restart failed: %v", err)
	}
}

// ── Keepalive watcher ─────────────────────────────────────────────────────

func (m *Manager) startWatcher() {
	stop := make(chan struct{})
	m.watchStop = stop
	interval := time.Duration(m.cfg.WatchInterval) * time.Second
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				m.mu.Lock()
				alive := m.cmd != nil && m.cmd.Process != nil && isAlive(m.cmd.Process.Pid)
				stopped := m.stopped
				m.mu.Unlock()
				if !alive && !stopped {
					log.Printf("process: keepalive: process gone, restarting")
					m.maybeRestart("keepalive")
				}
			}
		}
	}()
}

func (m *Manager) stopWatcher() {
	if m.watchStop != nil {
		close(m.watchStop)
		m.watchStop = nil
	}
}

// isAlive checks /proc/<pid>/status to see if the process still exists.
func isAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// ── Cron scheduler (mirrors Singa's startScheduler) ──────────────────────

func (m *Manager) startCron() {
	entry, err := cronrestart.Parse(m.cfg.CronExpr)
	if err != nil {
		log.Printf("process: invalid cron %q: %v", m.cfg.CronExpr, err)
		return
	}
	stop := make(chan struct{})
	m.schedStop = stop
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		lastFired := time.Time{}
		for {
			select {
			case <-stop:
				return
			case t := <-ticker.C:
				rounded := t.Truncate(time.Minute)
				if entry.Matches(rounded) && rounded.After(lastFired) {
					lastFired = rounded
					log.Printf("process: cron %q fired, restarting core", m.cfg.CronExpr)
					m.RestartCore()
				}
			}
		}
	}()
}

func (m *Manager) stopCron() {
	if m.schedStop != nil {
		close(m.schedStop)
		m.schedStop = nil
	}
}

// ── TUN device waiter (mirrors Singa's Start tun goroutine) ──────────────

func (m *Manager) waitForTun() {
	dev := m.cfg.TunName
	for i := 0; i < 20; i++ {
		time.Sleep(500 * time.Millisecond)
		if _, err := os.Stat("/sys/class/net/" + dev); err == nil {
			log.Printf("process: tun device %q appeared, applying tun routes", dev)
			firewall.ApplyTunRoutes()
			return
		}
	}
	log.Printf("process: warn: tun device %q did not appear within 10s", dev)
}

// ── Helpers ───────────────────────────────────────────────────────────────

func streamLog(prefix string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		log.Printf("[%s] %s", prefix, scanner.Text())
	}
}

func splitCmd(s string) []string {
	var parts []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if cur.Len() > 0 {
				parts = append(parts, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteByte(c)
		}
	}
	if cur.Len() > 0 {
		parts = append(parts, cur.String())
	}
	return parts
}
