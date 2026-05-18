package process

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"os/exec"

	"github.com/sprs/internal/config"
	"github.com/sprs/internal/cronrestart"
	"github.com/sprs/internal/firewall"
)

type Manager struct {
	cfg    *config.Config
	gid    uint32
	useIPT bool

	mu          sync.Mutex
	cmd         *exec.Cmd
	stopped     bool
	restarts    int
	schedStop   chan struct{}
	watchStop   chan struct{}
	resourceStop chan struct{}
}

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

	// For tun/mixed: wait for tun device, then apply tun routes.
	if m.cfg.Modes().NeedsTunInbound() {
		go m.waitForTun()
	}

	if m.cfg.Keepalive {
		m.startWatcher()
	}
	if m.cfg.CronRestart && m.cfg.CronExpr != "" {
		m.startCron()
	}
	if m.cfg.MaxMemoryMB > 0 || m.cfg.MaxCPUPct > 0 {
		m.startResourceMonitor()
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
	m.stopResourceMonitor()

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

// RestartCore restarts only the proxy process, rules/routes stay intact.
// Used by cron scheduler and resource monitor.
func (m *Manager) RestartCore(reason string) {
	m.mu.Lock()
	cmd := m.cmd
	m.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		log.Printf("process: restarting core (%s), stopping pid=%d", reason, cmd.Process.Pid)
		_ = cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _ = cmd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			<-done
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopped {
		return
	}
	if err := m.launch(); err != nil {
		log.Printf("process: restart failed: %v", err)
	}
}

// ── Launch ────────────────────────────────────────────────────────────────

func (m *Manager) launch() error {
	parts := splitCmd(m.cfg.Run)
	if len(parts) == 0 {
		return fmt.Errorf("run command is empty")
	}

	cmd := exec.Command(parts[0], parts[1:]...)
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
	log.Printf("process: started pid=%d", cmd.Process.Pid)

	go streamLog("core/out", stdout)
	go streamLog("core/err", stderr)

	// ── Startup confirmation ───────────────────────────────────────────
	// Wait start_timeout seconds to confirm the process didn't immediately crash.
	// This catches misconfigurations (bad config.json, wrong binary path, etc.)
	// before we declare success.
	if m.cfg.StartTimeout > 0 {
		confirmed := make(chan error, 1)
		go func() {
			time.Sleep(time.Duration(m.cfg.StartTimeout) * time.Second)
			if !isAlive(cmd.Process.Pid) {
				confirmed <- fmt.Errorf("process exited within %ds of start (check proxy config)", m.cfg.StartTimeout)
				return
			}
			confirmed <- nil
		}()
		if err := <-confirmed; err != nil {
			_ = cmd.Wait()
			return err
		}
	}

	go m.onExit(cmd)
	m.cmd = cmd
	return nil
}

// ── Exit handler ──────────────────────────────────────────────────────────

func (m *Manager) onExit(cmd *exec.Cmd) {
	err := cmd.Wait()

	m.mu.Lock()
	if m.cmd != cmd {
		m.mu.Unlock()
		return // replaced by cron or resource restart
	}
	m.cmd = nil
	stopped := m.stopped
	m.mu.Unlock()

	if stopped {
		return
	}

	if err != nil {
		log.Printf("process: exited with error: %v", err)
		if m.cfg.RestartOnFail {
			m.maybeRestart("restart_on_fail")
		}
	} else {
		log.Println("process: exited cleanly")
		// clean exit — treat as intentional, don't restart
	}
}

func (m *Manager) maybeRestart(reason string) {
	m.mu.Lock()
	if m.stopped {
		m.mu.Unlock()
		return
	}
	if m.cfg.MaxRestarts > 0 && m.restarts >= m.cfg.MaxRestarts {
		log.Printf("process: max_restarts=%d reached, giving up", m.cfg.MaxRestarts)
		m.mu.Unlock()
		return
	}
	m.restarts++
	attempt := m.restarts
	m.mu.Unlock()

	backoff := time.Duration(attempt) * time.Second
	if backoff > 30*time.Second {
		backoff = 30 * time.Second
	}
	log.Printf("process: restart in %s (%s, attempt %d)", backoff, reason, attempt)
	time.Sleep(backoff)

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
				pid := 0
				if m.cmd != nil && m.cmd.Process != nil {
					pid = m.cmd.Process.Pid
				}
				stopped := m.stopped
				m.mu.Unlock()

				if stopped {
					return
				}
				if pid == 0 || !isAlive(pid) {
					log.Printf("process: keepalive: process gone (pid=%d), restarting", pid)
					m.mu.Lock()
					m.cmd = nil
					m.mu.Unlock()
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

// ── Resource monitor ──────────────────────────────────────────────────────

func (m *Manager) startResourceMonitor() {
	stop := make(chan struct{})
	m.resourceStop = stop
	interval := time.Duration(m.cfg.ResourceCheckInterval) * time.Second

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// CPU measurement needs two samples
		var prevCPU cpuSample

		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				m.mu.Lock()
				pid := 0
				if m.cmd != nil && m.cmd.Process != nil {
					pid = m.cmd.Process.Pid
				}
				stopped := m.stopped
				m.mu.Unlock()

				if stopped || pid == 0 {
					continue
				}

				// ── Memory check ──────────────────────────────────────
				if m.cfg.MaxMemoryMB > 0 {
					memMB, err := procMemMB(pid)
					if err != nil {
						log.Printf("process: resource: read mem pid=%d: %v", pid, err)
					} else if memMB > m.cfg.MaxMemoryMB {
						log.Printf("process: memory limit exceeded: %dMB > %dMB, restarting core",
							memMB, m.cfg.MaxMemoryMB)
						go m.RestartCore(fmt.Sprintf("memory limit %dMB exceeded (%dMB)", m.cfg.MaxMemoryMB, memMB))
						prevCPU = cpuSample{}
						continue
					}
				}

				// ── CPU check ─────────────────────────────────────────
				if m.cfg.MaxCPUPct > 0 {
					cur, err := procCPUSample(pid)
					if err != nil {
						log.Printf("process: resource: read cpu pid=%d: %v", pid, err)
						prevCPU = cpuSample{}
					} else {
						if prevCPU.total > 0 {
							pct := cpuPercent(prevCPU, cur)
							if pct > m.cfg.MaxCPUPct {
								log.Printf("process: CPU limit exceeded: %.1f%% > %.1f%%, restarting core",
									pct, m.cfg.MaxCPUPct)
								go m.RestartCore(fmt.Sprintf("CPU limit %.1f%% exceeded (%.1f%%)", m.cfg.MaxCPUPct, pct))
								prevCPU = cpuSample{}
								continue
							}
						}
						prevCPU = cur
					}
				}
			}
		}
	}()
}

func (m *Manager) stopResourceMonitor() {
	if m.resourceStop != nil {
		close(m.resourceStop)
		m.resourceStop = nil
	}
}

// ── /proc based resource reading ─────────────────────────────────────────

// procMemMB reads RSS memory (MB) from /proc/<pid>/status.
func procMemMB(pid int) (int, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			kb, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0, err
			}
			return kb / 1024, nil
		}
	}
	return 0, fmt.Errorf("VmRSS not found in /proc/%d/status", pid)
}

type cpuSample struct {
	utime uint64 // user jiffies
	stime uint64 // system jiffies
	total uint64 // total system jiffies (from /proc/stat)
}

// procCPUSample reads CPU jiffies for pid and the system total from /proc/stat.
func procCPUSample(pid int) (cpuSample, error) {
	// /proc/<pid>/stat fields (space separated, 1-indexed):
	// 14: utime, 15: stime
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return cpuSample{}, err
	}
	// The second field is the comm which may contain spaces and parentheses.
	// Find the last ')' and split from there.
	s := string(data)
	rp := strings.LastIndex(s, ")")
	if rp < 0 {
		return cpuSample{}, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(s[rp+1:])
	// After ')': fields[0]=state, fields[1]=ppid, ..., fields[11]=utime, fields[12]=stime
	if len(fields) < 13 {
		return cpuSample{}, fmt.Errorf("short /proc/%d/stat", pid)
	}
	utime, _ := strconv.ParseUint(fields[11], 10, 64)
	stime, _ := strconv.ParseUint(fields[12], 10, 64)

	// System total jiffies from /proc/stat first line
	statData, err := os.ReadFile("/proc/stat")
	if err != nil {
		return cpuSample{}, err
	}
	line := strings.SplitN(string(statData), "\n", 2)[0]
	var total uint64
	for i, f := range strings.Fields(line) {
		if i == 0 {
			continue // "cpu"
		}
		v, _ := strconv.ParseUint(f, 10, 64)
		total += v
	}

	return cpuSample{utime: utime, stime: stime, total: total}, nil
}

// cpuPercent calculates CPU usage % between two samples.
func cpuPercent(prev, cur cpuSample) float64 {
	procDelta := float64((cur.utime + cur.stime) - (prev.utime + prev.stime))
	sysDelta := float64(cur.total - prev.total)
	if sysDelta == 0 {
		return 0
	}
	return (procDelta / sysDelta) * 100.0
}

// ── Cron scheduler ────────────────────────────────────────────────────────

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
					log.Printf("process: cron %q fired", m.cfg.CronExpr)
					go m.RestartCore("cron")
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

// ── TUN device waiter ─────────────────────────────────────────────────────

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

func isAlive(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

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
