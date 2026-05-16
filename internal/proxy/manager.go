package proxy

// manager.go — 协调组创建、防火墙配置和代理子进程。

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// Config 保存所有 CLI 参数。
type Config struct {
	// 必要参数
	TProxyPort int    // --tport
	RunCmd     string // --run

	// 可选参数
	DNSPort int  // --dport  (0 = 不劫持 DNS)
	IPv6    bool // --ipv6
	FakeIP  bool // --fakeip
}

// Manager 管理防火墙状态和代理子进程。
type Manager struct {
	cfg      Config
	gid      uint32
	cmd      *exec.Cmd
	mu       sync.Mutex
	confPath string
}

// NewManager 初始化：确保代理组存在。
func NewManager(cfg Config) (*Manager, error) {
	gid, err := ensureProxyGroup()
	if err != nil {
		return nil, fmt.Errorf("proxy group: %w", err)
	}

	confDir := filepath.Dir(os.Args[0])
	if confDir == "" || confDir == "." {
		confDir = os.TempDir()
	}
	confPath := filepath.Join(confDir, nftTableName+".nft")

	return &Manager{
		cfg:      cfg,
		gid:      gid,
		confPath: confPath,
	}, nil
}

// Start 应用防火墙规则并启动代理进程。
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	log.Printf("manager: tport=%d dport=%d ipv6=%v fakeip=%v gid=%d",
		m.cfg.TProxyPort, m.cfg.DNSPort, m.cfg.IPv6, m.cfg.FakeIP, m.gid)

	conf := buildNFTConf(m.cfg, m.gid)
	if err := applyNFT(conf, m.confPath); err != nil {
		return fmt.Errorf("nft apply: %w", err)
	}

	setupTProxyRoutes(m.cfg.IPv6)
	syncLocalIPs(m.cfg.IPv6)

	if err := m.startProcess(); err != nil {
		cleanupNFT(m.confPath)
		cleanupTProxyRoutes(m.cfg.IPv6)
		return fmt.Errorf("start process: %w", err)
	}

	if m.cfg.DNSPort > 0 {
		log.Printf("manager: DNS hijack enabled: :53 -> :%d", m.cfg.DNSPort)
	} else {
		log.Println("manager: DNS hijack disabled")
	}
	if m.cfg.FakeIP {
		log.Printf("manager: FakeIP enabled (IPv4=%s IPv6=%s)", fakeIPv4Range, fakeIPv6Range)
	}

	return nil
}

// Stop 停止代理进程并清理防火墙规则。
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil && m.cmd.Process != nil {
		log.Printf("manager: stopping proxy (pid=%d)", m.cmd.Process.Pid)
		_ = m.cmd.Process.Signal(syscall.SIGTERM)
		_ = m.cmd.Wait()
		m.cmd = nil
	}

	cleanupTProxyRoutes(m.cfg.IPv6)
	cleanupNFT(m.confPath)
	log.Println("manager: stopped")
}

// startProcess 以代理组 GID 启动代理命令。
// uid 保持 0（root）以保留 CAP_NET_ADMIN 等能力，
// gid 设为 tproxy_core 使 nft skgid 规则能豁免其流量。
func (m *Manager) startProcess() error {
	parts := splitCmd(m.cfg.RunCmd)
	if len(parts) == 0 {
		return fmt.Errorf("empty run command")
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
	log.Printf("manager: started proxy pid=%d", cmd.Process.Pid)

	go streamLog("proxy/out", stdout)
	go streamLog("proxy/err", stderr)

	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("manager: proxy exited: %v", err)
		} else {
			log.Println("manager: proxy exited cleanly")
		}
	}()

	m.cmd = cmd
	return nil
}

func streamLog(prefix string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		log.Printf("[%s] %s", prefix, scanner.Text())
	}
}

// splitCmd 按空格切分命令，支持双引号包裹的参数。
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
