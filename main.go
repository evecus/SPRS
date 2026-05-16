package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/tproxy/internal/proxy"
)

func main() {
	var cfg proxy.Config

	// 必要参数
	flag.IntVar(&cfg.TProxyPort, "tport", 0, "[必须] tproxy 入站端口（代理监听的 tproxy 端口）")
	flag.StringVar(&cfg.RunCmd, "run", "", "[必须] 启动代理的命令，例如 \"/usr/bin/sing-box -c config.json\"")

	// 可选参数
	flag.IntVar(&cfg.DNSPort, "dport", 0, "[可选] 代理 DNS 监听端口；不设置则不劫持 DNS")
	flag.BoolVar(&cfg.IPv6, "ipv6", false, "[可选] 启用 IPv6 tproxy 规则（默认关闭）")
	flag.BoolVar(&cfg.FakeIP, "fakeip", false, "[可选] 启用 FakeIP 模式（放行 198.18.0.0/15 和 fc00::/18）")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "用法: %s --tport <端口> --run \"<命令>\" [选项]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "必要参数:\n")
		fmt.Fprintf(os.Stderr, "  --tport int     tproxy 入站端口\n")
		fmt.Fprintf(os.Stderr, "  --run   string  代理启动命令\n\n")
		fmt.Fprintf(os.Stderr, "可选参数:\n")
		fmt.Fprintf(os.Stderr, "  --dport  int   代理 DNS 端口（不设置则不做 DNS 劫持）\n")
		fmt.Fprintf(os.Stderr, "  --ipv6   bool  启用 IPv6（默认 false）\n")
		fmt.Fprintf(os.Stderr, "  --fakeip bool  启用 FakeIP 模式（默认 false）\n\n")
		fmt.Fprintf(os.Stderr, "示例:\n")
		fmt.Fprintf(os.Stderr, "  %s --tport 7897 --run \"/usr/bin/sing-box -c config.json\"\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s --tport 7897 --dport 5353 --ipv6 --fakeip --run \"/usr/bin/sing-box -c config.json\"\n", os.Args[0])
	}

	flag.Parse()

	if cfg.TProxyPort == 0 || cfg.RunCmd == "" {
		fmt.Fprintf(os.Stderr, "错误: --tport 和 --run 为必要参数\n\n")
		flag.Usage()
		os.Exit(1)
	}

	log.SetFlags(log.Ldate | log.Ltime)
	log.SetPrefix("[tproxy] ")

	mgr, err := proxy.NewManager(cfg)
	if err != nil {
		log.Fatalf("初始化失败: %v", err)
	}

	if err := mgr.Start(); err != nil {
		log.Fatalf("启动失败: %v", err)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Printf("收到信号 %s，正在退出", s)

	mgr.Stop()
}
