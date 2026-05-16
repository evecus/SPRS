package proxy

// group.go — ensure the proxy group exists and return its GID.
// Mirrors Singa's ensureSingaGroup / writeGroupEntry pattern.

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

const proxyGroupName = "tproxy_core"

// ensureProxyGroup looks up or creates the tproxy_core system group.
// Returns the GID.  Falls back to directly editing /etc/group when groupadd
// is unavailable (e.g. minimal containers).
func ensureProxyGroup() (uint32, error) {
	// 1. Group already exists?
	if g, err := user.LookupGroup(proxyGroupName); err == nil {
		gid, err := strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse gid %q: %w", g.Gid, err)
		}
		log.Printf("group: using existing group %q (gid=%d)", proxyGroupName, gid)
		return uint32(gid), nil
	}

	log.Printf("group: %q not found, creating", proxyGroupName)

	// 2. Try groupadd
	if path, err := exec.LookPath("groupadd"); err == nil {
		out, err := exec.Command(path, "--system", proxyGroupName).CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("groupadd: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
		g, err := user.LookupGroup(proxyGroupName)
		if err != nil {
			return 0, fmt.Errorf("lookup group after create: %w", err)
		}
		gid, err := strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse gid %q: %w", g.Gid, err)
		}
		log.Printf("group: created group %q (gid=%d)", proxyGroupName, gid)
		return uint32(gid), nil
	}

	// 3. Fallback: write directly to /etc/group
	return writeGroupEntry(proxyGroupName)
}

// writeGroupEntry appends a new group entry to /etc/group, picking a free GID
// in the system range 500–64999.
func writeGroupEntry(name string) (uint32, error) {
	const groupFile = "/etc/group"
	data, err := os.ReadFile(groupFile)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", groupFile, err)
	}

	// Collect used GIDs
	usedGIDs := make(map[uint32]bool)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if gid, err := strconv.ParseUint(parts[2], 10, 32); err == nil {
			usedGIDs[uint32(gid)] = true
		}
	}

	// Find a free GID
	var chosen uint32
	for candidate := uint32(500); candidate < 65000; candidate++ {
		if !usedGIDs[candidate] {
			chosen = candidate
			break
		}
	}
	if chosen == 0 {
		return 0, fmt.Errorf("no free GID available")
	}

	entry := fmt.Sprintf("%s:x:%d:\n", name, chosen)
	f, err := os.OpenFile(groupFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", groupFile, err)
	}
	defer f.Close()
	if _, err := f.WriteString(entry); err != nil {
		return 0, fmt.Errorf("write group entry: %w", err)
	}

	log.Printf("group: wrote entry for %q (gid=%d) to %s", name, chosen, groupFile)
	return chosen, nil
}
