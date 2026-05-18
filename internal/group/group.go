// Package group ensures the sprs system group exists.
// Logic copied from Singa's core/manager.go ensureSingaGroup / writeGroupEntry.
package group

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

const GroupName = "sprs"

// Ensure looks up or creates the sprs system group and returns its GID.
func Ensure() (uint32, error) {
	if g, err := user.LookupGroup(GroupName); err == nil {
		gid, err := strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse gid %q: %w", g.Gid, err)
		}
		return uint32(gid), nil
	}

	log.Printf("group: %q not found, creating", GroupName)

	if path, err := exec.LookPath("groupadd"); err == nil {
		out, err := exec.Command(path, "--system", GroupName).CombinedOutput()
		if err != nil {
			return 0, fmt.Errorf("groupadd: %w (output: %s)", err, strings.TrimSpace(string(out)))
		}
		g, err := user.LookupGroup(GroupName)
		if err != nil {
			return 0, fmt.Errorf("lookup group after create: %w", err)
		}
		gid, err := strconv.ParseUint(g.Gid, 10, 32)
		if err != nil {
			return 0, fmt.Errorf("parse gid: %w", err)
		}
		log.Printf("group: created %q (gid=%d)", GroupName, gid)
		return uint32(gid), nil
	}

	return writeGroupEntry(GroupName)
}

func writeGroupEntry(name string) (uint32, error) {
	const groupFile = "/etc/group"
	data, err := os.ReadFile(groupFile)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", groupFile, err)
	}
	used := map[uint32]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 3 {
			continue
		}
		if gid, err := strconv.ParseUint(parts[2], 10, 32); err == nil {
			used[uint32(gid)] = true
		}
	}
	var chosen uint32
	for c := uint32(500); c < 65000; c++ {
		if !used[c] {
			chosen = c
			break
		}
	}
	if chosen == 0 {
		return 0, fmt.Errorf("no free GID available")
	}
	f, err := os.OpenFile(groupFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", groupFile, err)
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "%s:x:%d:\n", name, chosen); err != nil {
		return 0, fmt.Errorf("write group entry: %w", err)
	}
	log.Printf("group: wrote %q gid=%d to %s", name, chosen, groupFile)
	return chosen, nil
}
