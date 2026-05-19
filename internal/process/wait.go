package process

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const waitPollInterval = 5 * time.Second

// WaitForProcesses blocks until all process names in names appear in /proc,
// or until timeout elapses (0 = wait forever).
// Returns error if timeout is exceeded.
func WaitForProcesses(names []string, timeoutSec int) error {
	if len(names) == 0 {
		return nil
	}

	log.Printf("wait_process: waiting for processes: %v (timeout=%ds)", names, timeoutSec)

	deadline := time.Time{}
	if timeoutSec > 0 {
		deadline = time.Now().Add(time.Duration(timeoutSec) * time.Second)
	}

	for {
		missing := findMissingProcesses(names)
		if len(missing) == 0 {
			log.Printf("wait_process: all processes found: %v", names)
			return nil
		}
		log.Printf("wait_process: still waiting for: %v", missing)

		if !deadline.IsZero() && time.Now().Add(waitPollInterval).After(deadline) {
			return fmt.Errorf("wait_process: timeout after %ds, missing: %v", timeoutSec, missing)
		}

		time.Sleep(waitPollInterval)
	}
}

// findMissingProcesses returns names that are not currently running.
// Matches against /proc/<pid>/comm (exact full process name, no fuzzy).
func findMissingProcesses(names []string) []string {
	running := runningProcessNames()
	var missing []string
	for _, name := range names {
		if !running[name] {
			missing = append(missing, name)
		}
	}
	return missing
}

// runningProcessNames reads /proc and returns a set of all comm names.
func runningProcessNames() map[string]bool {
	found := make(map[string]bool)
	entries, err := filepath.Glob("/proc/*/comm")
	if err != nil {
		return found
	}
	for _, commPath := range entries {
		data, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(data))
		if name != "" {
			found[name] = true
		}
	}
	return found
}
