// Package cronrestart provides a simple 5-field cron scheduler.
// Copied verbatim from Singa's internal/cronrestart/cron.go.
package cronrestart

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type field struct {
	vals map[int]bool // nil = wildcard (*)
}

func parseField(s string, min, max int) (field, error) {
	if s == "*" {
		return field{}, nil
	}
	vals := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		if strings.Contains(part, "-") {
			rng := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(rng[0])
			hi, err2 := strconv.Atoi(rng[1])
			if err1 != nil || err2 != nil || lo < min || hi > max || lo > hi {
				return field{}, fmt.Errorf("invalid range %q", part)
			}
			for i := lo; i <= hi; i++ {
				vals[i] = true
			}
		} else if strings.Contains(part, "/") {
			sp := strings.SplitN(part, "/", 2)
			step, err := strconv.Atoi(sp[1])
			if err != nil || step <= 0 {
				return field{}, fmt.Errorf("invalid step %q", part)
			}
			start := min
			if sp[0] != "*" {
				var err error
				start, err = strconv.Atoi(sp[0])
				if err != nil {
					return field{}, fmt.Errorf("invalid step start %q", part)
				}
			}
			for i := start; i <= max; i += step {
				vals[i] = true
			}
		} else {
			v, err := strconv.Atoi(part)
			if err != nil || v < min || v > max {
				return field{}, fmt.Errorf("value %q out of range [%d-%d]", part, min, max)
			}
			vals[v] = true
		}
	}
	return field{vals: vals}, nil
}

func (f field) matches(v int) bool {
	if f.vals == nil {
		return true
	}
	return f.vals[v]
}

// Entry is a parsed cron expression.
type Entry struct {
	minute field
	hour   field
	dom    field
	month  field
	dow    field
	Raw    string
}

// Parse parses a standard 5-field cron expression.
func Parse(expr string) (*Entry, error) {
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return nil, fmt.Errorf("cron expression must have 5 fields, got %d", len(parts))
	}
	e := &Entry{Raw: expr}
	var err error
	if e.minute, err = parseField(parts[0], 0, 59); err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	if e.hour, err = parseField(parts[1], 0, 23); err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	if e.dom, err = parseField(parts[2], 1, 31); err != nil {
		return nil, fmt.Errorf("day-of-month: %w", err)
	}
	if e.month, err = parseField(parts[3], 1, 12); err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	if e.dow, err = parseField(parts[4], 0, 6); err != nil {
		return nil, fmt.Errorf("day-of-week: %w", err)
	}
	return e, nil
}

// Matches reports whether t matches this cron entry.
func (e *Entry) Matches(t time.Time) bool {
	return e.minute.matches(t.Minute()) &&
		e.hour.matches(t.Hour()) &&
		e.dom.matches(t.Day()) &&
		e.month.matches(int(t.Month())) &&
		e.dow.matches(int(t.Weekday()))
}
