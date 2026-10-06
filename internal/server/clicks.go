package server

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

const (
	clickWindowLen = time.Hour
	// Requests from one browser open arrive together. They count as one click.
	clickBurst = 10 * time.Second
)

// clickWindow counts allowed redirects per IP during the last hour.
// The record is stored beside the config file so a container restart keeps it.
type clickWindow struct {
	mu   sync.Mutex
	m    map[string][]time.Time
	path string
}

func newClickWindow(path string) *clickWindow {
	c := &clickWindow{m: make(map[string][]time.Time), path: path}
	c.load()
	return c
}

// reset forgets every IP so visitors can pass the click limit again.
func (c *clickWindow) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m = make(map[string][]time.Time)
	c.saveLocked()
}

// allow records one click and reports whether it is still within max per hour.
// Repeated requests inside clickBurst do not add another click.
func (c *clickWindow) allow(ip string, max int, now time.Time) bool {
	if ip == "" || max < 1 {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := recent(c.m[ip], now)
	if len(kept) > 0 && now.Sub(kept[len(kept)-1]) < clickBurst {
		c.m[ip] = kept
		return true
	}
	if len(kept) >= max {
		c.m[ip] = kept
		c.saveLocked()
		return false
	}
	c.m[ip] = append(kept, now)
	c.saveLocked()
	return true
}

func recent(hits []time.Time, now time.Time) []time.Time {
	cutoff := now.Add(-clickWindowLen)
	kept := make([]time.Time, 0, len(hits))
	for _, hit := range hits {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	return kept
}

func (c *clickWindow) load() {
	if c.path == "" {
		return
	}
	raw, err := os.ReadFile(c.file())
	if err != nil {
		return
	}
	var saved map[string][]int64
	if json.Unmarshal(raw, &saved) != nil {
		return
	}
	now := time.Now()
	for ip, stamps := range saved {
		hits := make([]time.Time, 0, len(stamps))
		for _, sec := range stamps {
			hits = append(hits, time.Unix(0, sec))
		}
		if kept := recent(hits, now); len(kept) > 0 {
			c.m[ip] = kept
		}
	}
}

func (c *clickWindow) saveLocked() {
	if c.path == "" {
		return
	}
	saved := make(map[string][]int64, len(c.m))
	for ip, hits := range c.m {
		if len(hits) == 0 {
			continue
		}
		stamps := make([]int64, len(hits))
		for i, hit := range hits {
			stamps[i] = hit.UnixNano()
		}
		saved[ip] = stamps
	}
	raw, err := json.Marshal(saved)
	if err != nil {
		return
	}
	tmp := c.file() + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, c.file())
}

func (c *clickWindow) file() string {
	return c.path + ".clicks"
}
