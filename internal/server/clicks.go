package server

import (
	"sync"
	"time"
)

// clickWindow counts allowed redirects per IP during the last hour.
type clickWindow struct {
	mu sync.Mutex
	m  map[string][]time.Time
}

func newClickWindow() *clickWindow {
	return &clickWindow{m: make(map[string][]time.Time)}
}

// allow records one click and reports whether it is still within max per hour.
func (c *clickWindow) allow(ip string, max int, now time.Time) bool {
	if ip == "" || max < 1 {
		return true
	}
	cutoff := now.Add(-time.Hour)
	c.mu.Lock()
	defer c.mu.Unlock()
	kept := c.m[ip][:0]
	for _, hit := range c.m[ip] {
		if hit.After(cutoff) {
			kept = append(kept, hit)
		}
	}
	if len(kept) >= max {
		if len(kept) == 0 {
			delete(c.m, ip)
		} else {
			c.m[ip] = kept
		}
		return false
	}
	c.m[ip] = append(kept, now)
	return true
}
