package server

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
	"time"

	"keitaro/internal/config"
)

// clickSplit counts visits that reached the real target and visits that were blocked.
type clickSplit struct {
	Target  int64 `json:"target"`
	Blocked int64 `json:"blocked"`
}

func (s clickSplit) total() int64 {
	return s.Target + s.Blocked
}

// wib is Western Indonesian Time, UTC+7, with no daylight-saving change.
var wib = time.FixedZone("WIB", 7*60*60)

// routeClicks keeps click totals for each redirect, identified by host, slug, and params.
// Totals belong to the current WIB calendar day and clear at 00:00.
// Repeated requests from the same IP inside clickBurst count once.
type routeClicks struct {
	mu     sync.Mutex
	day    string
	counts map[string]clickSplit
	seen   map[string]time.Time
	path   string
}

type clickFile struct {
	Day    string                `json:"day"`
	Counts map[string]clickSplit `json:"counts"`
}

func newDomainClicks(path string) *routeClicks {
	d := &routeClicks{
		counts: make(map[string]clickSplit),
		seen:   make(map[string]time.Time),
		path:   path,
	}
	d.load()
	return d
}

// add records one click. toTarget is false when the visitor was sent to the blocked result.
func (d *routeClicks) add(host, slug, params, ip string, toTarget bool, now time.Time) {
	key := statKey(host, slug, params)
	if key == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rollLocked(now)
	d.pruneSeen(now)
	if ip != "" {
		burst := ip + " " + key
		if last, ok := d.seen[burst]; ok && now.Sub(last) < clickBurst {
			return
		}
		d.seen[burst] = now
	}
	split := d.counts[key]
	if toTarget {
		split.Target++
	} else {
		split.Blocked++
	}
	d.counts[key] = split
	d.saveLocked()
}

func (d *routeClicks) get(host, slug, params string) clickSplit {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rollLocked(time.Now())
	return d.counts[statKey(host, slug, params)]
}

func (d *routeClicks) snapshot() map[string]clickSplit {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rollLocked(time.Now())
	out := make(map[string]clickSplit, len(d.counts))
	for key, split := range d.counts {
		out[key] = split
	}
	return out
}

func (d *routeClicks) forgetHost(host string) {
	prefix := statKey(host, "", "")
	if prefix == "" {
		return
	}
	// statKey(host, "", "") is "host\n\n"; every route on that host shares the host prefix.
	prefix = strings.Split(prefix, "\n")[0] + "\n"
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rollLocked(time.Now())
	changed := false
	for key := range d.counts {
		if strings.HasPrefix(key, prefix) {
			delete(d.counts, key)
			changed = true
		}
	}
	if changed {
		d.saveLocked()
	}
}

func (d *routeClicks) forgetRoute(host, slug, params string) {
	key := statKey(host, slug, params)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rollLocked(time.Now())
	if _, ok := d.counts[key]; !ok {
		return
	}
	delete(d.counts, key)
	d.saveLocked()
}

func (d *routeClicks) rename(oldHost, oldSlug, oldParams, host, slug, params string) {
	oldKey := statKey(oldHost, oldSlug, oldParams)
	newKey := statKey(host, slug, params)
	if oldKey == "" || oldKey == newKey {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.rollLocked(time.Now())
	split, ok := d.counts[oldKey]
	if !ok {
		return
	}
	delete(d.counts, oldKey)
	next := d.counts[newKey]
	next.Target += split.Target
	next.Blocked += split.Blocked
	d.counts[newKey] = next
	d.saveLocked()
}

func (d *routeClicks) pruneSeen(now time.Time) {
	for key, last := range d.seen {
		if now.Sub(last) >= clickBurst {
			delete(d.seen, key)
		}
	}
}

func (d *routeClicks) rollLocked(now time.Time) {
	today := wibDate(now)
	if d.day == today {
		return
	}
	d.day = today
	d.counts = make(map[string]clickSplit)
	d.seen = make(map[string]time.Time)
	d.saveLocked()
}

func wibDate(now time.Time) string {
	return now.In(wib).Format("2006-01-02")
}

func (d *routeClicks) load() {
	if d.path == "" {
		return
	}
	raw, err := os.ReadFile(d.file())
	if err != nil {
		return
	}
	today := wibDate(time.Now())
	var saved clickFile
	if json.Unmarshal(raw, &saved) == nil && saved.Day != "" {
		d.day = saved.Day
		if saved.Day != today {
			d.rollLocked(time.Now())
			return
		}
		d.keep(saved.Counts)
		return
	}
	var legacy map[string]clickSplit
	if json.Unmarshal(raw, &legacy) != nil {
		return
	}
	d.day = today
	d.keep(legacy)
}

func (d *routeClicks) keep(saved map[string]clickSplit) {
	for key, split := range saved {
		if key != "" && split.total() > 0 {
			d.counts[key] = split
		}
	}
}

func (d *routeClicks) saveLocked() {
	if d.path == "" {
		return
	}
	if d.counts == nil {
		d.counts = map[string]clickSplit{}
	}
	raw, err := json.Marshal(clickFile{Day: d.day, Counts: d.counts})
	if err != nil {
		return
	}
	tmp := d.file() + ".tmp"
	if os.WriteFile(tmp, raw, 0o600) != nil {
		return
	}
	_ = os.Rename(tmp, d.file())
}

func (d *routeClicks) file() string {
	return d.path + ".domainclicks"
}

func statKey(host, slug, params string) string {
	host, err := config.NormalizeHost(host)
	if err != nil {
		return ""
	}
	slug = strings.Trim(strings.TrimSpace(slug), "/")
	params = strings.TrimPrefix(strings.TrimSpace(params), "?")
	return host + "\n" + slug + "\n" + params
}
