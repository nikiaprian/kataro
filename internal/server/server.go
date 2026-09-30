package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"keitaro/internal/config"
	"keitaro/internal/gate"
)

// CountryLookup resolves an IP to an ISO country code. Empty string means unknown.
type CountryLookup interface {
	Country(net.IP) (string, error)
}

type handler struct {
	mu       sync.Mutex
	cfg      *config.Config
	path     string
	gate     *gate.Gate
	lookup   CountryLookup
	sessions *sessions
}

// New returns an HTTP handler. lookup may be nil when country comes only from Cloudflare.
// configPath is rewritten when the dashboard changes routes or blocked countries.
func New(cfg *config.Config, configPath string, lookup CountryLookup) http.Handler {
	return &handler{
		cfg:      cfg,
		path:     configPath,
		gate:     gate.New(cfg),
		lookup:   lookup,
		sessions: newSessions(),
	}
}

// Server builds an HTTP server with short timeouts. Dashboard forms are limited to 64 KiB.
func Server(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	g, trusted := h.snapshot()
	host, hostErr := config.NormalizeHost(r.Host)
	if hostErr == nil && isDashboardHost(host) && !g.HasRoute(host) {
		if g.IsBot(r.UserAgent()) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		h.serveDashboard(w, r)
		return
	}

	ip := clientIP(r, trusted)
	decision := g.Decide(gate.Input{
		Host:      r.Host,
		UserAgent: r.UserAgent(),
		RawQuery:  r.URL.RawQuery,
		Country:   h.country(r, ip),
	})

	if decision.Status == http.StatusFound {
		w.Header().Set("Location", decision.Location)
	}
	w.WriteHeader(decision.Status)
}

func (h *handler) snapshot() (*gate.Gate, []*net.IPNet) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.gate, h.cfg.Trusted
}

func isDashboardHost(host string) bool {
	if host == "localhost" {
		return true
	}
	return net.ParseIP(host) != nil
}

func (h *handler) country(r *http.Request, ip net.IP) string {
	cf := strings.ToUpper(strings.TrimSpace(r.Header.Get("CF-IPCountry")))
	if len(cf) == 2 && cf != "XX" && isAlpha(cf) {
		return cf
	}
	if h.lookup == nil || ip == nil {
		return ""
	}
	code, err := h.lookup.Country(ip)
	if err != nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(code))
}

func isAlpha(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return true
}

// clientIP prefers Cloudflare's connecting IP when CF-IPCountry is also present,
// then X-Forwarded-For from a trusted proxy, then the TCP peer.
func clientIP(r *http.Request, trusted []*net.IPNet) net.IP {
	remote := parseIP(r.RemoteAddr)
	if strings.TrimSpace(r.Header.Get("CF-IPCountry")) != "" {
		if ip := parseIP(r.Header.Get("CF-Connecting-IP")); ip != nil {
			return ip
		}
	}
	if ipInNets(remote, trusted) {
		if ip := forwardedIP(r.Header.Get("X-Forwarded-For"), trusted); ip != nil {
			return ip
		}
	}
	return remote
}

// forwardedIP walks X-Forwarded-For from the right and skips trusted proxies,
// so a client-supplied prefix cannot override the address added by our proxy.
func forwardedIP(header string, trusted []*net.IPNet) net.IP {
	parts := strings.Split(header, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		ip := parseIP(parts[i])
		if ip == nil || ipInNets(ip, trusted) {
			continue
		}
		return ip
	}
	return nil
}

func parseIP(s string) net.IP {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"")
	if s == "" {
		return nil
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	ip := net.ParseIP(s)
	if ip == nil {
		return nil
	}
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
