package gate

import (
	"net/http"
	"net/url"
	"strings"

	"keitaro/internal/config"
)

// Default user-agent fragments. Matching is case-insensitive and uses contains.
var defaultUAFragments = []string{
	"bot",
	"spider",
	"crawler",
	"headless",
	"curl",
	"wget",
	"python-requests",
	"python-urllib",
	"go-http-client",
	"scrapy",
	"phantomjs",
	"selenium",
	"puppeteer",
	"playwright",
	"httpclient",
	"libwww",
	"okhttp",
}

// Input is everything the gate needs from one request. Country is already resolved.
type Input struct {
	Host      string
	UserAgent string
	RawQuery  string
	Country   string
}

// Decision is the HTTP result. Location is set only for a redirect.
type Decision struct {
	Status   int
	Location string
}

// Gate decides whether to reject or redirect a request.
type Gate struct {
	routes     map[string]*url.URL
	blocked    map[string]struct{}
	needles    []string
	blockEmpty bool
}

// New builds a gate from validated config.
func New(cfg *config.Config) *Gate {
	routes := make(map[string]*url.URL, len(cfg.Routes))
	for _, r := range cfg.Routes {
		routes[r.Host] = r.Target
	}
	needles := make([]string, 0, len(defaultUAFragments)+len(cfg.UAContains))
	seen := make(map[string]struct{}, len(defaultUAFragments)+len(cfg.UAContains))
	for _, n := range append(append([]string{}, defaultUAFragments...), cfg.UAContains...) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		needles = append(needles, n)
	}
	blocked := cfg.Blocked
	if blocked == nil {
		blocked = map[string]struct{}{}
	}
	return &Gate{
		routes:     routes,
		blocked:    blocked,
		needles:    needles,
		blockEmpty: cfg.BlockEmptyUA,
	}
}

// IsBot reports whether the user-agent is rejected.
func (g *Gate) IsBot(ua string) bool {
	return g.isBot(ua)
}

// HasRoute reports whether host is a configured redirect domain.
func (g *Gate) HasRoute(host string) bool {
	h, err := config.NormalizeHost(host)
	if err != nil {
		return false
	}
	_, ok := g.routes[h]
	return ok
}

// Decide checks bot, then country, then host.
func (g *Gate) Decide(in Input) Decision {
	if g.isBot(in.UserAgent) {
		return Decision{Status: http.StatusForbidden}
	}
	country := strings.ToUpper(strings.TrimSpace(in.Country))
	if _, ok := g.blocked[country]; ok {
		return Decision{Status: http.StatusForbidden}
	}
	host, err := config.NormalizeHost(in.Host)
	if err != nil {
		return Decision{Status: http.StatusNotFound}
	}
	target, ok := g.routes[host]
	if !ok {
		return Decision{Status: http.StatusNotFound}
	}
	return Decision{
		Status:   http.StatusFound,
		Location: withQuery(target, in.RawQuery),
	}
}

func (g *Gate) isBot(ua string) bool {
	ua = strings.ToLower(strings.TrimSpace(ua))
	if ua == "" {
		return g.blockEmpty
	}
	for _, n := range g.needles {
		if strings.Contains(ua, n) {
			return true
		}
	}
	return false
}

func withQuery(target *url.URL, rawQuery string) string {
	if rawQuery == "" {
		return target.String()
	}
	u := *target
	if u.RawQuery == "" {
		u.RawQuery = rawQuery
	} else {
		u.RawQuery = u.RawQuery + "&" + rawQuery
	}
	return u.String()
}
