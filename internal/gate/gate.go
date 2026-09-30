package gate

import (
	"net/http"
	"net/url"
	"regexp"
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
	Path      string
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
	routes     map[string]config.Route
	blocked    map[string]struct{}
	needles    []string
	blockEmpty bool
}

// New builds a gate from validated config.
func New(cfg *config.Config) *Gate {
	routes := make(map[string]config.Route, len(cfg.Routes))
	for _, r := range cfg.Routes {
		routes[r.Host] = r
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
	route, ok := g.routes[host]
	if !ok || !matchesIncoming(route, in.Path, in.RawQuery) {
		return Decision{Status: http.StatusNotFound}
	}
	return Decision{
		Status:   http.StatusFound,
		Location: route.Target.String(),
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

var tokenPattern = regexp.MustCompile(`\[([A-Za-z0-9_]+)\]`)

// matchesIncoming reports whether the request path and query fit the route.
// An empty slug matches any path. An empty params template matches any query.
// A [name] token matches any value for that piece.
func matchesIncoming(route config.Route, path, rawQuery string) bool {
	return pathMatches(route.Slug, path) && queryMatches(route.Params, rawQuery)
}

func pathMatches(slug, path string) bool {
	slug = strings.Trim(slug, "/")
	path = strings.Trim(path, "/")
	if slug == "" {
		return true
	}
	re, ok := tokenRegexp(slug, `[^/]*`)
	if !ok {
		return path == slug
	}
	return re.MatchString(path)
}

func queryMatches(params, rawQuery string) bool {
	if strings.TrimSpace(params) == "" {
		return true
	}
	want, err := url.ParseQuery(params)
	if err != nil {
		return false
	}
	got, err := url.ParseQuery(rawQuery)
	if err != nil {
		return false
	}
	for key, expected := range want {
		actual, ok := got[key]
		if !ok {
			return false
		}
		for _, pattern := range expected {
			if !valueMatches(pattern, first(actual)) {
				return false
			}
		}
	}
	return true
}

func valueMatches(pattern, actual string) bool {
	re, ok := tokenRegexp(pattern, `.*`)
	if !ok {
		return pattern == actual
	}
	return re.MatchString(actual)
}

func tokenRegexp(pattern, token string) (*regexp.Regexp, bool) {
	if !tokenPattern.MatchString(pattern) {
		return nil, false
	}
	var b strings.Builder
	b.WriteString("^")
	last := 0
	for _, loc := range tokenPattern.FindAllStringIndex(pattern, -1) {
		b.WriteString(regexp.QuoteMeta(pattern[last:loc[0]]))
		b.WriteString(token)
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(pattern[last:]))
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, false
	}
	return re, true
}

func first(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
