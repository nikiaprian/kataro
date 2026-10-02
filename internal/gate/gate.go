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
	routes     map[string][]config.Route
	blocked    map[string]struct{}
	needles    []string
	blockEmpty bool
}

// New builds a gate from validated config.
func New(cfg *config.Config) *Gate {
	routes := make(map[string][]config.Route, len(cfg.Routes))
	for _, r := range cfg.Routes {
		routes[r.Host] = append(routes[r.Host], r)
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
	return len(g.routes[h]) > 0
}

// Decide checks the incoming route, then sends blocked visitors to the
// blocked target when one is set. Otherwise a bot or blocked country is rejected.
func (g *Gate) Decide(in Input) Decision {
	blockedVisitor := g.isBot(in.UserAgent) || g.isBlockedCountry(in.Country)
	host, err := config.NormalizeHost(in.Host)
	if err != nil {
		return g.rejectOrMiss(blockedVisitor)
	}
	route, ok := matchRoute(g.routes[host], in.Path, in.RawQuery)
	if !ok {
		return g.rejectOrMiss(blockedVisitor)
	}
	if blockedVisitor {
		if route.BlockedTarget != nil {
			return Decision{Status: http.StatusFound, Location: route.BlockedTarget.String()}
		}
		return Decision{Status: http.StatusForbidden}
	}
	return Decision{
		Status:   http.StatusFound,
		Location: route.Target.String(),
	}
}

func (g *Gate) isBlockedCountry(country string) bool {
	country = strings.ToUpper(strings.TrimSpace(country))
	_, ok := g.blocked[country]
	return ok
}

func (g *Gate) rejectOrMiss(blockedVisitor bool) Decision {
	if blockedVisitor {
		return Decision{Status: http.StatusForbidden}
	}
	return Decision{Status: http.StatusNotFound}
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
// matchRoute picks the most specific redirect that fits the request.
// A slug or query template outranks a redirect that accepts any path or query.
func matchRoute(routes []config.Route, path, rawQuery string) (config.Route, bool) {
	var best config.Route
	found := false
	bestScore := -1
	for _, route := range routes {
		if !matchesIncoming(route, path, rawQuery) {
			continue
		}
		score := specificity(route)
		if !found || score > bestScore {
			best = route
			bestScore = score
			found = true
		}
	}
	return best, found
}

func specificity(route config.Route) int {
	score := 0
	if strings.Trim(route.Slug, "/") != "" {
		score += 1000
	}
	if strings.TrimSpace(route.Params) == "" {
		return score
	}
	q, err := url.ParseQuery(route.Params)
	if err != nil {
		return score + 1
	}
	return score + len(q)
}

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
