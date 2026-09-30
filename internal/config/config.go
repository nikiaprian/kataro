package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Route is one host-to-target mapping. Host is normalized.
// Slug and Params describe the incoming URL, for example
// host/asdfg?zxc=[qwerty]. A [name] token matches any value.
type Route struct {
	Host          string
	Target        *url.URL
	BlockedTarget *url.URL
	Slug          string
	Params        string
}

// Incoming is the visitor URL pattern: host, optional slug, optional params.
func (r Route) Incoming() string {
	s := r.Host
	if r.Slug != "" {
		s += "/" + r.Slug
	}
	if r.Params != "" {
		s += "?" + r.Params
	}
	return s
}

// Config is the validated runtime configuration.
type Config struct {
	Listen       string
	GeoIPDB      string
	Trusted      []*net.IPNet
	TrustedRaw   []string
	Blocked      map[string]struct{}
	BlockEmptyUA bool
	UAContains   []string
	Domains      []string
	Routes       []Route
	SSLEmail     string
}

type file struct {
	Listen           string      `yaml:"listen"`
	GeoIPDB          string      `yaml:"geoip_db"`
	TrustedProxies   []string    `yaml:"trusted_proxies"`
	BlockedCountries []string    `yaml:"blocked_countries"`
	Bot              botFile     `yaml:"bot"`
	Domains          []string    `yaml:"domains"`
	Routes           []routeFile `yaml:"routes"`
	SSLEmail         string      `yaml:"ssl_email"`
}

type botFile struct {
	BlockEmptyUserAgent *bool    `yaml:"block_empty_user_agent"`
	UserAgentContains   []string `yaml:"user_agent_contains"`
}

type routeFile struct {
	Host          string `yaml:"host"`
	Target        string `yaml:"target"`
	BlockedTarget string `yaml:"blocked_target,omitempty"`
	Slug          string `yaml:"slug,omitempty"`
	Params        string `yaml:"params,omitempty"`
}

// Load reads and validates a YAML config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return Parse(raw)
}

// Parse validates YAML config bytes.
func Parse(raw []byte) (*Config, error) {
	var f file
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	listen := strings.TrimSpace(f.Listen)
	if listen == "" {
		listen = ":8080"
	}

	trusted, trustedRaw, err := parseCIDRs(f.TrustedProxies)
	if err != nil {
		return nil, err
	}

	blocked, err := parseCountries(f.BlockedCountries)
	if err != nil {
		return nil, err
	}

	blockEmpty := true
	if f.Bot.BlockEmptyUserAgent != nil {
		blockEmpty = *f.Bot.BlockEmptyUserAgent
	}

	needles := make([]string, 0, len(f.Bot.UserAgentContains))
	for _, n := range f.Bot.UserAgentContains {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		needles = append(needles, n)
	}

	domains, err := parseDomains(f.Domains)
	if err != nil {
		return nil, err
	}

	routes := make([]Route, 0, len(f.Routes))
	seen := make(map[string]struct{}, len(f.Routes))
	for i, r := range f.Routes {
		host, err := normalizeHost(r.Host)
		if err != nil {
			return nil, fmt.Errorf("config: route %d: %w", i, err)
		}
		if _, ok := seen[host]; ok {
			return nil, fmt.Errorf("config: duplicate host %q", host)
		}
		seen[host] = struct{}{}

		target, err := parseTarget(r.Target)
		if err != nil {
			return nil, fmt.Errorf("config: route %d: %w", i, err)
		}
		blocked, err := parseOptionalTarget(r.BlockedTarget)
		if err != nil {
			return nil, fmt.Errorf("config: route %d: %w", i, err)
		}
		slug, err := parseSlug(r.Slug)
		if err != nil {
			return nil, fmt.Errorf("config: route %d: %w", i, err)
		}
		params, err := parseParams(r.Params)
		if err != nil {
			return nil, fmt.Errorf("config: route %d: %w", i, err)
		}
		routes = append(routes, Route{Host: host, Target: target, BlockedTarget: blocked, Slug: slug, Params: params})
		domains = appendDomain(domains, host)
	}

	return &Config{
		Listen:       listen,
		GeoIPDB:      strings.TrimSpace(f.GeoIPDB),
		Trusted:      trusted,
		TrustedRaw:   trustedRaw,
		Blocked:      blocked,
		BlockEmptyUA: blockEmpty,
		UAContains:   needles,
		Domains:      domains,
		Routes:       routes,
		SSLEmail:     strings.TrimSpace(f.SSLEmail),
	}, nil
}

// AddDomain records an incoming domain. A domain already in the list is unchanged.
func AddDomain(cfg *Config, host string) (*Config, error) {
	host, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	next := cfg.clone()
	next.Domains = appendDomain(next.Domains, host)
	return next, nil
}

// RemoveDomain drops an incoming domain and any redirect that uses it.
func RemoveDomain(cfg *Config, host string) (*Config, error) {
	host, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	next := cfg.clone()
	kept := make([]string, 0, len(next.Domains))
	for _, domain := range next.Domains {
		if domain != host {
			kept = append(kept, domain)
		}
	}
	next.Domains = kept
	routes := make([]Route, 0, len(next.Routes))
	for _, route := range next.Routes {
		if route.Host != host {
			routes = append(routes, route)
		}
	}
	next.Routes = routes
	return next, nil
}

// UpsertRoute adds a redirect or replaces its targets, slug, and params.
// blockedTarget may be empty. Bots and blocked countries then stay rejected.
func UpsertRoute(cfg *Config, host, target, blockedTarget, slug, params string) (*Config, error) {
	host, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	dest, err := parseTarget(target)
	if err != nil {
		return nil, err
	}
	blocked, err := parseOptionalTarget(blockedTarget)
	if err != nil {
		return nil, err
	}
	slug, err = parseSlug(slug)
	if err != nil {
		return nil, err
	}
	params, err = parseParams(params)
	if err != nil {
		return nil, err
	}
	if !hasDomain(cfg.Domains, host) {
		return nil, fmt.Errorf("config: domain %q is not in the incoming list", host)
	}
	next := cfg.clone()
	route := Route{Host: host, Target: dest, BlockedTarget: blocked, Slug: slug, Params: params}
	for i, existing := range next.Routes {
		if existing.Host == host {
			next.Routes[i] = route
			return next, nil
		}
	}
	next.Routes = append(next.Routes, route)
	return next, nil
}

// RemoveRoute drops a redirect domain. A missing host is left unchanged.
func RemoveRoute(cfg *Config, host string) (*Config, error) {
	host, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	next := cfg.clone()
	kept := make([]Route, 0, len(next.Routes))
	for _, route := range next.Routes {
		if route.Host != host {
			kept = append(kept, route)
		}
	}
	next.Routes = kept
	return next, nil
}

// AddCountry adds one ISO country code to the block list.
func AddCountry(cfg *Config, code string) (*Config, error) {
	parsed, err := parseCountries([]string{code})
	if err != nil {
		return nil, err
	}
	if len(parsed) == 0 {
		return nil, fmt.Errorf("config: invalid country code %q", code)
	}
	next := cfg.clone()
	for c := range parsed {
		next.Blocked[c] = struct{}{}
	}
	return next, nil
}

// RemoveCountry drops one ISO country code. A missing code is left unchanged.
func RemoveCountry(cfg *Config, code string) (*Config, error) {
	parsed, err := parseCountries([]string{code})
	if err != nil {
		return nil, err
	}
	next := cfg.clone()
	for c := range parsed {
		delete(next.Blocked, c)
	}
	return next, nil
}

// Save writes the config back to disk, replacing the previous file.
func Save(path string, cfg *Config) error {
	raw, err := yaml.Marshal(cfg.file())
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(path)
		if err := os.Rename(tmp, path); err != nil {
			return fmt.Errorf("replace config: %w", err)
		}
	}
	return nil
}

func (c *Config) clone() *Config {
	next := *c
	next.Trusted = append([]*net.IPNet(nil), c.Trusted...)
	next.TrustedRaw = append([]string(nil), c.TrustedRaw...)
	next.UAContains = append([]string(nil), c.UAContains...)
	next.Domains = append([]string(nil), c.Domains...)
	next.Routes = append([]Route(nil), c.Routes...)
	next.Blocked = make(map[string]struct{}, len(c.Blocked))
	for code := range c.Blocked {
		next.Blocked[code] = struct{}{}
	}
	return &next
}

func (c *Config) file() file {
	countries := make([]string, 0, len(c.Blocked))
	for code := range c.Blocked {
		countries = append(countries, code)
	}
	sort.Strings(countries)
	domains := append([]string(nil), c.Domains...)
	if domains == nil {
		domains = []string{}
	}
	routes := make([]routeFile, 0, len(c.Routes))
	for _, route := range c.Routes {
		saved := routeFile{
			Host:   route.Host,
			Target: route.Target.String(),
			Slug:   route.Slug,
			Params: route.Params,
		}
		if route.BlockedTarget != nil {
			saved.BlockedTarget = route.BlockedTarget.String()
		}
		routes = append(routes, saved)
	}
	proxies := c.TrustedRaw
	if proxies == nil {
		proxies = []string{}
	}
	needles := c.UAContains
	if needles == nil {
		needles = []string{}
	}
	if countries == nil {
		countries = []string{}
	}
	if routes == nil {
		routes = []routeFile{}
	}
	blockEmpty := c.BlockEmptyUA
	return file{
		Listen:           c.Listen,
		GeoIPDB:          c.GeoIPDB,
		TrustedProxies:   proxies,
		BlockedCountries: countries,
		Bot: botFile{
			BlockEmptyUserAgent: &blockEmpty,
			UserAgentContains:   needles,
		},
		Domains:  domains,
		Routes:   routes,
		SSLEmail: c.SSLEmail,
	}
}

func parseDomains(values []string) ([]string, error) {
	out := make([]string, 0, len(values))
	for i, raw := range values {
		host, err := normalizeHost(raw)
		if err != nil {
			return nil, fmt.Errorf("config: domain %d: %w", i, err)
		}
		out = appendDomain(out, host)
	}
	return out, nil
}

func appendDomain(domains []string, host string) []string {
	if hasDomain(domains, host) {
		return domains
	}
	return append(domains, host)
}

func hasDomain(domains []string, host string) bool {
	for _, domain := range domains {
		if domain == host {
			return true
		}
	}
	return false
}

func parseCIDRs(values []string) ([]*net.IPNet, []string, error) {
	nets := make([]*net.IPNet, 0, len(values))
	raw := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		_, n, err := net.ParseCIDR(v)
		if err != nil {
			return nil, nil, fmt.Errorf("config: invalid trusted proxy %q", v)
		}
		nets = append(nets, n)
		raw = append(raw, v)
	}
	return nets, raw, nil
}

func parseCountries(values []string) (map[string]struct{}, error) {
	out := make(map[string]struct{}, len(values))
	for _, v := range values {
		code := strings.ToUpper(strings.TrimSpace(v))
		if code == "" {
			continue
		}
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
			return nil, fmt.Errorf("config: invalid country code %q", v)
		}
		out[code] = struct{}{}
	}
	return out, nil
}

var tokenPattern = regexp.MustCompile(`\[([A-Za-z0-9_]+)\]`)

func parseSlug(raw string) (string, error) {
	s := strings.Trim(strings.TrimSpace(raw), "/")
	if s == "" {
		return "", nil
	}
	if strings.Contains(s, "..") || strings.ContainsAny(s, "?#\\ \t\r\n") {
		return "", fmt.Errorf("slug hanya boleh huruf, angka, garis, dan token [nama]")
	}
	cleaned := tokenPattern.ReplaceAllString(s, "x")
	for _, r := range cleaned {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '-' || r == '_' || r == '.':
		default:
			return "", fmt.Errorf("slug hanya boleh huruf, angka, garis, dan token [nama]")
		}
	}
	return s, nil
}

func parseParams(raw string) (string, error) {
	s := strings.TrimPrefix(strings.TrimSpace(raw), "?")
	if s == "" {
		return "", nil
	}
	if strings.ContainsAny(s, " \t\r\n#") {
		return "", fmt.Errorf("parameter tidak valid")
	}
	return s, nil
}

func parseOptionalTarget(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	return parseTarget(raw)
}

func parseTarget(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("target must be an absolute http or https URL")
	}
	if u.User != nil {
		return nil, fmt.Errorf("target must not include user info")
	}
	return u, nil
}

// NormalizeHost lowercases a host and strips a port. Exported for request handling.
func NormalizeHost(host string) (string, error) {
	return normalizeHost(host)
}

func normalizeHost(host string) (string, error) {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return "", fmt.Errorf("host is empty")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", fmt.Errorf("host is empty")
	}
	return host, nil
}
