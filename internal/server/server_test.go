package server

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"keitaro/internal/config"
)

type mapLookup map[string]string

func (m mapLookup) Country(ip net.IP) (string, error) {
	if ip == nil {
		return "", nil
	}
	return m[ip.String()], nil
}

func testHandler(t *testing.T, yaml string, lookup CountryLookup) http.Handler {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return New(cfg, filepath.Join(t.TempDir(), "config.yaml"), lookup, nil)
}

const baseConfig = `
blocked_countries: ["CN"]
trusted_proxies: ["10.0.0.0/8"]
routes:
  - host: go.example.com
    target: https://offer.example/landing
`

func request(method, host, path, remote string) *http.Request {
	req := httptest.NewRequest(method, "http://"+host+path, nil)
	req.Host = host
	req.RemoteAddr = remote
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	return req
}

func TestRedirectPreservesQuery(t *testing.T) {
	h := testHandler(t, baseConfig, nil)
	rec := httptest.NewRecorder()
	req := request(http.MethodGet, "go.example.com", "/?click=1&sub=a", "203.0.113.8:4000")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://offer.example/landing" {
		t.Fatalf("location = %q", loc)
	}
	body, _ := io.ReadAll(rec.Body)
	if len(body) != 0 {
		t.Fatalf("body = %q", body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control = %q", rec.Header().Get("Cache-Control"))
	}
}

func TestBotAndUnknownHost(t *testing.T) {
	h := testHandler(t, baseConfig, nil)

	rec := httptest.NewRecorder()
	req := request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000")
	req.Header.Set("User-Agent", "curl/8.0")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("bot status = %d", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("blocked response leaked Location")
	}

	rec = httptest.NewRecorder()
	req = request(http.MethodGet, "missing.example", "/", "203.0.113.8:4000")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing status = %d", rec.Code)
	}
}

func TestCountryFromCloudflareAndGeo(t *testing.T) {
	h := testHandler(t, baseConfig, mapLookup{
		"203.0.113.8":  "ID",
		"198.51.100.9": "CN",
		"203.0.113.10": "CN",
	})

	rec := httptest.NewRecorder()
	req := request(http.MethodGet, "go.example.com", "/", "203.0.113.10:4000")
	req.Header.Set("CF-IPCountry", "ID")
	req.Header.Set("CF-Connecting-IP", "198.51.100.9")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("cf country status = %d, want 302", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000")
	req.Header.Set("CF-IPCountry", "CN")
	req.Header.Set("CF-Connecting-IP", "198.51.100.9")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked cf country status = %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = request(http.MethodGet, "go.example.com", "/", "198.51.100.9:4000")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("geo country status = %d, want 403", rec.Code)
	}
}

func TestForwardedForTrust(t *testing.T) {
	h := testHandler(t, baseConfig, mapLookup{
		"203.0.113.50": "CN",
		"10.1.2.3":     "US",
	})

	rec := httptest.NewRecorder()
	req := request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000")
	req.Header.Set("X-Forwarded-For", "203.0.113.50")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("untrusted xff status = %d, want 302 (peer country unknown)", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = request(http.MethodGet, "go.example.com", "/", "10.1.2.3:4000")
	req.Header.Set("X-Forwarded-For", "198.51.100.1, 203.0.113.50")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("trusted xff status = %d, want 403", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = request(http.MethodGet, "go.example.com", "/", "10.1.2.3:4000")
	req.Header.Set("X-Forwarded-For", "203.0.113.50, 10.9.9.9")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("rightmost untrusted xff status = %d, want 403", rec.Code)
	}
}

func TestCloudflareUnknownFallsBackToGeo(t *testing.T) {
	h := testHandler(t, baseConfig, mapLookup{"203.0.113.50": "CN"})

	rec := httptest.NewRecorder()
	req := request(http.MethodGet, "go.example.com", "/", "198.51.100.2:4000")
	req.Header.Set("CF-IPCountry", "XX")
	req.Header.Set("CF-Connecting-IP", "203.0.113.50")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 from geo of CF-Connecting-IP", rec.Code)
	}
}

func TestDashboardOnLocalAddress(t *testing.T) {
	h := testHandler(t, baseConfig, nil)
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	for _, host := range []string{"localhost", "127.0.0.1", "203.0.113.8"} {
		rec := httptest.NewRecorder()
		req := request(http.MethodGet, host, "/", host+":4000")
		req.Header.Set("User-Agent", ua)
		req.Header.Set("CF-IPCountry", "CN")
		req.Header.Set("CF-Connecting-IP", "1.2.3.4")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want 200", host, rec.Code)
		}
		if rec.Header().Get("Location") != "" {
			t.Fatalf("%s leaked redirect to %s", host, rec.Header().Get("Location"))
		}
		body, _ := io.ReadAll(rec.Body)
		if !strings.Contains(string(body), "Masuk") || strings.Contains(string(body), "go.example.com") {
			t.Fatalf("%s login page leaked config: %s", host, body)
		}
	}
}

func TestLoginAndEdit(t *testing.T) {
	h := testHandler(t, baseConfig, nil)

	bad := postForm(t, h, "127.0.0.1", "/login", nil, url.Values{
		"username": {"kataro"},
		"password": {"salah"},
	})
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status = %d", bad.Code)
	}

	rec := postForm(t, h, "127.0.0.1", "/login", nil, url.Values{
		"username": {"kataro"},
		"password": {"@BebiiDigital2025"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("login status = %d, body %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("missing session cookie")
	}
	cookie := cookies[0]

	page := getAuth(t, h, cookie)
	if !strings.Contains(page, "go.example.com") {
		t.Fatalf("dashboard missing route: %s", page)
	}
	csrf := csrfFrom(t, page)

	rec = postForm(t, h, "127.0.0.1", "/", cookie, url.Values{
		"csrf":   {csrf},
		"action": {"add_route"},
		"host":   {"ads.example.com"},
		"target": {"https://offer.example/baru"},
	})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Pilih domain masuk") {
		t.Fatalf("route without domain status = %d, body %s", rec.Code, rec.Body.String())
	}

	page = getAuth(t, h, cookie)
	csrf = csrfFrom(t, page)
	rec = postForm(t, h, "127.0.0.1", "/", cookie, url.Values{
		"csrf":   {csrf},
		"action": {"add_domain"},
		"host":   {"ads.example.com"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("add domain status = %d, body %s", rec.Code, rec.Body.String())
	}
	page = getAuth(t, h, cookie)
	if !strings.Contains(page, `<option value="ads.example.com">`) {
		t.Fatalf("dropdown missing domain: %s", page)
	}
	csrf = csrfFrom(t, page)
	rec = postForm(t, h, "127.0.0.1", "/", cookie, url.Values{
		"csrf":   {csrf},
		"action": {"add_route"},
		"host":   {"ads.example.com"},
		"target": {"https://offer.example/baru"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("add route status = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req := request(http.MethodGet, "ads.example.com", "/?click=1", "203.0.113.9:4000")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("new route status = %d", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "https://offer.example/baru" {
		t.Fatalf("location = %q", loc)
	}

	page = getAuth(t, h, cookie)
	csrf = csrfFrom(t, page)
	rec = postForm(t, h, "127.0.0.1", "/", cookie, url.Values{
		"csrf":    {csrf},
		"action":  {"add_country"},
		"country": {"id"},
	})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("add country status = %d, body %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = request(http.MethodGet, "go.example.com", "/", "203.0.113.9:4000")
	req.Header.Set("CF-IPCountry", "ID")
	req.Header.Set("CF-Connecting-IP", "198.51.100.20")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("blocked country status = %d", rec.Code)
	}
}

func postForm(t *testing.T, h http.Handler, host, path string, c *http.Cookie, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "http://"+host+path, strings.NewReader(form.Encode()))
	req.Host = host
	req.RemoteAddr = "203.0.113.8:4000"
	req.Header.Set("User-Agent", "Mozilla/5.0 Chrome/120.0.0.0")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c != nil {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func getAuth(t *testing.T, h http.Handler, c *http.Cookie) string {
	t.Helper()
	req := request(http.MethodGet, "127.0.0.1", "/", "203.0.113.8:4000")
	req.AddCookie(c)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d", rec.Code)
	}
	return rec.Body.String()
}

func csrfFrom(t *testing.T, body string) string {
	t.Helper()
	const needle = `name="csrf" value="`
	i := strings.Index(body, needle)
	if i < 0 {
		t.Fatalf("csrf missing: %s", body)
	}
	rest := body[i+len(needle):]
	j := strings.Index(rest, `"`)
	if j <= 0 {
		t.Fatal("csrf truncated")
	}
	return rest[:j]
}

func TestClickLimit(t *testing.T) {
	h := testHandler(t, `
click_limit: true
click_limit_max: 1
routes:
  - host: go.example.com
    target: https://offer.example/landing
    blocked_target: https://safe.example/home
`, nil)
	hh := h.(*handler)
	first := httptest.NewRecorder()
	h.ServeHTTP(first, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
	if first.Code != http.StatusFound || first.Header().Get("Location") != "https://offer.example/landing" {
		t.Fatalf("first = %d %q", first.Code, first.Header().Get("Location"))
	}
	// A repeat in the same moment is still the same click.
	repeat := httptest.NewRecorder()
	h.ServeHTTP(repeat, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
	if repeat.Header().Get("Location") != "https://offer.example/landing" {
		t.Fatalf("repeat = %q", repeat.Header().Get("Location"))
	}
	ageClicks(hh, time.Minute)
	second := httptest.NewRecorder()
	h.ServeHTTP(second, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
	if second.Code != http.StatusFound || second.Header().Get("Location") != "https://safe.example/home" {
		t.Fatalf("second = %d %q", second.Code, second.Header().Get("Location"))
	}
	other := httptest.NewRecorder()
	h.ServeHTTP(other, request(http.MethodGet, "go.example.com", "/", "203.0.113.9:4000"))
	if other.Header().Get("Location") != "https://offer.example/landing" {
		t.Fatalf("other ip location = %q", other.Header().Get("Location"))
	}
}

func TestClickLimitUsesConfiguredMax(t *testing.T) {
	h := testHandler(t, `
click_limit: true
click_limit_max: 3
routes:
  - host: go.example.com
    target: https://offer.example/landing
`, nil)
	hh := h.(*handler)
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
		if rec.Header().Get("Location") != "https://offer.example/landing" {
			t.Fatalf("click %d location = %q", i+1, rec.Header().Get("Location"))
		}
		ageClicks(hh, time.Minute)
	}
	blocked := httptest.NewRecorder()
	h.ServeHTTP(blocked, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("fourth status = %d", blocked.Code)
	}
}

func TestClickLimitSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	cfg, err := config.Parse([]byte(`
click_limit: true
click_limit_max: 1
routes:
  - host: go.example.com
    target: https://offer.example/landing
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := config.Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	first := New(cfg, path, nil, nil)
	rec := httptest.NewRecorder()
	first.ServeHTTP(rec, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
	if rec.Header().Get("Location") != "https://offer.example/landing" {
		t.Fatalf("first = %q", rec.Header().Get("Location"))
	}
	restarted := New(cfg, path, nil, nil).(*handler)
	ageClicks(restarted, time.Minute)
	rec = httptest.NewRecorder()
	restarted.ServeHTTP(rec, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("after restart status = %d location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestResetClicks(t *testing.T) {
	h := testHandler(t, `
click_limit: true
click_limit_max: 1
routes:
  - host: go.example.com
    target: https://offer.example/landing
`, nil)
	hh := h.(*handler)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
	ageClicks(hh, time.Minute)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("before reset status = %d", rec.Code)
	}
	hh.clicks.reset()
	cfg, err := config.Parse([]byte(`
click_limit: true
click_limit_max: 1
routes:
  - host: go.example.com
    target: https://offer.example/landing
`))
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(cfg, hh.clicks.path, nil, nil)
	rec = httptest.NewRecorder()
	restarted.ServeHTTP(rec, request(http.MethodGet, "go.example.com", "/", "203.0.113.8:4000"))
	if rec.Header().Get("Location") != "https://offer.example/landing" {
		t.Fatalf("after reset location = %q", rec.Header().Get("Location"))
	}
}

func TestRouteClickCount(t *testing.T) {
	const yaml = `
domains:
  - go.example.com
routes:
  - host: go.example.com
    slug: satu
    params: z=[x]
    target: https://offer.example/landing
    blocked_target: https://blocked.example/no
  - host: go.example.com
    slug: dua
    target: https://offer.example/other
`
	h := testHandler(t, yaml, nil)
	hh := h.(*handler)
	h.ServeHTTP(httptest.NewRecorder(), request(http.MethodGet, "go.example.com", "/satu?z=1", "203.0.113.8:4000"))
	h.ServeHTTP(httptest.NewRecorder(), request(http.MethodGet, "go.example.com", "/satu?z=1", "203.0.113.8:4000"))
	got := hh.stats.get("go.example.com", "satu", "z=[x]")
	if got.Target != 1 || got.Blocked != 0 || got.total() != 1 {
		t.Fatalf("burst split = %+v, want target 1", got)
	}
	ageDomainClicks(hh, time.Minute)
	bot := request(http.MethodGet, "go.example.com", "/satu?z=9", "203.0.113.8:4000")
	bot.Header.Set("User-Agent", "curl/8.0")
	h.ServeHTTP(httptest.NewRecorder(), bot)
	h.ServeHTTP(httptest.NewRecorder(), request(http.MethodGet, "go.example.com", "/dua", "203.0.113.9:4000"))
	got = hh.stats.get("go.example.com", "satu", "z=[x]")
	if got.Target != 1 || got.Blocked != 1 || got.total() != 2 {
		t.Fatalf("satu split = %+v, want target 1 blocked 1", got)
	}
	if other := hh.stats.get("go.example.com", "dua", ""); other.Target != 1 || other.total() != 1 {
		t.Fatalf("dua split = %+v, want target 1", other)
	}
	page := hh.dashPage("", "")
	var satu dashRoute
	for _, row := range page.Routes {
		if row.Slug == "satu" {
			satu = row
		}
	}
	if satu.Clicks != 2 || satu.ToTarget != 1 || satu.ToBlock != 1 {
		t.Fatalf("dashboard satu = %+v", satu)
	}

	restarted := New(mustConfig(t, yaml), hh.stats.path, nil, nil)
	got = restarted.(*handler).stats.get("go.example.com", "satu", "z=[x]")
	if got.Target != 1 || got.Blocked != 1 {
		t.Fatalf("after restart split = %+v", got)
	}
}

func mustConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func ageDomainClicks(h *handler, d time.Duration) {
	h.stats.mu.Lock()
	defer h.stats.mu.Unlock()
	for key, seen := range h.stats.seen {
		h.stats.seen[key] = seen.Add(-d)
	}
}

func ageClicks(h *handler, d time.Duration) {
	h.clicks.mu.Lock()
	defer h.clicks.mu.Unlock()
	for ip, hits := range h.clicks.m {
		for i := range hits {
			hits[i] = hits[i].Add(-d)
		}
		h.clicks.m[ip] = hits
	}
}

func TestServerTimeouts(t *testing.T) {
	srv := Server(":8080", http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	if srv.ReadHeaderTimeout == 0 || srv.ReadTimeout == 0 || srv.WriteTimeout == 0 || srv.IdleTimeout == 0 {
		t.Fatal("expected server timeouts")
	}
	if srv.MaxHeaderBytes == 0 {
		t.Fatal("expected max header bytes")
	}
}
