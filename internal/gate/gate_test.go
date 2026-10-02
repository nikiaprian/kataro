package gate

import (
	"net/http"
	"testing"

	"keitaro/internal/config"
)

func testGate(t *testing.T, yaml string) *Gate {
	t.Helper()
	cfg, err := config.Parse([]byte(yaml))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return New(cfg)
}

func TestDecide(t *testing.T) {
	g := testGate(t, `
blocked_countries: ["CN", "ru"]
bot:
  block_empty_user_agent: true
  user_agent_contains: ["my-scanner"]
routes:
  - host: go.example.com
    target: https://offer.example/landing
  - host: "Ads.Example.com:443"
    target: "https://offer.example/other?src=1"
`)

	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	tests := []struct {
		name     string
		in       Input
		status   int
		location string
	}{
		{
			name:   "empty user agent",
			in:     Input{Host: "go.example.com", Country: "US"},
			status: http.StatusForbidden,
		},
		{
			name:   "known bot fragment",
			in:     Input{Host: "go.example.com", UserAgent: "curl/8.0", Country: "US"},
			status: http.StatusForbidden,
		},
		{
			name:   "headless browser",
			in:     Input{Host: "go.example.com", UserAgent: "Mozilla/5.0 HeadlessChrome", Country: "US"},
			status: http.StatusForbidden,
		},
		{
			name:   "extra fragment",
			in:     Input{Host: "go.example.com", UserAgent: "My-Scanner/1.0", Country: "US"},
			status: http.StatusForbidden,
		},
		{
			name:   "blocked country",
			in:     Input{Host: "go.example.com", UserAgent: chrome, Country: "cn"},
			status: http.StatusForbidden,
		},
		{
			name:     "unknown country allowed",
			in:       Input{Host: "go.example.com", UserAgent: chrome, Country: ""},
			status:   http.StatusFound,
			location: "https://offer.example/landing",
		},
		{
			name:   "unknown host",
			in:     Input{Host: "other.example", UserAgent: chrome, Country: "US"},
			status: http.StatusNotFound,
		},
		{
			name:     "visitor query is not added to target",
			in:       Input{Host: "go.example.com", UserAgent: chrome, Country: "ID", RawQuery: "click=1&sub=a"},
			status:   http.StatusFound,
			location: "https://offer.example/landing",
		},
		{
			name:     "host case and port",
			in:       Input{Host: "ADS.EXAMPLE.COM:443", UserAgent: chrome, Country: "ID", RawQuery: "x=2"},
			status:   http.StatusFound,
			location: "https://offer.example/other?src=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := g.Decide(tt.in)
			if got.Status != tt.status {
				t.Fatalf("status = %d, want %d", got.Status, tt.status)
			}
			if got.Location != tt.location {
				t.Fatalf("location = %q, want %q", got.Location, tt.location)
			}
		})
	}
}

func TestSlugAndParams(t *testing.T) {
	g := testGate(t, `
routes:
  - host: go.example.com
    target: https://domain.com
    slug: asdfg
    params: "zxc=[qwerty]"
`)
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	filled := g.Decide(Input{
		Host: "go.example.com", Path: "/asdfg", UserAgent: chrome, Country: "ID", RawQuery: "zxc=abc",
	})
	if filled.Status != http.StatusFound || filled.Location != "https://domain.com" {
		t.Fatalf("filled = %d %q", filled.Status, filled.Location)
	}

	wrongPath := g.Decide(Input{
		Host: "go.example.com", Path: "/", UserAgent: chrome, Country: "ID", RawQuery: "zxc=abc",
	})
	if wrongPath.Status != http.StatusNotFound {
		t.Fatalf("wrong path status = %d", wrongPath.Status)
	}

	missing := g.Decide(Input{
		Host: "go.example.com", Path: "/asdfg", UserAgent: chrome, Country: "ID",
	})
	if missing.Status != http.StatusNotFound {
		t.Fatalf("missing param status = %d", missing.Status)
	}
}

func TestBlockedRedirect(t *testing.T) {
	g := testGate(t, `
blocked_countries: ["CN"]
routes:
  - host: go.example.com
    target: https://offer.example/landing
    blocked_target: https://safe.example/home
`)
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	country := g.Decide(Input{Host: "go.example.com", UserAgent: chrome, Country: "CN"})
	if country.Status != http.StatusFound || country.Location != "https://safe.example/home" {
		t.Fatalf("country = %d %q", country.Status, country.Location)
	}

	bot := g.Decide(Input{Host: "go.example.com", UserAgent: "curl/8.0", Country: "ID"})
	if bot.Status != http.StatusFound || bot.Location != "https://safe.example/home" {
		t.Fatalf("bot = %d %q", bot.Status, bot.Location)
	}

	allowed := g.Decide(Input{Host: "go.example.com", UserAgent: chrome, Country: "ID"})
	if allowed.Status != http.StatusFound || allowed.Location != "https://offer.example/landing" {
		t.Fatalf("allowed = %d %q", allowed.Status, allowed.Location)
	}
}

func TestSameHostDifferentSlug(t *testing.T) {
	g := testGate(t, `
routes:
  - host: go.example.com
    target: https://offer.example/satu
    slug: slekv
    params: "trshdah=[guts]"
  - host: go.example.com
    target: https://offer.example/dua
    slug: lain
    params: "a=[b]"
`)
	chrome := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	first := g.Decide(Input{Host: "go.example.com", Path: "/slekv", UserAgent: chrome, Country: "ID", RawQuery: "trshdah=abc"})
	if first.Status != http.StatusFound || first.Location != "https://offer.example/satu" {
		t.Fatalf("first = %d %q", first.Status, first.Location)
	}
	second := g.Decide(Input{Host: "go.example.com", Path: "/lain", UserAgent: chrome, Country: "ID", RawQuery: "a=1"})
	if second.Status != http.StatusFound || second.Location != "https://offer.example/dua" {
		t.Fatalf("second = %d %q", second.Status, second.Location)
	}
}

func TestEmptyUserAgentAllowed(t *testing.T) {
	g := testGate(t, `
bot:
  block_empty_user_agent: false
routes:
  - host: go.example.com
    target: https://offer.example/landing
`)
	got := g.Decide(Input{Host: "go.example.com", Country: "US"})
	if got.Status != http.StatusFound {
		t.Fatalf("status = %d, want %d", got.Status, http.StatusFound)
	}
	if got.Location != "https://offer.example/landing" {
		t.Fatalf("location = %q", got.Location)
	}
}
