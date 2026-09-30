package config

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseExample(t *testing.T) {
	cfg, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if cfg.GeoIPDB != "GeoLite2-Country.mmdb" {
		t.Fatalf("geoip = %q", cfg.GeoIPDB)
	}
	if !cfg.BlockEmptyUA {
		t.Fatal("expected empty user agent to be blocked")
	}
	if _, ok := cfg.Blocked["CN"]; !ok {
		t.Fatal("missing CN")
	}
	if _, ok := cfg.Blocked["RU"]; !ok {
		t.Fatal("missing RU")
	}
	if len(cfg.Routes) != 1 || cfg.Routes[0].Host != "go.example.com" {
		t.Fatalf("routes = %+v", cfg.Routes)
	}
	if cfg.Routes[0].Target.String() != "https://offer.example/landing" {
		t.Fatalf("target = %s", cfg.Routes[0].Target)
	}
}

func TestParseDefaultsAndRejects(t *testing.T) {
	cfg, err := Parse([]byte(`
routes:
  - host: Go.Example.com.
    target: https://offer.example/a
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != ":8080" {
		t.Fatalf("listen = %q", cfg.Listen)
	}
	if !cfg.BlockEmptyUA {
		t.Fatal("empty user agent should be blocked by default")
	}
	if cfg.Routes[0].Host != "go.example.com" {
		t.Fatalf("host = %q", cfg.Routes[0].Host)
	}

	empty, err := Parse([]byte("routes: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Routes) != 0 {
		t.Fatalf("routes = %d, want 0", len(empty.Routes))
	}

	cases := []string{
		"routes:\n  - host: a.example\n    target: javascript:alert(1)",
		"routes:\n  - host: a.example\n    target: https://user:pass@offer.example/",
		"routes:\n  - host: a.example\n    target: https://offer.example/\n  - host: A.Example\n    target: https://offer.example/b",
		"blocked_countries: [\"USA\"]\nroutes:\n  - host: a.example\n    target: https://offer.example/",
		"trusted_proxies: [\"not-a-cidr\"]\nroutes:\n  - host: a.example\n    target: https://offer.example/",
		"routes:\n  - host: \"\"\n    target: https://offer.example/",
	}
	for _, raw := range cases {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatalf("expected error for:\n%s", raw)
		}
	}
}

func TestNormalizeHost(t *testing.T) {
	got, err := NormalizeHost("Go.Example.COM:8443")
	if err != nil {
		t.Fatal(err)
	}
	if got != "go.example.com" {
		t.Fatalf("got %q", got)
	}
	if _, err := NormalizeHost("   "); err == nil {
		t.Fatal("expected empty host error")
	}
	if strings.Contains(got, ":") {
		t.Fatal("port leaked")
	}
}

func TestSaveRoundTrip(t *testing.T) {
	cfg, err := Parse([]byte(`
listen: ":8080"
geoip_db: ""
trusted_proxies: ["127.0.0.1/32"]
blocked_countries: ["CN"]
routes:
  - host: go.example.com
    target: https://offer.example/landing
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Domains) != 1 || cfg.Domains[0] != "go.example.com" {
		t.Fatalf("domains = %+v", cfg.Domains)
	}
	cfg, err = AddDomain(cfg, "Ads.Example.com")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = UpsertRoute(cfg, "Ads.Example.com", "https://offer.example/baru", "asdfg", "zxc=[qwerty]")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = AddCountry(cfg, "id")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Routes) != 2 || loaded.Routes[1].Host != "ads.example.com" {
		t.Fatalf("routes = %+v", loaded.Routes)
	}
	if loaded.Routes[1].Target.String() != "https://offer.example/baru" {
		t.Fatalf("target = %s", loaded.Routes[1].Target)
	}
	if loaded.Routes[1].Slug != "asdfg" || loaded.Routes[1].Params != "zxc=[qwerty]" {
		t.Fatalf("slug/params = %q %q", loaded.Routes[1].Slug, loaded.Routes[1].Params)
	}
	if _, ok := loaded.Blocked["ID"]; !ok {
		t.Fatalf("blocked = %+v", loaded.Blocked)
	}
	if len(loaded.TrustedRaw) != 1 || loaded.TrustedRaw[0] != "127.0.0.1/32" {
		t.Fatalf("proxies = %+v", loaded.TrustedRaw)
	}
}
