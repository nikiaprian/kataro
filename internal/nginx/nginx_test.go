package nginx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallAndRemove(t *testing.T) {
	root := t.TempDir()
	available := filepath.Join(root, "available")
	enabled := filepath.Join(root, "enabled")
	if err := os.MkdirAll(available, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(enabled, 0o755); err != nil {
		t.Fatal(err)
	}
	var calls []string
	m := &Manager{
		Available: available,
		Enabled:   enabled,
		Upstream:  "127.0.0.1:8088",
		run: func(name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return []byte("ok"), nil
		},
		link: copyLink,
	}

	if err := m.Install("contoh.co.id", true, "admin@contoh.co.id"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(available, "contoh.co.id"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	if !strings.Contains(text, "server_name contoh.co.id;") || !strings.Contains(text, "proxy_pass http://127.0.0.1:8088;") {
		t.Fatalf("config = %s", text)
	}
	if _, err := os.Lstat(filepath.Join(enabled, "contoh.co.id")); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "nginx -t") || !strings.Contains(joined, "nginx -s reload") || !strings.Contains(joined, "certbot --nginx -d contoh.co.id") {
		t.Fatalf("calls = %s", joined)
	}
	if !strings.Contains(joined, "-m admin@contoh.co.id") {
		t.Fatalf("email missing: %s", joined)
	}

	calls = nil
	if err := m.Install("lain.co.id", false, ""); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(calls, "\n"), "certbot") {
		t.Fatal("certbot ran without ssl")
	}

	if err := os.WriteFile(filepath.Join(available, "manual.co.id"), []byte("server { }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Install("manual.co.id", false, ""); err == nil {
		t.Fatal("expected refusal to replace an unmanaged file")
	}

	if err := m.Remove("contoh.co.id"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(available, "contoh.co.id")); !os.IsNotExist(err) {
		t.Fatal("site file still exists")
	}
}

func copyLink(target, link string) error {
	return os.WriteFile(link, []byte(target), 0o644)
}

func TestHostCommandsUseNsenter(t *testing.T) {
	root := t.TempDir()
	available := filepath.Join(root, "available")
	enabled := filepath.Join(root, "enabled")
	os.MkdirAll(available, 0o755)
	os.MkdirAll(enabled, 0o755)
	var calls []string
	m := &Manager{
		Available: available,
		Enabled:   enabled,
		Upstream:  "127.0.0.1:8088",
		HostRoot:  "/host",
		run: func(name string, args ...string) ([]byte, error) {
			calls = append(calls, name+" "+strings.Join(args, " "))
			return []byte("ok"), nil
		},
		link: copyLink,
	}
	if err := m.Install("contoh.co.id", false, ""); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(calls, "\n")
	if !strings.Contains(got, "nsenter -t 1 -m -u -i -n -p -- nginx -s reload") {
		t.Fatalf("calls = %s", got)
	}
}

func TestNginxTestFailureRollsBack(t *testing.T) {
	root := t.TempDir()
	available := filepath.Join(root, "available")
	enabled := filepath.Join(root, "enabled")
	os.MkdirAll(available, 0o755)
	os.MkdirAll(enabled, 0o755)
	m := &Manager{
		Available: available,
		Enabled:   enabled,
		Upstream:  "127.0.0.1:8088",
		run: func(string, ...string) ([]byte, error) {
			return []byte("boom"), os.ErrInvalid
		},
		link: copyLink,
	}
	if err := m.Install("contoh.co.id", false, ""); err == nil {
		t.Fatal("expected nginx failure")
	}
	if _, err := os.Stat(filepath.Join(available, "contoh.co.id")); !os.IsNotExist(err) {
		t.Fatal("failed install left a site file")
	}
}
