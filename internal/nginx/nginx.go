package nginx

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const marker = "managed-by-gate"

// Manager writes host nginx site files and can request a Let's Encrypt certificate.
type Manager struct {
	Available string
	Enabled   string
	Upstream  string
	HostRoot  string
	run       func(name string, args ...string) ([]byte, error)
	link      func(target, link string) error
}

// FromEnv configures nginx integration from the environment.
// It stays inactive when NGINX_SITES_AVAILABLE or NGINX_SITES_ENABLED is empty.
func FromEnv() *Manager {
	available := strings.TrimSpace(os.Getenv("NGINX_SITES_AVAILABLE"))
	enabled := strings.TrimSpace(os.Getenv("NGINX_SITES_ENABLED"))
	if available == "" || enabled == "" {
		return &Manager{}
	}
	upstream := strings.TrimSpace(os.Getenv("NGINX_UPSTREAM"))
	if upstream == "" {
		upstream = "127.0.0.1:8088"
	}
	return &Manager{
		Available: available,
		Enabled:   enabled,
		Upstream:  upstream,
		HostRoot:  strings.TrimSpace(os.Getenv("NGINX_HOST_ROOT")),
		run:       defaultRun,
	}
}

// Active reports whether site files can be written.
func (m *Manager) Active() bool {
	return m != nil && m.Available != "" && m.Enabled != ""
}

// Install writes and enables a site, reloads nginx, and optionally requests SSL.
func (m *Manager) Install(domain string, ssl bool, email string) error {
	name, err := fileName(domain)
	if err != nil {
		return err
	}
	if err := validateEmail(email); err != nil {
		return err
	}
	path := m.Available + "/" + name
	if existing, readErr := os.ReadFile(path); readErr == nil && !bytes.Contains(existing, []byte(marker)) {
		return fmt.Errorf("file nginx %s sudah ada dan bukan buatan dashboard", name)
	}
	body := []byte(siteConfig(domain, m.Upstream))
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return fmt.Errorf("gagal menulis konfigurasi nginx: %w", err)
	}
	if err := m.enable(name); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := m.nginxTest(); err != nil {
		m.disable(name)
		_ = os.Remove(path)
		return err
	}
	if err := m.nginxReload(); err != nil {
		return err
	}
	if !ssl {
		return nil
	}
	if err := m.certbot(domain, email); err != nil {
		return fmt.Errorf("konfigurasi nginx sudah dipasang, SSL gagal: %s", err.Error())
	}
	return nil
}

// Remove deletes a site created by the dashboard and reloads nginx.
func (m *Manager) Remove(domain string) error {
	name, err := fileName(domain)
	if err != nil {
		return err
	}
	path := m.Available + "/" + name
	existing, readErr := os.ReadFile(path)
	if readErr != nil && !os.IsNotExist(readErr) {
		return fmt.Errorf("gagal membaca konfigurasi nginx: %w", readErr)
	}
	if readErr == nil && !bytes.Contains(existing, []byte(marker)) {
		return fmt.Errorf("file nginx %s tidak dihapus karena bukan buatan dashboard", name)
	}
	m.disable(name)
	if readErr == nil {
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("gagal menghapus konfigurasi nginx: %w", err)
		}
	}
	if err := m.nginxTest(); err != nil {
		if readErr == nil {
			_ = os.WriteFile(path, existing, 0o644)
			_ = m.enable(name)
		}
		return err
	}
	return m.nginxReload()
}

func (m *Manager) enable(name string) error {
	link := m.Enabled + "/" + name
	_ = os.Remove(link)
	target := m.Available + "/" + name
	if m.HostRoot != "" && strings.HasPrefix(m.Available, m.HostRoot) {
		target = strings.TrimPrefix(m.Available, m.HostRoot) + "/" + name
	}
	linkFn := m.link
	if linkFn == nil {
		linkFn = os.Symlink
	}
	if err := linkFn(target, link); err != nil {
		return fmt.Errorf("gagal mengaktifkan situs nginx: %w", err)
	}
	return nil
}

func (m *Manager) disable(name string) {
	_ = os.Remove(m.Enabled + "/" + name)
}

func (m *Manager) nginxTest() error {
	out, err := m.exec("nginx", "-t")
	if err != nil {
		return fmt.Errorf("nginx -t gagal: %s", clip(out))
	}
	return nil
}

func (m *Manager) nginxReload() error {
	out, err := m.exec("nginx", "-s", "reload")
	if err != nil {
		return fmt.Errorf("gagal memuat ulang nginx: %s", clip(out))
	}
	return nil
}

func (m *Manager) certbot(domain, email string) error {
	args := []string{
		"--nginx",
		"-d", domain,
		"--non-interactive",
		"--agree-tos",
		"--keep-until-expiring",
		"--redirect",
	}
	if email == "" {
		args = append(args, "--register-unsafely-without-email")
	} else {
		args = append(args, "-m", email)
	}
	out, err := m.exec("certbot", args...)
	if err != nil {
		return fmt.Errorf("%s", clip(out))
	}
	return nil
}

func (m *Manager) exec(bin string, args ...string) ([]byte, error) {
	run := m.run
	if run == nil {
		run = defaultRun
	}
	if m.HostRoot != "" {
		// Enter the host namespaces. nginx -s reload must signal the host
		// master process; doing that from the container returns permission denied.
		args = append([]string{"-t", "1", "-m", "-u", "-i", "-n", "-p", "--", bin}, args...)
		bin = "nsenter"
	}
	return run(bin, args...)
}

func defaultRun(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.CombinedOutput()
}

func siteConfig(domain, upstream string) string {
	return "# " + marker + "\n" +
		"server {\n" +
		"    listen 80;\n" +
		"    server_name " + domain + ";\n" +
		"\n" +
		"    location / {\n" +
		"        proxy_pass http://" + upstream + ";\n" +
		"        proxy_set_header Host $host;\n" +
		"        proxy_set_header X-Forwarded-For $remote_addr;\n" +
		"        proxy_set_header X-Forwarded-Proto $scheme;\n" +
		"    }\n" +
		"}\n"
}

func fileName(host string) (string, error) {
	if host == "" || strings.Contains(host, "..") {
		return "", fmt.Errorf("nama domain tidak aman")
	}
	for _, c := range host {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '.' && c != '-' {
			return "", fmt.Errorf("nama domain tidak aman")
		}
	}
	return host, nil
}

func validateEmail(email string) error {
	if email == "" {
		return nil
	}
	if !strings.Contains(email, "@") || strings.ContainsAny(email, " \t\r\n") {
		return fmt.Errorf("email SSL tidak valid")
	}
	return nil
}

func clip(out []byte) string {
	text := strings.TrimSpace(string(out))
	if text == "" {
		return "perintah gagal"
	}
	if len(text) > 400 {
		return text[:400]
	}
	return text
}
