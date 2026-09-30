package server

import (
	"html/template"
	"net/http"
	"sort"
)

type dashRoute struct {
	Host   string
	Target string
}

type dashPage struct {
	Routes    []dashRoute
	Countries []string
	CSRF      string
	Error     string
}

var dashTmpl = template.Must(template.New("dashboard").Parse(`<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Dashboard</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; line-height: 1.45; max-width: 46rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 0.45rem 0.6rem 0.45rem 0; border-bottom: 1px solid #ddd; vertical-align: middle; }
  code, input { font-family: ui-monospace, monospace; }
  input { padding: 0.35rem 0.5rem; margin: 0 0.4rem 0.4rem 0; }
  button { padding: 0.35rem 0.7rem; }
  form.inline { display: inline; }
  .error { color: #9b1c1c; }
  .top { display: flex; justify-content: space-between; align-items: center; }
</style>
</head>
<body>
<div class="top">
  <h1>Dashboard</h1>
  <form method="post" action="/logout">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <button type="submit">Keluar</button>
  </form>
</div>
<p>Domain yang DNS-nya mengarah ke server ini akan diarahkan ke tujuan di bawah. Perubahan langsung tersimpan.</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}

<h2>Domain</h2>
{{if .Routes}}
<table>
<thead><tr><th>Domain masuk</th><th>Tujuan</th><th></th></tr></thead>
<tbody>
{{range .Routes}}
<tr>
  <td><code>{{.Host}}</code></td>
  <td><code>{{.Target}}</code></td>
  <td>
    <form class="inline" method="post" action="/">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="action" value="delete_route">
      <input type="hidden" name="host" value="{{.Host}}">
      <button type="submit">Hapus</button>
    </form>
  </td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>Belum ada domain.</p>
{{end}}
<form method="post" action="/">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="add_route">
  <input name="host" placeholder="domain-masuk.com" required>
  <input name="target" placeholder="https://tujuan.com/halaman" required>
  <button type="submit">Simpan domain</button>
</form>

<h2>Negara diblokir</h2>
{{if .Countries}}
<table>
<tbody>
{{range .Countries}}
<tr>
  <td><code>{{.}}</code></td>
  <td>
    <form class="inline" method="post" action="/">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="action" value="delete_country">
      <input type="hidden" name="country" value="{{.}}">
      <button type="submit">Hapus</button>
    </form>
  </td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>Tidak ada.</p>
{{end}}
<form method="post" action="/">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="add_country">
  <input name="country" placeholder="ID" maxlength="2" required>
  <button type="submit">Blokir negara</button>
</form>
</body>
</html>
`))

var loginTmpl = template.Must(template.New("login").Parse(`<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Masuk</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; line-height: 1.45; }
  label { display: block; margin-top: 0.8rem; }
  input { display: block; margin-top: 0.25rem; padding: 0.35rem 0.5rem; }
  button { margin-top: 1rem; padding: 0.4rem 0.8rem; }
  .error { color: #9b1c1c; }
</style>
</head>
<body>
<h1>Masuk</h1>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<form method="post" action="/login">
  <label>Nama<input name="username" autocomplete="username" required></label>
  <label>Kata sandi<input type="password" name="password" autocomplete="current-password" required></label>
  <button type="submit">Masuk</button>
</form>
</body>
</html>
`))

func (h *handler) writeDashboard(w http.ResponseWriter, csrf, errMsg string) {
	page := h.dashPage(csrf, errMsg)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = dashTmpl.Execute(w, page)
}

func (h *handler) dashPage(csrf, errMsg string) dashPage {
	h.mu.Lock()
	defer h.mu.Unlock()
	page := dashPage{CSRF: csrf, Error: errMsg, Countries: blockedList(h.cfg.Blocked)}
	for _, route := range h.cfg.Routes {
		page.Routes = append(page.Routes, dashRoute{Host: route.Host, Target: route.Target.String()})
	}
	return page
}

func writeLogin(w http.ResponseWriter, status int, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = loginTmpl.Execute(w, struct{ Error string }{Error: errMsg})
}

func blockedList(blocked map[string]struct{}) []string {
	out := make([]string, 0, len(blocked))
	for code := range blocked {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}
