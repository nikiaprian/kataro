package server

import (
	"html/template"
	"net/http"
	"sort"
)

type dashRoute struct {
	Host     string
	Incoming string
	Target   string
	Blocked  string
}

type dashPage struct {
	Domains   []string
	Routes    []dashRoute
	Countries []string
	SSLEmail  string
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
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; line-height: 1.45; max-width: 64rem; }
  table { border-collapse: collapse; width: 100%; }
  th, td { text-align: left; padding: 0.45rem 0.6rem 0.45rem 0; border-bottom: 1px solid #ddd; vertical-align: middle; }
  code, input, select { font-family: ui-monospace, monospace; }
  input, select { padding: 0.35rem 0.5rem; margin: 0 0.4rem 0.4rem 0; }
  button { padding: 0.35rem 0.7rem; }
  form.inline { display: inline; }
  label.check { margin-right: 0.6rem; }
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
<p>Domain yang DNS-nya mengarah ke server ini akan diarahkan ke tujuan di bawah.</p>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}

<h2>Domain masuk</h2>
{{if .Domains}}
<table>
<tbody>
{{range .Domains}}
<tr>
  <td><code>{{.}}</code></td>
  <td>
    <form class="inline" method="post" action="/">
      <input type="hidden" name="csrf" value="{{$.CSRF}}">
      <input type="hidden" name="action" value="delete_domain">
      <input type="hidden" name="host" value="{{.}}">
      <button type="submit">Hapus</button>
    </form>
  </td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p>Belum ada domain masuk.</p>
{{end}}
<form method="post" action="/">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="add_domain">
  <input name="host" placeholder="domain-masuk.com" required>
  <label class="check"><input type="checkbox" name="ssl" value="1"> Pasang SSL</label>
  <input name="ssl_email" type="email" placeholder="email untuk sertifikat" value="{{.SSLEmail}}">
  <button type="submit">Tambah domain</button>
</form>

<h2>Redirect</h2>
{{if .Routes}}
<table>
<thead><tr><th>Domain masuk</th><th>Tujuan</th><th>Tujuan diblokir</th><th></th></tr></thead>
<tbody>
{{range .Routes}}
<tr>
  <td><code>{{.Incoming}}</code></td>
  <td><code>{{.Target}}</code></td>
  <td><code>{{.Blocked}}</code></td>
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
<p>Belum ada redirect.</p>
{{end}}
{{if .Domains}}
<form method="post" action="/">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="hidden" name="action" value="add_route">
  <select name="host" required>
    <option value="">Pilih domain masuk</option>
    {{range .Domains}}<option value="{{.}}">{{.}}</option>{{end}}
  </select>
  <input name="slug" placeholder="slug domain masuk, contoh asdfg">
  <input name="params" placeholder="param domain masuk, contoh zxc=[qwerty]">
  <input name="target" placeholder="https://tujuan.com" required>
  <input name="blocked_target" placeholder="https://tujuan-diblokir.com">
  <button type="submit">Simpan redirect</button>
</form>
<p>Slug dan parameter adalah bagian URL domain masuk, misalnya <code>domain-masuk.com/asdfg?zxc=[qwerty]</code>. Tanda <code>[qwerty]</code> cocok dengan nilai apa pun. Kunjungan yang lolos diarahkan ke URL tujuan. Bot dan negara yang diblokir diarahkan ke tujuan diblokir; jika kosong, permintaan ditolak.</p>
{{else}}
<p>Tambahkan domain masuk terlebih dahulu.</p>
{{end}}

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
	page := dashPage{
		CSRF:      csrf,
		Error:     errMsg,
		Countries: blockedList(h.cfg.Blocked),
		Domains:   append([]string(nil), h.cfg.Domains...),
		SSLEmail:  h.cfg.SSLEmail,
	}
	for _, route := range h.cfg.Routes {
		row := dashRoute{
			Host:     route.Host,
			Incoming: route.Incoming(),
			Target:   route.Target.String(),
		}
		if route.BlockedTarget != nil {
			row.Blocked = route.BlockedTarget.String()
		}
		page.Routes = append(page.Routes, row)
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
