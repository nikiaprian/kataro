package server

import (
	"net/http"

	"keitaro/internal/config"
	"keitaro/internal/gate"
)

func (h *handler) serveDashboard(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/login":
		h.login(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/logout":
		h.logout(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/":
		h.update(w, r)
	case r.Method == http.MethodGet && (r.URL.Path == "/" || r.URL.Path == "/login"):
		if sess, ok := h.currentSession(r); ok && r.URL.Path == "/" {
			h.writeDashboard(w, sess.csrf, "")
			return
		}
		if _, ok := h.currentSession(r); ok {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		writeLogin(w, http.StatusOK, "")
	default:
		http.NotFound(w, r)
	}
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	if err := readForm(w, r); err != nil {
		writeLogin(w, http.StatusBadRequest, "Permintaan tidak valid.")
		return
	}
	user := r.PostForm.Get("username")
	pass := r.PostForm.Get("password")
	if !sameText(user, adminUser) || !sameText(pass, adminPass) {
		writeLogin(w, http.StatusUnauthorized, "Nama atau kata sandi salah.")
		return
	}
	token, _, err := h.sessions.create()
	if err != nil {
		writeLogin(w, http.StatusInternalServerError, "Gagal membuat sesi.")
		return
	}
	setSessionCookie(w, token)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.currentSession(r)
	if !ok {
		writeLogin(w, http.StatusOK, "")
		return
	}
	if err := readForm(w, r); err != nil || !sameText(r.PostForm.Get("csrf"), sess.csrf) {
		http.Error(w, "sesi tidak valid", http.StatusForbidden)
		return
	}
	h.sessions.drop(sessionToken(r))
	clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handler) update(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.currentSession(r)
	if !ok {
		writeLogin(w, http.StatusOK, "")
		return
	}
	if err := readForm(w, r); err != nil || !sameText(r.PostForm.Get("csrf"), sess.csrf) {
		http.Error(w, "sesi tidak valid", http.StatusForbidden)
		return
	}

	action := r.PostForm.Get("action")
	var err error
	switch action {
	case "add_route":
		err = h.addRoute(r.PostForm.Get("host"), r.PostForm.Get("target"))
	case "delete_route":
		err = h.apply(func(cfg *config.Config) (*config.Config, error) {
			return config.RemoveRoute(cfg, r.PostForm.Get("host"))
		})
	case "add_country":
		err = h.apply(func(cfg *config.Config) (*config.Config, error) {
			return config.AddCountry(cfg, r.PostForm.Get("country"))
		})
	case "delete_country":
		err = h.apply(func(cfg *config.Config) (*config.Config, error) {
			return config.RemoveCountry(cfg, r.PostForm.Get("country"))
		})
	default:
		h.writeDashboard(w, sess.csrf, "Perubahan tidak dikenali.")
		return
	}
	if err != nil {
		h.writeDashboard(w, sess.csrf, actionError(action, err))
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (h *handler) addRoute(host, target string) error {
	normalized, err := config.NormalizeHost(host)
	if err != nil || isDashboardHost(normalized) {
		return errInvalid
	}
	return h.apply(func(cfg *config.Config) (*config.Config, error) {
		return config.UpsertRoute(cfg, host, target)
	})
}

func (h *handler) apply(fn func(*config.Config) (*config.Config, error)) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	next, err := fn(h.cfg)
	if err != nil {
		return err
	}
	if err := config.Save(h.path, next); err != nil {
		return errSave
	}
	h.cfg = next
	h.gate = gate.New(next)
	return nil
}

func actionError(action string, err error) string {
	if err == nil {
		return ""
	}
	if err == errSave {
		return "Gagal menyimpan konfigurasi."
	}
	switch action {
	case "add_country", "delete_country":
		return "Kode negara harus dua huruf, misalnya ID."
	default:
		return "Domain masuk atau URL tujuan tidak valid. Gunakan nama domain, bukan IP atau localhost."
	}
}

func (h *handler) currentSession(r *http.Request) (session, bool) {
	return h.sessions.lookup(sessionToken(r))
}

func readForm(w http.ResponseWriter, r *http.Request) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	return r.ParseForm()
}

var (
	errInvalid = errString("invalid")
	errSave    = errString("save")
)

type errString string

func (e errString) Error() string { return string(e) }
