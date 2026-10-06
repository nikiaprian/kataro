package server

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"sync"
	"time"
)

const (
	adminUser = "kataro"
	adminPass = "@BebiiDigital2025"

	sessionCookie = "gate_session"
	sessionTTL    = 24 * time.Hour
)

type session struct {
	csrf string
	exp  time.Time
}

type sessions struct {
	mu sync.Mutex
	m  map[string]session
}

func newSessions() *sessions {
	return &sessions{m: make(map[string]session)}
}

func (s *sessions) create() (token, csrf string, err error) {
	token, err = randomToken()
	if err != nil {
		return "", "", err
	}
	csrf, err = randomToken()
	if err != nil {
		return "", "", err
	}
	s.mu.Lock()
	s.m[token] = session{csrf: csrf, exp: time.Now().Add(sessionTTL)}
	s.mu.Unlock()
	return token, csrf, nil
}

func (s *sessions) lookup(token string) (session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.m[token]
	if !ok {
		return session{}, false
	}
	if time.Now().After(sess.exp) {
		delete(s.m, token)
		return session{}, false
	}
	return sess, true
}

func (s *sessions) drop(token string) {
	s.mu.Lock()
	delete(s.m, token)
	s.mu.Unlock()
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func sameText(got, want string) bool {
	if len(got) != len(want) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func sessionToken(r *http.Request) string {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return c.Value
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}
