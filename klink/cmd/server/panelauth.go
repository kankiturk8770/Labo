package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// panelUser is the fixed admin username; the password is generated/stored.
const panelUser = "admin"

// userKeySlice makes a [32]byte key sliceable for hex encoding inline.
func userKeySlice(k [32]byte) []byte { return k[:] }

// resolveServerSecret returns KLINK_SECRET, or a persisted random secret
// generated on first run — never a hardcoded fallback key.
func resolveServerSecret() string {
	if s := strings.TrimSpace(os.Getenv("KLINK_SECRET")); s != "" {
		return s
	}
	dir := panelCertDir()
	file := filepath.Join(dir, "secret.key")
	if b, err := os.ReadFile(file); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	buf := make([]byte, 32)
	_, _ = rand.Read(buf)
	s := hex.EncodeToString(buf)
	_ = os.MkdirAll(dir, 0o755)
	if err := os.WriteFile(file, []byte(s+"\n"), 0o600); err != nil {
		log.Printf("[KLINK] WARNING: could not persist generated secret: %v", err)
	} else {
		log.Printf("[KLINK] no KLINK_SECRET set; generated and stored a random secret at %s", file)
	}
	return s
}

// resolvePanelPassword returns the panel admin password: KLINK_PANEL_PASSWORD
// if set, else a persisted random password (generated on first run).
func resolvePanelPassword(dir string) string {
	if p := strings.TrimSpace(os.Getenv("KLINK_PANEL_PASSWORD")); p != "" {
		return p
	}
	file := filepath.Join(dir, "panel-password.txt")
	if b, err := os.ReadFile(file); err == nil {
		if p := strings.TrimSpace(string(b)); p != "" {
			return p
		}
	}
	buf := make([]byte, 18)
	_, _ = rand.Read(buf)
	p := hex.EncodeToString(buf)
	if err := os.WriteFile(file, []byte(p+"\n"), 0o600); err != nil {
		log.Printf("[KLINK-PANEL] WARNING: could not persist admin password: %v", err)
	} else {
		log.Printf("[KLINK-PANEL] admin password generated (user %q), stored at %s", panelUser, file)
	}
	return p
}

// requirePanelAuth wraps the panel with HTTP Basic auth. Subscription links
// (/sub/<token>) stay public because clients fetch them unauthenticated; every
// other route — the UI and all /api/* control endpoints — requires the admin
// credentials.
func requirePanelAuth(next http.Handler, password string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/sub/") {
			next.ServeHTTP(w, r)
			return
		}
		user, pass, ok := r.BasicAuth()
		userOK := subtle.ConstantTimeCompare([]byte(user), []byte(panelUser)) == 1
		passOK := subtle.ConstantTimeCompare([]byte(pass), []byte(password)) == 1
		if !ok || !userOK || !passOK {
			w.Header().Set("WWW-Authenticate", `Basic realm="KLINK Panel"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
