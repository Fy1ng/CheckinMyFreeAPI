package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// LocalMode reports a startup policy, not a mode stored in migrated auth tables.
func (s *Service) LocalMode() bool { return s.opts.LocalMode }

// LocalAccess deliberately does not trust PrivateRecovery or configured proxies.
// Only direct connections from a loopback peer can use the local UI, and an
// attacker cannot turn a forwarded/public request into one by changing Host.
func (s *Service) LocalAccess(r *http.Request) bool {
	if !s.opts.LocalMode || !peerIP(r).IsLoopback() {
		return false
	}
	origin, err := s.Origin(r)
	if err != nil {
		return false
	}
	u, err := url.Parse(origin)
	if err != nil || !loopbackName(u.Hostname()) {
		return false
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") {
			return false
		}
	}
	origins := r.Header.Values("Origin")
	if len(origins) > 1 || (len(origins) == 1 && origins[0] != origin) {
		return false
	}
	if strings.HasPrefix(r.URL.Path, "/api/") || strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		site := r.Header.Get("Sec-Fetch-Site")
		if site != "" && site != "none" && site != "same-origin" {
			return false
		}
	}
	return true
}

func localIdentityPath(path string) bool {
	return path == "/api/login" || path == "/api/logout" || path == "/api/security" || strings.HasPrefix(path, "/api/security/") || strings.HasPrefix(path, "/api/passkey/")
}

func localCapabilities() map[string]any {
	return map[string]any{
		"auth_mode": "local", "local_mode": true, "reauth_method": "none",
		"password_login_allowed": false, "passkey_available": false, "passkey_origin_allowed": false,
	}
}

func (s *Service) localSession(r *http.Request, origin string) *Session {
	if !s.LocalAccess(r) {
		return nil
	}
	policy, err := readPolicy(s.db)
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mac := hmac.New(sha256.New, s.localToken)
	_, _ = mac.Write([]byte("checkin-local-csrf-v1\x00" + origin + "\x00" + strconv.FormatInt(policy.Revision, 10)))
	return &Session{CSRF: base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), Origin: origin, Method: "local", Revision: policy.Revision, Expires: time.Now().Add(8 * time.Hour)}
}
