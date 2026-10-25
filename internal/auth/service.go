// Package auth preserves the existing WebUI security contract across runtimes.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

const ceremonyTTL = 180 * time.Second
const sessionCookie = "checkin_web_session"

type HTTPError struct {
	Status  int
	Message string
}

func (e *HTTPError) Error() string             { return e.Message }
func failure(status int, message string) error { return &HTTPError{status, message} }

type Options struct {
	Password        string
	PublicOrigin    string
	TrustedProxyIPs []string
	Maintenance     func() bool
	SecurityBusy    func() bool
}

type Session struct {
	CSRF, Origin, Method, CredentialID string
	Expires                            time.Time
	Revision                           int64
}

type Proof struct {
	Method       string
	CredentialID string
}
type proofRecord struct {
	Proof
	Origin, Binding string
	Revision        int64
	Expires         time.Time
}

type Service struct {
	db               *sql.DB
	Access           *Access
	opts             Options
	mu               sync.Mutex
	securityMu       sync.Mutex
	sessions         map[string]Session
	pending          map[string]ceremony
	proofs           map[string]proofRecord
	passwordAttempts map[string][]time.Time
	passkeyAttempts  map[string][]time.Time
	passwordBusy     chan struct{}
	salt, digest     []byte
}

func New(db *sql.DB, opts Options) (*Service, error) {
	a, err := NewAccess(opts.PublicOrigin, opts.TrustedProxyIPs)
	if err != nil {
		return nil, err
	}
	if err = initialize(db, opts.Password); err != nil {
		return nil, err
	}
	if _, err = readPolicy(db); err != nil {
		return nil, err
	}
	opts.Password = ""
	s := &Service{db: db, Access: a, opts: opts, sessions: map[string]Session{}, pending: map[string]ceremony{}, proofs: map[string]proofRecord{}, passwordAttempts: map[string][]time.Time{}, passkeyAttempts: map[string][]time.Time{}, passwordBusy: make(chan struct{}, 1)}
	if err = db.QueryRow("SELECT salt,digest FROM web_auth WHERE id=1").Scan(&s.salt, &s.digest); err != nil {
		return nil, err
	}
	if len(s.salt) != 16 || len(s.digest) != 64 {
		return nil, failure(503, "管理员密码存储无效, 请恢复完整数据库")
	}
	return s, nil
}

func random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func binding(value string) string { b := sha256.Sum256([]byte(value)); return hex.EncodeToString(b[:]) }
func cookie(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
func (s *Service) Origin(r *http.Request) (string, error) { return s.Access.Origin(r) }

func (s *Service) Session(r *http.Request) *Session {
	origin, err := s.Origin(r)
	if err != nil {
		return nil
	}
	p, err := readPolicy(s.db)
	if err != nil {
		return nil
	}
	token := cookie(r, sessionCookie)
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sessions[token]
	if !ok {
		return nil
	}
	if !x.Expires.After(time.Now()) || x.Revision != p.Revision {
		delete(s.sessions, token)
		return nil
	}
	if x.Origin != origin {
		return nil
	}
	return &x
}

func (s *Service) Invalidate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions = map[string]Session{}
	s.pending = map[string]ceremony{}
	s.proofs = map[string]proofRecord{}
}

// Exclusive waits for any in-flight credential mutation. Backup/restore callers
// first mark their operation busy, then hold this lock while capturing or
// replacing security tables. The callback may call ConsumeReauth/Invalidate.
func (s *Service) Exclusive(operation func() error) error {
	s.securityMu.Lock()
	defer s.securityMu.Unlock()
	return operation()
}

func (s *Service) passkeyOrigin(origin string) string {
	if s.Access.PublicOrigin != "" {
		return s.Access.PublicOrigin
	}
	return origin
}

func (s *Service) capabilities(r *http.Request) (map[string]any, error) {
	origin, err := s.Origin(r)
	if err != nil {
		return nil, err
	}
	p, err := readPolicy(s.db)
	if err != nil {
		return nil, err
	}
	pkOrigin := s.passkeyOrigin(origin)
	keys, err := readKeys(s.db, pkOrigin)
	if err != nil {
		return nil, err
	}
	u, _ := url.Parse(pkOrigin)
	allowed := origin == pkOrigin && (u.Scheme == "https" || u.Hostname() == "localhost")
	available := false
	for _, k := range keys {
		available = available || k.Verified
	}
	recovery := s.Access.PrivateRecovery(r, origin)
	method := "password"
	if p.Mode == "passkey" && !recovery {
		method = "passkey"
	}
	return map[string]any{"auth_mode": p.Mode, "password_login_allowed": p.Mode == "password" || recovery, "passkey_available": available, "passkey_origin_allowed": allowed, "reauth_method": method}, nil
}

func (s *Service) Capabilities(r *http.Request) map[string]any {
	v, err := s.capabilities(r)
	if err != nil {
		return map[string]any{"password_login_allowed": false, "passkey_origin_allowed": false}
	}
	return v
}
func (s *Service) RequirePasskeyReauth(r *http.Request) bool {
	return s.Capabilities(r)["reauth_method"] == "passkey"
}

var publicPaths = map[string]bool{"/": true, "/status": true, "/backups": true, "/security": true, "/app.js": true, "/backups.js": true, "/security.js": true, "/passkeys.js": true, "/style.css": true, "/favicon.ico": true, "/api/login": true, "/api/passkey/login/options": true, "/api/passkey/login/verify": true, "/api/session": true, "/healthz": true}
var noCSRF = map[string]bool{"/api/login": true, "/api/passkey/login/options": true, "/api/passkey/login/verify": true}

func (s *Service) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; frame-src 'self'; frame-ancestors 'self'; form-action 'self'; connect-src 'self'")
		if s.opts.Maintenance != nil && s.opts.Maintenance() {
			w.Header().Set("Retry-After", "5")
			WriteError(w, failure(503, "正在恢复数据, 请稍后重新登录"))
			return
		}
		origin, err := s.Origin(r)
		if err != nil {
			WriteError(w, err)
			return
		}
		if origin == s.Access.PublicOrigin {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		mutating := r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS"
		if (mutating || strings.EqualFold(r.Header.Get("Upgrade"), "websocket")) && r.Header.Get("Origin") != origin {
			WriteError(w, failure(403, "请求来源不匹配"))
			return
		}
		if mutating && strings.HasPrefix(r.URL.Path, "/api/security/") && s.opts.SecurityBusy != nil && s.opts.SecurityBusy() {
			WriteError(w, failure(409, "请等待备份或恢复操作结束后修改登录安全设置"))
			return
		}
		x := s.Session(r)
		if !publicPaths[r.URL.Path] && x == nil {
			WriteError(w, failure(401, "请先登录"))
			return
		}
		if mutating && !noCSRF[r.URL.Path] && (x == nil || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(x.CSRF)) != 1) {
			WriteError(w, failure(403, "页面凭据已失效, 请重新登录"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func WriteError(w http.ResponseWriter, err error) {
	status, message := 500, "服务暂时不可用"
	var e *HTTPError
	if errors.As(err, &e) {
		status, message = e.Status, e.Message
	}
	if status == 429 {
		w.Header().Set("Retry-After", "60")
	}
	writeJSON(w, status, map[string]any{"error": message})
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func body(r *http.Request, names ...string) (map[string]json.RawMessage, error) {
	data, err := io.ReadAll(io.LimitReader(r.Body, 128*1024+1))
	if err != nil || len(data) > 128*1024 {
		return nil, failure(400, "请求格式无效")
	}
	var value map[string]json.RawMessage
	if json.Unmarshal(data, &value) != nil || value == nil || len(value) != len(names) {
		return nil, failure(400, "请求格式无效")
	}
	for _, name := range names {
		if _, ok := value[name]; !ok {
			return nil, failure(400, "请求格式无效")
		}
	}
	return value, nil
}
func text(v json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(v, &s) != nil {
		return "", failure(400, "请求格式无效")
	}
	return s, nil
}
func integer(v json.RawMessage) (int64, error) {
	var n int64
	if json.Unmarshal(v, &n) != nil || n < 1 {
		return 0, failure(400, "请求格式无效")
	}
	return n, nil
}

type endpoint func(http.ResponseWriter, *http.Request) error

func handle(f endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := f(w, r); err != nil {
			WriteError(w, err)
		}
	}
}
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/session", handle(s.sessionStatus))
	mux.HandleFunc("POST /api/login", handle(s.login))
	mux.HandleFunc("POST /api/logout", handle(s.logout))
	mux.HandleFunc("GET /api/security", handle(s.securityStatus))
	mux.HandleFunc("POST /api/security/reauth", handle(s.passwordReauth))
	mux.HandleFunc("POST /api/passkey/login/options", handle(s.serial(s.loginOptions)))
	mux.HandleFunc("POST /api/passkey/login/verify", handle(s.serial(s.loginVerify)))
	mux.HandleFunc("POST /api/security/reauth/options", handle(s.serial(s.reauthOptions)))
	mux.HandleFunc("POST /api/security/reauth/verify", handle(s.serial(s.reauthVerify)))
	mux.HandleFunc("POST /api/security/register/options", handle(s.serial(s.registerOptions)))
	mux.HandleFunc("POST /api/security/register/verify", handle(s.serial(s.registerVerify)))
	mux.HandleFunc("POST /api/security/mode", handle(s.serial(s.securityMode)))
	mux.HandleFunc("DELETE /api/security/passkeys/{id}", handle(s.serial(s.removeKey)))
}

func (s *Service) sessionStatus(w http.ResponseWriter, r *http.Request) error {
	result, err := s.capabilities(r)
	if err != nil {
		return err
	}
	x := s.Session(r)
	result["authenticated"] = x != nil
	result["csrf"] = ""
	if x != nil {
		result["csrf"] = x.CSRF
	}
	writeJSON(w, 200, result)
	return nil
}

func (s *Service) issueSession(w http.ResponseWriter, r *http.Request, method, credentialID string, extra map[string]any) error {
	origin, err := s.Origin(r)
	if err != nil {
		return err
	}
	p, err := readPolicy(s.db)
	if err != nil {
		return err
	}
	result, err := s.capabilities(r)
	if err != nil {
		return err
	}
	if method == "password" && result["password_login_allowed"] != true {
		return failure(403, "当前已启用 Passkey 登录, 公网密码登录已关闭")
	}
	now := time.Now()
	token, csrf := random(), random()
	s.mu.Lock()
	delete(s.sessions, cookie(r, sessionCookie))
	for t, x := range s.sessions {
		if !x.Expires.After(now) || x.Revision != p.Revision {
			delete(s.sessions, t)
		}
	}
	if len(s.sessions) >= 16 {
		oldest := ""
		var earliest time.Time
		for t, x := range s.sessions {
			if oldest == "" || x.Expires.Before(earliest) {
				oldest, earliest = t, x.Expires
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[token] = Session{CSRF: csrf, Origin: origin, Method: method, CredentialID: credentialID, Expires: now.Add(8 * time.Hour), Revision: p.Revision}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(origin, "https://"), MaxAge: 8 * 3600})
	result["authenticated"], result["csrf"] = true, csrf
	for k, v := range extra {
		result[k] = v
	}
	writeJSON(w, 200, result)
	return nil
}

func (s *Service) checkLimit(ip string, passkey bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	attempts := s.passwordAttempts
	per, totalLimit := 5, 30
	if passkey {
		attempts = s.passkeyAttempts
		per, totalLimit = 30, 120
	}
	now := time.Now()
	total := 0
	for k, values := range attempts {
		recent := values[:0]
		for _, v := range values {
			if now.Sub(v) < time.Minute {
				recent = append(recent, v)
			}
		}
		if len(recent) == 0 {
			delete(attempts, k)
		} else {
			attempts[k] = recent
			total += len(recent)
		}
	}
	if len(attempts[ip]) >= per || total >= totalLimit || (attempts[ip] == nil && len(attempts) >= 256) {
		return false
	}
	attempts[ip] = append(attempts[ip], now)
	return true
}

func (s *Service) verifyPassword(r *http.Request, password string) error {
	if len([]rune(password)) > 512 {
		return failure(401, "密码错误")
	}
	if !s.checkLimit(s.Access.ClientIP(r), false) {
		return failure(429, "尝试次数过多, 请在 60 秒后重试")
	}
	select {
	case s.passwordBusy <- struct{}{}:
		defer func() { <-s.passwordBusy }()
	default:
		return failure(429, "尝试次数过多, 请在 60 秒后重试")
	}
	digest, err := scrypt.Key([]byte(password), s.salt, 16384, 8, 1, 64)
	if err != nil {
		return failure(500, "密码验证暂时不可用")
	}
	if subtle.ConstantTimeCompare(digest, s.digest) != 1 {
		return failure(401, "密码错误")
	}
	return nil
}

func (s *Service) Reauthenticate(r *http.Request, password string) error {
	before, err := readPolicy(s.db)
	if err != nil {
		return err
	}
	caps, err := s.capabilities(r)
	if err != nil {
		return err
	}
	if caps["reauth_method"] == "passkey" {
		return failure(403, "当前操作需要重新验证 Passkey, 公网密码验证已关闭")
	}
	if s.Session(r) == nil {
		return failure(401, "请先登录")
	}
	if err = s.verifyPassword(r, password); err != nil {
		return err
	}
	after, err := readPolicy(s.db)
	if err != nil {
		return err
	}
	if before.Revision != after.Revision || s.Session(r) == nil {
		return failure(401, "登录安全配置已更新, 请重新登录")
	}
	return nil
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) error {
	caps, err := s.capabilities(r)
	if err != nil {
		return err
	}
	if caps["password_login_allowed"] != true {
		return failure(403, "当前已启用 Passkey 登录, 公网密码登录已关闭")
	}
	b, err := body(r, "password")
	if err != nil {
		return err
	}
	password, err := text(b["password"])
	if err != nil {
		return failure(401, "密码错误")
	}
	if err = s.verifyPassword(r, password); err != nil {
		return err
	}
	return s.issueSession(w, r, "password", "", nil)
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) error {
	s.mu.Lock()
	delete(s.sessions, cookie(r, sessionCookie))
	s.mu.Unlock()
	origin, _ := s.Origin(r)
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(origin, "https://"), MaxAge: -1, Expires: time.Unix(1, 0)})
	writeJSON(w, 200, map[string]any{"authenticated": false})
	return nil
}

func (s *Service) securityStatus(w http.ResponseWriter, r *http.Request) error {
	origin, err := s.Origin(r)
	if err != nil {
		return err
	}
	p, err := readPolicy(s.db)
	if err != nil {
		return err
	}
	keys, err := readKeys(s.db, s.passkeyOrigin(origin))
	if err != nil {
		return err
	}
	result, err := s.capabilities(r)
	if err != nil {
		return err
	}
	public := []map[string]any{}
	for _, k := range keys {
		var last any
		if k.Last.Valid {
			last = timestamp(k.Last.Float64)
		}
		public = append(public, map[string]any{"id": k.ID, "label": k.Label, "verified": k.Verified, "created_at": timestamp(k.Created), "last_used_at": last})
	}
	result["mode"], result["revision"], result["passkeys"] = p.Mode, p.Revision, public
	result["can_register"] = result["passkey_origin_allowed"]
	result["private_recovery_access"] = s.Access.PrivateRecovery(r, origin)
	writeJSON(w, 200, result)
	return nil
}
