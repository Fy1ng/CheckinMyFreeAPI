package auth

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type administrator struct {
	Handle      []byte
	Credentials []webauthn.Credential
}

func (a administrator) WebAuthnID() []byte                         { return a.Handle }
func (a administrator) WebAuthnName() string                       { return "admin" }
func (a administrator) WebAuthnDisplayName() string                { return "Administrator" }
func (a administrator) WebAuthnCredentials() []webauthn.Credential { return a.Credentials }

type ceremony struct {
	Kind, Origin, Binding, Label string
	Revision                     int64
	Expires                      time.Time
	State                        webauthn.SessionData
}

func webauthnServer(origin string) (*webauthn.WebAuthn, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" {
		return nil, failure(400, "Passkey 站点配置无效")
	}
	return webauthn.New(&webauthn.Config{RPID: u.Hostname(), RPDisplayName: "CheckinMyFreeAPI", RPOrigins: []string{origin}, RPAllowCrossOrigin: false, RPTopOriginVerificationMode: protocol.TopOriginExplicitVerificationMode, AttestationPreference: protocol.PreferNoAttestation, AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementRequired, UserVerification: protocol.VerificationRequired}, Timeouts: webauthn.TimeoutsConfig{Login: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL}, Registration: webauthn.TimeoutConfig{Enforce: true, Timeout: ceremonyTTL}}})
}

func (s *Service) requirePasskeyOrigin(r *http.Request) (string, error) {
	caps, err := s.capabilities(r)
	if err != nil {
		return "", err
	}
	if caps["passkey_origin_allowed"] != true {
		return "", failure(400, "请使用配置的 HTTPS 管理地址进行 Passkey 操作")
	}
	if !s.checkLimit(s.Access.ClientIP(r), true) {
		return "", failure(429, "Passkey 验证请求过多, 请稍后重试")
	}
	origin, err := s.Origin(r)
	return s.passkeyOrigin(origin), err
}

func (s *Service) cleanLocked() {
	now := time.Now()
	for k, v := range s.pending {
		if !v.Expires.After(now) {
			delete(s.pending, k)
		}
	}
	for k, v := range s.proofs {
		if !v.Expires.After(now) {
			delete(s.proofs, k)
		}
	}
}

func (s *Service) loadUser(origin string) (administrator, []keyRecord, error) {
	p, err := readPolicy(s.db)
	if err != nil {
		return administrator{}, nil, err
	}
	rows, err := readKeys(s.db, origin)
	if err != nil {
		return administrator{}, nil, err
	}
	u, _ := url.Parse(origin)
	user := administrator{Handle: p.Handle}
	for _, row := range rows {
		if row.RPID != u.Hostname() {
			return administrator{}, nil, failure(503, "Passkey 站点记录不匹配")
		}
		c, err := row.credential()
		if err != nil {
			return administrator{}, nil, err
		}
		user.Credentials = append(user.Credentials, c)
	}
	return user, rows, nil
}

func (s *Service) begin(kind, origin, sessionBinding, label string) (map[string]any, error) {
	p, err := readPolicy(s.db)
	if err != nil {
		return nil, err
	}
	user, rows, err := s.loadUser(origin)
	if err != nil {
		return nil, err
	}
	server, err := webauthnServer(origin)
	if err != nil {
		return nil, err
	}
	var public any
	var state *webauthn.SessionData
	if kind == "register" {
		label = strings.TrimSpace(label)
		if len([]rune(label)) < 1 || len([]rune(label)) > 80 {
			return nil, failure(400, "请填写 1 到 80 字符的 Passkey 名称")
		}
		for _, c := range label {
			if unicode.IsControl(c) {
				return nil, failure(400, "Passkey 名称不能包含控制字符")
			}
		}
		if len(rows) >= 10 {
			return nil, failure(400, "最多保存 10 个 Passkey")
		}
		exclusions := make([]protocol.CredentialDescriptor, len(user.Credentials))
		for i, c := range user.Credentials {
			exclusions[i] = c.Descriptor()
		}
		options, x, e := server.BeginRegistration(user, webauthn.WithExclusions(exclusions))
		if e != nil {
			return nil, failure(400, "无法创建 Passkey 注册请求")
		}
		public, state = options.Response, x
	} else {
		if len(user.Credentials) == 0 {
			return nil, failure(400, "尚未绑定此站点的 Passkey, 请先使用密码模式完成绑定")
		}
		options, x, e := server.BeginLogin(user, webauthn.WithUserVerification(protocol.VerificationRequired))
		if e != nil {
			return nil, failure(400, "无法创建 Passkey 验证请求")
		}
		public, state = options.Response, x
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	if len(s.pending) >= 128 {
		return nil, failure(429, "验证请求过多, 请稍后重试")
	}
	ticket := random()
	s.pending[ticket] = ceremony{Kind: kind, Origin: origin, Binding: sessionBinding, Label: label, Revision: p.Revision, Expires: time.Now().Add(ceremonyTTL), State: *state}
	return map[string]any{"ticket": ticket, "publicKey": public}, nil
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func strictCredential(data json.RawMessage, origin string) error {
	if len(data) > 65536 {
		return failure(400, "Passkey 响应无效")
	}
	var value struct {
		ID       string `json:"id"`
		RawID    string `json:"rawId"`
		Type     string `json:"type"`
		Response struct {
			Client string          `json:"clientDataJSON"`
			Handle json.RawMessage `json:"userHandle"`
		} `json:"response"`
	}
	if json.Unmarshal(data, &value) != nil || value.ID != value.RawID || len(value.ID) < 2 || len(value.ID) > 1400 || !identifierPattern.MatchString(value.ID) || value.Type != "public-key" {
		return failure(400, "Passkey 响应无效")
	}
	client, err := base64.RawURLEncoding.DecodeString(value.Response.Client)
	if err != nil {
		return failure(400, "Passkey 响应校验失败, 请重新验证")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(client, &fields) != nil || fields == nil {
		return failure(400, "Passkey 响应无效")
	}
	var clientOrigin string
	if json.Unmarshal(fields["origin"], &clientOrigin) != nil || clientOrigin != origin {
		return failure(400, "Passkey 响应来源不匹配")
	}
	if raw, ok := fields["crossOrigin"]; ok && string(raw) != "false" {
		return failure(400, "不允许跨域 Passkey 响应")
	}
	if raw, ok := fields["topOrigin"]; ok && string(raw) != "null" {
		return failure(400, "不允许跨域 Passkey 响应")
	}
	return nil
}

func (s *Service) complete(kind, ticket string, credential json.RawMessage, origin, sessionBinding string) (string, error) {
	p, err := readPolicy(s.db)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	s.cleanLocked()
	item, ok := s.pending[ticket]
	delete(s.pending, ticket)
	s.mu.Unlock()
	if !ok || item.Kind != kind || item.Origin != origin || subtle.ConstantTimeCompare([]byte(item.Binding), []byte(sessionBinding)) != 1 || item.Revision != p.Revision {
		return "", failure(400, "Passkey 验证请求已失效, 请重新开始")
	}
	if err = strictCredential(credential, origin); err != nil {
		return "", err
	}
	user, rows, err := s.loadUser(origin)
	if err != nil {
		return "", err
	}
	server, err := webauthnServer(origin)
	if err != nil {
		return "", err
	}
	if kind == "register" {
		parsed, e := protocol.ParseCredentialCreationResponseBytes(credential)
		if e != nil {
			return "", failure(400, "Passkey 响应校验失败, 请重新验证")
		}
		c, e := server.CreateCredential(user, item.State, parsed)
		if e != nil {
			return "", failure(400, "Passkey 响应校验失败, 请重新验证")
		}
		return addKey(s.db, origin, server.Config.RPID, item.Label, c)
	}
	parsed, e := protocol.ParseCredentialRequestResponseBytes(credential)
	if e != nil {
		return "", failure(400, "Passkey 响应校验失败, 请重新验证")
	}
	// The library treats an empty userHandle like an omitted handle. The existing
	// contract distinguishes these: any supplied handle must equal the stored user.
	var raw struct {
		Response struct {
			Handle *string `json:"userHandle"`
		} `json:"response"`
	}
	if json.Unmarshal(credential, &raw) != nil {
		return "", failure(400, "Passkey 响应无效")
	}
	if raw.Response.Handle != nil {
		h, e := base64.RawURLEncoding.DecodeString(*raw.Response.Handle)
		if e != nil || subtle.ConstantTimeCompare(h, user.Handle) != 1 {
			return "", failure(400, "Passkey 用户标识不匹配")
		}
	}
	c, e := server.ValidateLogin(user, item.State, parsed)
	if e != nil {
		return "", failure(400, "Passkey 响应校验失败, 请重新验证")
	}
	id := base64.RawURLEncoding.EncodeToString(c.ID)
	for _, previous := range rows {
		if previous.ID == id {
			if err = recordAssertion(s.db, origin, c, previous); err != nil {
				return "", err
			}
			return id, nil
		}
	}
	return "", failure(400, "Passkey 不存在")
}

func (s *Service) issueProof(r *http.Request, method, credentialID string) (string, error) {
	origin, err := s.Origin(r)
	if err != nil {
		return "", err
	}
	p, err := readPolicy(s.db)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	if len(s.proofs) >= 128 {
		return "", failure(429, "验证请求过多, 请稍后重试")
	}
	token := random()
	s.proofs[token] = proofRecord{Proof: Proof{method, credentialID}, Origin: origin, Binding: binding(cookie(r, sessionCookie)), Revision: p.Revision, Expires: time.Now().Add(ceremonyTTL)}
	return token, nil
}

// ConsumeReauth is single-use and binds the proof to this session, exact origin,
// current security revision and the current authentication mode.
func (s *Service) ConsumeReauth(r *http.Request, token string, requirePasskey bool) (Proof, error) {
	origin, err := s.Origin(r)
	if err != nil {
		return Proof{}, err
	}
	p, err := readPolicy(s.db)
	if err != nil {
		return Proof{}, err
	}
	requirePasskey = requirePasskey || s.RequirePasskeyReauth(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cleanLocked()
	proof, ok := s.proofs[token]
	delete(s.proofs, token)
	if !ok || proof.Origin != origin || subtle.ConstantTimeCompare([]byte(proof.Binding), []byte(binding(cookie(r, sessionCookie)))) != 1 || proof.Revision != p.Revision || (requirePasskey && proof.Method != "passkey") {
		return Proof{}, failure(400, "请重新验证当前登录身份后操作")
	}
	return proof.Proof, nil
}

func (s *Service) passwordReauth(w http.ResponseWriter, r *http.Request) error {
	b, err := body(r, "password")
	if err != nil {
		return err
	}
	password, err := text(b["password"])
	if err != nil {
		return err
	}
	if err = s.Reauthenticate(r, password); err != nil {
		return err
	}
	token, err := s.issueProof(r, "password", "")
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"reauth_token": token})
	return nil
}

func (s *Service) loginOptions(w http.ResponseWriter, r *http.Request) error {
	origin, err := s.requirePasskeyOrigin(r)
	if err != nil {
		return err
	}
	if _, err = body(r); err != nil {
		return err
	}
	browser := random()
	result, err := s.begin("login", origin, binding(browser), "")
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: "checkin_passkey_challenge", Value: browser, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(origin, "https://"), MaxAge: 180})
	writeJSON(w, 200, result)
	return nil
}
func (s *Service) loginVerify(w http.ResponseWriter, r *http.Request) error {
	origin, err := s.requirePasskeyOrigin(r)
	if err != nil {
		return err
	}
	b, err := body(r, "ticket", "credential")
	if err != nil {
		return err
	}
	ticket, err := text(b["ticket"])
	if err != nil {
		return err
	}
	id, err := s.complete("login", ticket, b["credential"], origin, binding(cookie(r, "checkin_passkey_challenge")))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: "checkin_passkey_challenge", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, Secure: strings.HasPrefix(origin, "https://"), MaxAge: -1})
	return s.issueSession(w, r, "passkey", id, nil)
}
func (s *Service) reauthOptions(w http.ResponseWriter, r *http.Request) error {
	origin, err := s.requirePasskeyOrigin(r)
	if err != nil {
		return err
	}
	if _, err = body(r); err != nil {
		return err
	}
	result, err := s.begin("reauth", origin, binding(cookie(r, sessionCookie)), "")
	if err != nil {
		return err
	}
	writeJSON(w, 200, result)
	return nil
}
func (s *Service) reauthVerify(w http.ResponseWriter, r *http.Request) error {
	origin, err := s.requirePasskeyOrigin(r)
	if err != nil {
		return err
	}
	b, err := body(r, "ticket", "credential")
	if err != nil {
		return err
	}
	ticket, err := text(b["ticket"])
	if err != nil {
		return err
	}
	id, err := s.complete("reauth", ticket, b["credential"], origin, binding(cookie(r, sessionCookie)))
	if err != nil {
		return err
	}
	token, err := s.issueProof(r, "passkey", id)
	if err != nil {
		return err
	}
	writeJSON(w, 200, map[string]any{"reauth_token": token})
	return nil
}

func (s *Service) registerOptions(w http.ResponseWriter, r *http.Request) error {
	origin, err := s.requirePasskeyOrigin(r)
	if err != nil {
		return err
	}
	b, err := body(r, "label", "reauth_token")
	if err != nil {
		return err
	}
	label, err := text(b["label"])
	if err != nil {
		return err
	}
	token, err := text(b["reauth_token"])
	if err != nil {
		return err
	}
	if _, err = s.ConsumeReauth(r, token, false); err != nil {
		return err
	}
	result, err := s.begin("register", origin, binding(cookie(r, sessionCookie)), label)
	if err != nil {
		return err
	}
	writeJSON(w, 200, result)
	return nil
}
func (s *Service) registerVerify(w http.ResponseWriter, r *http.Request) error {
	origin, err := s.requirePasskeyOrigin(r)
	if err != nil {
		return err
	}
	b, err := body(r, "ticket", "credential")
	if err != nil {
		return err
	}
	ticket, err := text(b["ticket"])
	if err != nil {
		return err
	}
	current := s.Session(r)
	if current == nil {
		return failure(401, "请先登录")
	}
	id, err := s.complete("register", ticket, b["credential"], origin, binding(cookie(r, sessionCookie)))
	if err != nil {
		return err
	}
	s.Invalidate()
	return s.issueSession(w, r, current.Method, current.CredentialID, map[string]any{"registered": true, "credential_id": id})
}

func (s *Service) securityMode(w http.ResponseWriter, r *http.Request) error {
	b, err := body(r, "mode", "revision", "reauth_token")
	if err != nil {
		return err
	}
	mode, err := text(b["mode"])
	if err != nil || (mode != "password" && mode != "passkey") {
		return failure(400, "登录模式无效")
	}
	revision, err := integer(b["revision"])
	if err != nil {
		return err
	}
	token, err := text(b["reauth_token"])
	if err != nil {
		return err
	}
	proof, err := s.ConsumeReauth(r, token, mode == "passkey")
	if err != nil {
		return err
	}
	p, err := readPolicy(s.db)
	if err != nil {
		return err
	}
	if p.Revision != revision {
		return failure(409, "登录安全配置已更新, 请重新读取")
	}
	if mode == "passkey" {
		origin, _ := s.Origin(r)
		keys, err := readKeys(s.db, s.passkeyOrigin(origin))
		if err != nil {
			return err
		}
		verified := false
		for _, k := range keys {
			verified = verified || k.Verified
		}
		if !verified || proof.Method != "passkey" {
			return failure(400, "请先绑定并验证一个 Passkey, 再启用 Passkey 登录")
		}
	}
	res, err := s.db.Exec("UPDATE web_security SET mode=?,revision=revision+1 WHERE id=1 AND revision=?", mode, revision)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return failure(409, "登录安全配置已更新, 请重新读取")
	}
	s.Invalidate()
	return s.issueSession(w, r, proof.Method, proof.CredentialID, map[string]any{"mode": mode, "revision": revision + 1})
}

func (s *Service) removeKey(w http.ResponseWriter, r *http.Request) error {
	b, err := body(r, "revision", "reauth_token")
	if err != nil {
		return err
	}
	revision, err := integer(b["revision"])
	if err != nil {
		return err
	}
	token, err := text(b["reauth_token"])
	if err != nil {
		return err
	}
	proof, err := s.ConsumeReauth(r, token, false)
	if err != nil {
		return err
	}
	p, err := readPolicy(s.db)
	if err != nil {
		return err
	}
	if p.Revision != revision {
		return failure(409, "登录安全配置已更新, 请重新读取")
	}
	origin, _ := s.Origin(r)
	keys, err := readKeys(s.db, s.passkeyOrigin(origin))
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	found, last := false, false
	verified := 0
	for _, k := range keys {
		if k.Verified {
			verified++
		}
		if k.ID == id {
			found = true
			last = k.Verified
		}
	}
	if !found {
		return failure(400, "Passkey 不存在")
	}
	if p.Mode == "passkey" && last && verified <= 1 {
		return failure(400, "Passkey 模式不能删除最后一个已验证密钥, 请先添加其他密钥或切换模式")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM web_passkeys WHERE id=? AND origin=?", id, s.passkeyOrigin(origin)); err != nil {
		return err
	}
	res, err := tx.Exec("UPDATE web_security SET revision=revision+1 WHERE id=1 AND revision=?", revision)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return failure(409, "登录安全配置已更新, 请重新读取")
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.Invalidate()
	return s.issueSession(w, r, proof.Method, proof.CredentialID, map[string]any{"deleted": true})
}

func (s *Service) serial(f endpoint) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		s.securityMu.Lock()
		defer s.securityMu.Unlock()
		if s.opts.Maintenance != nil && s.opts.Maintenance() {
			return failure(503, "正在恢复数据, 请稍后重新登录")
		}
		if strings.HasPrefix(r.URL.Path, "/api/security/") && s.opts.SecurityBusy != nil && s.opts.SecurityBusy() {
			return failure(409, "请等待备份或恢复操作结束后修改登录安全设置")
		}
		if !noCSRF[r.URL.Path] && s.Session(r) == nil {
			return failure(401, "请先登录")
		}
		return f(w, r)
	}
}
