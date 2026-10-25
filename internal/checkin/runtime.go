// Package checkin executes fixed-origin NewAPI requests without a browser.
// Errors and progress contain only allowlisted codes, never response bodies,
// credential-bearing URLs, cookies, or raw network errors.
package checkin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

type Document = map[string]any

type SessionStore interface {
	LoadSession(accountID, binding string) (map[string]any, error)
	SaveSession(accountID, binding string, state map[string]any) error
}

type Runtime struct {
	Config              Document
	Sessions            SessionStore
	BalanceObservations []map[string]any
	BalanceError        map[string]any
	// transport is deliberately package-private: production origins cannot be
	// overridden via configuration or an environment variable.
	transport  http.RoundTripper
	steps      []Document
	current    Document
	onProgress func(map[string]any)
}

var origins = map[string]string{"anyrouter": "https://anyrouter.top", "agentrouter": "https://agentrouter.org"}

const acwUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"

var cookieName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9a-zA-Z-]+$")
var uidPattern = regexp.MustCompile(`^[1-9][0-9]*$`)
var authMessages = []string{"not logged in", "not_logged_in", "unauthorized", "invalid token", "invalid access token", "access token is invalid", "token expired", "invalid credential", "password incorrect", "incorrect password", "未登录", "尚未登录", "登录已过期", "登录状态已失效", "无效的令牌", "令牌无效", "密码错误", "用户名或密码"}
var challengeMessages = []string{"cf-chl-", "/cdn-cgi/challenge-platform", "cloudflare", "turnstile", "captcha", "验证码", "人机验证"}
var alreadyMessages = []string{"已经签到", "已签到", "重复签到", "already checked", "already signed"}

type failure struct {
	outcome, reason string
	details         Document
}

func (f *failure) Error() string           { return f.reason }
func fail(outcome, reason string) *failure { return &failure{outcome: outcome, reason: reason} }
func copyMap(value Document) Document {
	result := Document{}
	for k, v := range value {
		result[k] = v
	}
	return result
}
func text(value any) string { s, _ := value.(string); return s }
func object(value any) Document {
	m, _ := value.(map[string]any)
	if m == nil {
		return Document{}
	}
	return m
}
func boolean(value any) bool { b, _ := value.(bool); return b }
func number(value any) (float64, bool) {
	var n float64
	switch v := value.(type) {
	case float64:
		n = v
	case float32:
		n = float64(v)
	case int:
		n = float64(v)
	case int64:
		n = float64(v)
	case json.Number:
		var err error
		n, err = v.Float64()
		if err != nil {
			return 0, false
		}
	default:
		return 0, false
	}
	return n, !math.IsNaN(n) && !math.IsInf(n, 0)
}
func uid(value any) string {
	if s, ok := value.(string); ok {
		s = strings.TrimSpace(s)
		if uidPattern.MatchString(s) {
			return s
		}
		return ""
	}
	switch v := value.(type) {
	case int:
		if v > 0 {
			return strconv.Itoa(v)
		}
	case int64:
		if v > 0 {
			return strconv.FormatInt(v, 10)
		}
	case json.Number:
		if uidPattern.MatchString(v.String()) {
			return v.String()
		}
	}
	return ""
}

func strictInteger(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case json.Number:
		s := v.String()
		if strings.ContainsAny(s, ".eE") {
			return 0, false
		}
		n, err := v.Int64()
		return n, err == nil
	}
	return 0, false
}
func containsAny(value string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}
func message(payload Document) string {
	for _, key := range []string{"message", "msg", "error"} {
		value := payload[key]
		if value == nil {
			continue
		}
		if s, ok := value.(string); ok {
			if s != "" {
				return strings.ToLower(s)
			}
			continue
		}
		if b, ok := value.(bool); ok && !b {
			continue
		}
		if n, ok := number(value); ok && n == 0 {
			continue
		}
		return strings.ToLower(fmt.Sprint(value))
	}
	return ""
}
func New(config map[string]any, sessions SessionStore) *Runtime {
	return &Runtime{Config: config, Sessions: sessions}
}

// PythonJSON matches json.dumps(...,sort_keys=True,separators=(',',':'))
// for the string/null account-binding fields, including ensure_ascii=True.
func PythonJSON(value any) []byte {
	var b bytes.Buffer
	encoder := json.NewEncoder(&b)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
	encoded := bytes.TrimSuffix(b.Bytes(), []byte{'\n'})
	var out strings.Builder
	for _, r := range string(encoded) {
		if r < 128 {
			out.WriteRune(r)
			continue
		}
		if r <= 0xffff {
			out.WriteString(`\u`)
			out.WriteString(leftHex(uint16(r)))
		} else {
			a, b := utf16.EncodeRune(r)
			out.WriteString(`\u` + leftHex(uint16(a)) + `\u` + leftHex(uint16(b)))
		}
	}
	return []byte(out.String())
}
func leftHex(n uint16) string {
	s := strconv.FormatUint(uint64(n), 16)
	return strings.Repeat("0", 4-len(s)) + s
}

func AccountBinding(account, config map[string]any) string {
	bound := Document{}
	for _, key := range []string{"id", "provider", "auth_type", "cookies", "username", "password", "system_access_token", "api_user", "expected_username", "proxy"} {
		bound[key] = account[key]
	}
	p := account["proxy"]
	if p == nil || p == "" || p == "default" {
		bound["proxy_url"] = config["proxy_url"]
	}
	sum := sha256.Sum256(PythonJSON(bound))
	return hex.EncodeToString(sum[:])
}

func (r *Runtime) update(details Document) {
	for k, v := range details {
		r.current[k] = v
	}
	r.steps[len(r.steps)-1] = copyMap(r.current)
	if r.onProgress != nil {
		r.onProgress(copyMap(r.current))
	}
}
func (r *Runtime) stage(name string) {
	if r.current != nil && r.current["state"] == "running" {
		r.update(Document{"state": "completed"})
	}
	r.current = Document{"stage": name, "at": time.Now().UTC().Format(time.RFC3339Nano), "state": "running"}
	r.steps = append(r.steps, copyMap(r.current))
	r.update(nil)
}
func (r *Runtime) finish(result Document) Document {
	if result["success"] == true {
		r.stage("finished")
		r.update(Document{"state": "completed"})
	} else {
		r.update(Document{"state": "failed"})
		diagnostic := copyMap(r.current)
		delete(diagnostic, "at")
		delete(diagnostic, "state")
		result["diagnostic"] = diagnostic
	}
	result["steps"] = r.steps
	return result
}
func (r *Runtime) Execute(ctx context.Context, account map[string]any, onProgress func(map[string]any)) map[string]any {
	return r.execute(ctx, account, onProgress, false)
}
func (r *Runtime) Balance(ctx context.Context, account map[string]any, onProgress func(map[string]any)) map[string]any {
	return r.execute(ctx, account, onProgress, true)
}
func (r *Runtime) execute(ctx context.Context, account Document, onProgress func(map[string]any), readOnly bool) Document {
	r.BalanceObservations = nil
	r.BalanceError = nil
	r.steps = nil
	r.current = nil
	r.onProgress = onProgress
	r.stage("prepare")
	result := Document{"id": account["id"], "name": account["name"], "provider": account["provider"], "success": false}
	if enabled, ok := account["enabled"].(bool); ok && !enabled {
		result["outcome"], result["reason"] = "skipped", "account_disabled"
		return r.finish(result)
	}
	provider, auth := text(account["provider"]), text(account["auth_type"])
	var details Document
	var err error
	if _, ok := origins[provider]; !ok || (provider == "agentrouter" && auth != "password") || (provider == "anyrouter" && auth != "cookie" && auth != "password") {
		err = fail("failed", "unsupported_account_configuration")
	} else {
		var c *accountClient
		c, err = r.client(account)
		if err == nil {
			defer c.client.CloseIdleConnections()
			if readOnly {
				details, err = r.balance(ctx, c, account)
			} else if provider == "agentrouter" {
				details, err = r.agent(ctx, c, account)
			} else {
				details, err = r.any(ctx, c, account)
			}
		}
	}
	if err == nil {
		for k, v := range details {
			result[k] = v
		}
		result["success"] = true
	} else {
		f := fail("failed", "invalid_http_configuration")
		errors.As(err, &f)
		result["outcome"], result["reason"] = f.outcome, f.reason
		for k, v := range f.details {
			result[k] = v
		}
	}
	return r.finish(result)
}

type accountClient struct {
	client   *http.Client
	jar      *trackedJar
	origin   *url.URL
	timeout  float64
	provider string
}

func (r *Runtime) client(account Document) (*accountClient, error) {
	provider := text(account["provider"])
	origin, _ := url.Parse(origins[provider])
	timeout := float64(30)
	if value, exists := object(r.Config["http"])["timeout_seconds"]; exists {
		n, ok := number(value)
		if !ok || n < 1 || n > 300 {
			return nil, fail("failed", "invalid_http_configuration")
		}
		timeout = n
	}
	proxyURL, err := ResolveProxy(account, r.Config)
	if err != nil {
		return nil, err
	}
	// Disabling keep-alive prevents implicit transport retries on reused
	// connections. Each application request has an explicit, bounded attempt.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	transport.DialContext = (&net.Dialer{Timeout: time.Duration(timeout * float64(time.Second)), KeepAlive: -1}).DialContext
	if proxyURL != "" {
		u, _ := url.Parse(proxyURL)
		transport.Proxy = http.ProxyURL(u)
	}
	var roundTripper http.RoundTripper = transport
	if r.transport != nil {
		roundTripper = r.transport
	}
	jar := newTrackedJar()
	client := &http.Client{Transport: roundTripper, Jar: jar, Timeout: time.Duration(timeout * float64(time.Second)), CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &accountClient{client: client, jar: jar, origin: origin, timeout: timeout, provider: provider}, nil
}

// ResolveProxy validates authenticated SOCKS5 and never falls back to a direct
// connection when the requested proxy is missing, invalid or unavailable.
func ResolveProxy(account, config map[string]any) (string, error) {
	mode := account["proxy"]
	if mode == "direct" {
		return "", nil
	}
	value := mode
	if mode == nil || mode == "" || mode == "default" {
		value = config["proxy_url"]
		if value == nil || value == "" {
			if mode == "default" {
				return "", fail("failed", "proxy_not_configured")
			}
			return "", nil
		}
	}
	s, ok := value.(string)
	bad := fail("failed", "invalid_proxy_configuration")
	if !ok || len(s) > 4096 || !utf8.ValidString(s) || strings.Contains(s, `\`) {
		return "", bad
	}
	for _, c := range s {
		if unicode.IsSpace(c) || c < 32 || c == 127 {
			return "", bad
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "socks5") {
		return "", bad
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil || p < 1 || p > 65535 {
		return "", bad
	}
	host := strings.TrimSuffix(u.Hostname(), ".")
	if net.ParseIP(host) == nil {
		var err error
		host, err = idna.Lookup.ToASCII(host)
		if err != nil {
			return "", bad
		}
		if len(host) > 253 {
			return "", bad
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", bad
			}
			for _, c := range label {
				if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
					return "", bad
				}
			}
		}
	}
	if u.Scheme == "socks5" && u.User != nil {
		password, present := u.User.Password()
		if !present {
			return "", bad
		}
		for _, credential := range []string{u.User.Username(), password} {
			if len(credential) < 1 || len(credential) > 255 || !utf8.ValidString(credential) {
				return "", bad
			}
			for _, c := range credential {
				if c < 32 || c == 127 {
					return "", bad
				}
			}
		}
	}
	return s, nil
}

func (r *Runtime) request(ctx context.Context, c *accountClient, method, path string, body Document, userID string) (Document, error) {
	stage := text(r.current["stage"])
	allowed := c.provider == "anyrouter" && ((method == "GET" && path == "/api/user/self") || (method == "POST" && path == "/api/user/login"))
	for attempt := 1; attempt <= 3; attempt++ {
		payload, challenge, err := r.requestOnce(ctx, c, method, path, body, userID)
		if challenge == "" {
			return payload, err
		}
		if !allowed {
			if method == "POST" {
				return nil, fail("uncertain", "acw_challenge_requires_confirmation")
			}
			return nil, fail("blocked", "acw_challenge_unsupported")
		}
		r.update(Document{"state": "verification_required"})
		r.stage("acw_verification")
		r.update(Document{"method": method, "path": path, "http_status": r.lastHTTPStatus(), "request_attempt": attempt, "max_attempts": 3, "acw_challenges": attempt})
		value, ok := SolveACW(challenge)
		if !ok {
			return nil, fail("blocked", "acw_challenge_unsupported")
		}
		if attempt == 3 {
			return nil, fail("blocked", "acw_challenge_limit")
		}
		u := c.origin.ResolveReference(&url.URL{Path: path})
		if len(c.jar.Cookies(u)) == 0 {
			return nil, fail("blocked", "acw_cookie_context_missing")
		}
		c.jar.removeName(c.origin, "acw_sc__v2")
		c.jar.SetCookies(c.origin, []*http.Cookie{{Name: "acw_sc__v2", Value: value, Path: "/", Domain: c.origin.Hostname(), Secure: true}})
		r.update(Document{"state": "completed"})
		r.stage(stage)
		r.update(Document{"request_attempt": attempt + 1, "max_attempts": 3, "acw_challenges": attempt})
	}
	return nil, fail("blocked", "acw_challenge_limit")
}
func (r *Runtime) lastHTTPStatus() any {
	for i := len(r.steps) - 1; i >= 0; i-- {
		if n, ok := r.steps[i]["http_status"]; ok {
			return n
		}
	}
	return nil
}

func (r *Runtime) requestOnce(ctx context.Context, c *accountClient, method, path string, body Document, userID string) (Document, string, error) {
	mutation := method == "POST"
	r.update(Document{"method": method, "path": path, "timeout_seconds": c.timeout})
	u := c.origin.ResolveReference(&url.URL{Path: path})
	if c.provider == "agentrouter" && path == "/api/user/login" {
		u.RawQuery = "turnstile="
	}
	var payloadReader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, "", fail("failed", "invalid_http_configuration")
		}
		payloadReader = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, u.String(), payloadReader)
	if e != nil {
		return nil, "", fail("failed", "invalid_http_configuration")
	}
	req.Header.Set("Accept", "application/json")
	if c.provider == "anyrouter" {
		req.Header.Set("User-Agent", acwUserAgent)
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	if path == "/api/user/login" {
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
	}
	if userID != "" {
		req.Header.Set("new-api-user", userID)
	}
	response, err := c.client.Do(req)
	if err != nil {
		errorType := "RequestError"
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() || errors.Is(err, context.DeadlineExceeded) {
			errorType = "TimeoutException"
		} else if strings.Contains(strings.ToLower(err.Error()), "proxy") || strings.Contains(strings.ToLower(err.Error()), "socks") {
			errorType = "ProxyError"
		} else {
			var oe *net.OpError
			if errors.As(err, &oe) {
				errorType = "ConnectError"
			}
		}
		r.update(Document{"error_type": errorType})
		lower := strings.ToLower(err.Error())
		if strings.Contains(lower, "username/password") || strings.Contains(lower, "authentication failed") || strings.Contains(lower, "proxy authentication required") {
			return nil, "", fail("failed", "proxy_authentication_failed")
		}
		if mutation {
			return nil, "", fail("uncertain", "request_result_unknown")
		}
		return nil, "", fail("failed", "network_error")
	}
	defer response.Body.Close()
	status := response.StatusCode
	r.update(Document{"http_status": status})
	if status < 200 || status >= 300 {
		r.update(Document{"error_type": "HTTPStatusError"})
	}
	if status == 429 {
		f := fail("rate_limited", "rate_limited")
		if n, ok := retryAfter(response.Header.Get("Retry-After")); ok {
			f.details = Document{"retry_after_seconds": n}
		}
		return nil, "", f
	}
	if status >= 300 && status < 400 {
		return nil, "", fail("blocked", "response_redirected")
	}
	if status >= 500 {
		if mutation {
			return nil, "", fail("uncertain", "request_result_unknown")
		}
		return nil, "", fail("failed", "service_unavailable")
	}
	if response.Header.Get("cf-mitigated") == "challenge" {
		return nil, "", fail("blocked", "interactive_verification_required")
	}
	// Bound both memory use and the accepted JSON response size.
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil {
		if mutation {
			return nil, "", fail("uncertain", "request_result_unknown")
		}
		return nil, "", fail("failed", "network_error")
	}
	if len(data) > 1024*1024 {
		if mutation {
			return nil, "", fail("uncertain", "invalid_json_response")
		}
		return nil, "", fail("failed", "invalid_json_response")
	}
	preview := string(data)
	if len(preview) > 100000 {
		preview = preview[:100000]
	}
	lower := strings.ToLower(preview)
	trimmed := strings.TrimSpace(lower)
	if strings.Contains(strings.ToLower(response.Header.Get("Content-Type")), "text/html") || strings.HasPrefix(trimmed, "<!doctype html") || strings.HasPrefix(trimmed, "<html") {
		if containsAny(lower, challengeMessages) {
			return nil, "", fail("blocked", "interactive_verification_required")
		}
		if IsACWChallenge(string(data)) {
			return nil, string(data), nil
		}
		return nil, "", fail("blocked", "html_response_received")
	}
	var payload Document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	err = decoder.Decode(&payload)
	var extra any
	trailing := decoder.Decode(&extra)
	if err != nil || payload == nil || trailing != io.EOF {
		if containsAny(lower, challengeMessages) {
			return nil, "", fail("blocked", "interactive_verification_required")
		}
		if status == 401 {
			return nil, "", fail("needs_credentials", "credentials_rejected")
		}
		if status == 403 {
			return nil, "", fail("blocked", "access_blocked")
		}
		if mutation {
			return nil, "", fail("uncertain", "invalid_json_response")
		}
		return nil, "", fail("failed", "invalid_json_response")
	}
	msg := message(payload)
	if containsAny(msg, challengeMessages) {
		return nil, "", fail("blocked", "interactive_verification_required")
	}
	if status == 401 || containsAny(msg, authMessages) {
		return nil, "", fail("needs_credentials", "credentials_rejected")
	}
	if status == 403 {
		return nil, "", fail("blocked", "access_blocked")
	}
	if status < 200 || status >= 300 {
		return nil, "", fail("failed", "http_request_rejected")
	}
	return payload, "", nil
}

func retryAfter(value string) (int, bool) {
	var seconds int64
	if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
		seconds = n
	} else if errors.Is(err, strconv.ErrRange) {
		if strings.HasPrefix(strings.TrimSpace(value), "-") {
			return 0, true
		}
		return 86400 * 365, true
	} else if d, err := http.ParseTime(value); err == nil {
		seconds = int64(math.Ceil(time.Until(d).Seconds()))
	} else {
		return 0, false
	}
	if seconds < 0 {
		seconds = 0
	}
	if seconds > 86400*365 {
		seconds = 86400 * 365
	}
	return int(seconds), true
}

func verify(payload, account Document, savedID string) (Document, error) {
	data, ok := payload["data"].(map[string]any)
	if payload["success"] != true || !ok || uid(data["id"]) == "" {
		if success, ok := payload["success"].(bool); ok && !success {
			return nil, fail("failed", "user_info_rejected")
		}
		return nil, fail("failed", "invalid_user_info")
	}
	actual, expected := uid(data["id"]), uid(account["api_user"])
	if expected != "" && actual != expected || savedID != "" && actual != savedID {
		return nil, fail("needs_credentials", "account_identity_mismatch")
	}
	if expectedName := text(account["expected_username"]); expectedName != "" && text(data["username"]) != expectedName {
		return nil, fail("needs_credentials", "account_identity_mismatch")
	}
	return data, nil
}
func (r *Runtime) load(account Document) (Document, error) {
	if r.Sessions == nil {
		return nil, nil
	}
	state, err := r.Sessions.LoadSession(text(account["id"]), AccountBinding(account, r.Config))
	if err != nil {
		return nil, fail("failed", "session_load_failed")
	}
	return state, nil
}
func (r *Runtime) save(c *accountClient, account Document, userID string) error {
	if r.Sessions == nil {
		return fail("failed", "session_save_failed")
	}
	err := r.Sessions.SaveSession(text(account["id"]), AccountBinding(account, r.Config), Document{"api_user": userID, "cookies": c.jar.saved(c.origin.Hostname())})
	if err != nil {
		return fail("failed", "session_save_failed")
	}
	return nil
}
func (r *Runtime) observe(user Document) {
	r.BalanceObservations = append(r.BalanceObservations, Document{"id": user["id"], "quota": user["quota"], "used_quota": user["used_quota"], "today_income": user["today_income"], "observed_at": float64(time.Now().UnixNano()) / 1e9})
}

func (r *Runtime) balance(ctx context.Context, c *accountClient, account Document) (Document, error) {
	r.stage("load_session")
	state, err := r.load(account)
	if err != nil {
		return nil, err
	}
	userID := uid(account["api_user"])
	if state != nil {
		savedID := uid(state["api_user"])
		if savedID == "" {
			return nil, fail("failed", "invalid_saved_session")
		}
		if userID != "" && userID != savedID {
			return nil, fail("needs_credentials", "account_identity_mismatch")
		}
		if err = c.cookies(state["cookies"], true); err != nil {
			return nil, err
		}
		userID = savedID
	} else if account["provider"] == "anyrouter" && account["auth_type"] == "cookie" {
		if err = c.cookies(account["cookies"], false); err != nil {
			return nil, err
		}
	} else {
		return nil, fail("needs_credentials", "balance_session_required")
	}
	if userID == "" {
		return nil, fail("needs_credentials", "cookie_user_id_required")
	}
	if len(c.jar.Cookies(c.origin)) == 0 {
		return nil, fail("needs_credentials", "balance_session_required")
	}
	r.stage("read_balance")
	payload, err := r.request(ctx, c, "GET", "/api/user/self", nil, userID)
	if err != nil {
		return nil, err
	}
	user, err := verify(payload, account, userID)
	if err != nil {
		return nil, err
	}
	r.observe(user)
	return Document{"outcome": "success", "reason": "balance_refreshed"}, nil
}

func (r *Runtime) agent(ctx context.Context, c *accountClient, account Document) (Document, error) {
	username, password := text(account["username"]), text(account["password"])
	if username == "" || password == "" {
		return nil, fail("needs_credentials", "username_and_password_required")
	}
	if text(account["api_user"]) != "" && uid(account["api_user"]) == "" {
		return nil, fail("needs_credentials", "login_identity_unverified")
	}
	r.stage("password_login")
	login, err := r.request(ctx, c, "POST", "/api/user/login", Document{"username": username, "password": password}, "")
	if err != nil {
		return nil, err
	}
	if success, ok := login["success"].(bool); ok && !success {
		return nil, fail("needs_credentials", "password_login_rejected")
	}
	r.stage("verify_identity")
	user, err := verify(login, account, "")
	if err != nil {
		var f *failure
		if errors.As(err, &f) && f.reason == "invalid_user_info" {
			return nil, fail("uncertain", "agent_checkin_result_unknown")
		}
		return nil, err
	}
	r.stage("verify_result")
	checked, ok := user["checked_in"].(bool)
	if !ok {
		return nil, fail("uncertain", "agent_checkin_result_unknown")
	}
	r.update(Document{"checked_in": checked})
	if !checked {
		f := fail("failed", "agent_checkin_not_confirmed")
		f.details = Document{"checked_in": false}
		return nil, f
	}
	if boolean(object(r.Config["monitoring"])["enabled"]) {
		err = r.save(c, account, uid(user["id"]))
		if err == nil {
			r.stage("read_balance")
			var payload, observed Document
			payload, err = r.request(ctx, c, "GET", "/api/user/self", nil, uid(user["id"]))
			if err == nil {
				observed, err = verify(payload, account, uid(user["id"]))
				if err == nil {
					r.observe(observed)
				}
			}
		}
		if err != nil {
			var f *failure
			if errors.As(err, &f) {
				r.BalanceError = Document{"outcome": f.outcome, "reason": f.reason}
				for k, v := range f.details {
					r.BalanceError[k] = v
				}
			} else {
				r.BalanceError = Document{"outcome": "failed", "reason": "balance_collection_failed"}
			}
			r.update(Document{"state": "failed"})
		}
	}
	return Document{"outcome": "success", "reason": "agent_checkin_verified", "checked_in": true}, nil
}

func (r *Runtime) any(ctx context.Context, c *accountClient, account Document) (Document, error) {
	r.stage("load_session")
	state, err := r.load(account)
	if err != nil {
		return nil, err
	}
	userID := uid(account["api_user"])
	savedID := ""
	if state != nil {
		savedID = uid(state["api_user"])
		if savedID == "" {
			return nil, fail("failed", "invalid_saved_session")
		}
	}
	if savedID != "" && userID != "" && savedID != userID {
		return nil, fail("needs_credentials", "account_identity_mismatch")
	}
	if userID == "" {
		userID = savedID
	}
	if account["auth_type"] == "cookie" && userID == "" {
		return nil, fail("needs_credentials", "cookie_user_id_required")
	}
	if state != nil {
		if err = c.cookies(state["cookies"], true); err != nil {
			return nil, err
		}
	} else if account["auth_type"] == "cookie" {
		if err = c.cookies(account["cookies"], false); err != nil {
			return nil, err
		}
	}
	var before Document
	if state != nil || account["auth_type"] == "cookie" {
		r.stage("verify_identity")
		var p Document
		p, err = r.request(ctx, c, "GET", "/api/user/self", nil, userID)
		if err == nil {
			before, err = verify(p, account, savedID)
		}
		if err != nil {
			r.update(Document{"state": "failed"})
			var f *failure
			if !errors.As(err, &f) || account["auth_type"] != "password" || f.reason != "credentials_rejected" {
				return nil, err
			}
		}
	}
	if before == nil {
		username, password := text(account["username"]), text(account["password"])
		if username == "" || password == "" {
			return nil, fail("needs_credentials", "username_and_password_required")
		}
		c.jar = newTrackedJar()
		c.client.Jar = c.jar
		r.stage("password_login")
		login, err := r.request(ctx, c, "POST", "/api/user/login", Document{"username": username, "password": password}, "")
		if err != nil {
			return nil, err
		}
		if login["success"] != true {
			return nil, fail("needs_credentials", "password_login_rejected")
		}
		loginID := uid(object(login["data"])["id"])
		if loginID != "" && (savedID != "" && loginID != savedID || userID != "" && loginID != userID) {
			return nil, fail("needs_credentials", "account_identity_mismatch")
		}
		if userID == "" {
			userID = loginID
		}
		if userID == "" {
			return nil, fail("needs_credentials", "login_identity_unverified")
		}
		r.stage("verify_identity")
		p, err := r.request(ctx, c, "GET", "/api/user/self", nil, userID)
		if err != nil {
			return nil, err
		}
		before, err = verify(p, account, userID)
		if err != nil {
			return nil, err
		}
	}
	userID = uid(before["id"])
	if boolean(object(r.Config["monitoring"])["enabled"]) {
		r.observe(before)
	}
	r.stage("checkin")
	payload, err := r.request(ctx, c, "POST", "/api/user/sign_in", nil, userID)
	if err != nil {
		return nil, err
	}
	already := containsAny(message(payload), alreadyMessages)
	accepted := payload["success"] == true
	if _, present := payload["success"]; !present {
		n1, o1 := strictInteger(payload["ret"])
		n2, o2 := strictInteger(payload["code"])
		accepted = o1 && n1 == 1 || o2 && n2 == 0
	}
	if !accepted && !already {
		return nil, fail("failed", "checkin_rejected")
	}
	r.stage("verify_result")
	afterPayload, err := r.request(ctx, c, "GET", "/api/user/self", nil, userID)
	var after Document
	if err == nil {
		after, err = verify(afterPayload, account, userID)
	}
	if err != nil {
		f := fail("uncertain", "checkin_verification_failed")
		var cause *failure
		if errors.As(err, &cause) {
			f.details = Document{"verification_reason": cause.reason}
		}
		return nil, f
	}
	if boolean(object(r.Config["monitoring"])["enabled"]) {
		r.observe(after)
	}
	r.stage("save_session")
	if err = r.save(c, account, userID); err != nil {
		return nil, fail("uncertain", "session_save_failed")
	}
	details := Document{"outcome": "success", "reason": "checkin_verified"}
	if already {
		details["outcome"], details["reason"] = "already_checked_in", "already_checked_in"
	}
	qb, okb := number(before["quota"])
	qa, oka := number(after["quota"])
	if okb {
		details["balance_before"] = qb / 500000
	}
	if oka {
		details["balance_after"] = qa / 500000
	}
	ub, okub := number(before["used_quota"])
	ua, okua := number(after["used_quota"])
	if okb && oka && okub && okua {
		reward := (qa + ua - qb - ub) / 500000
		if reward >= 0 {
			details["reward"] = math.Round(reward*1e10) / 1e10
		}
	}
	return details, nil
}

// trackedJar delegates request policy to Go's cookiejar and retains the
// original domain/path/expiry needed by the encrypted Python session format.
type trackedJar struct {
	jar   *cookiejar.Jar
	items map[string]*http.Cookie
}

func newTrackedJar() *trackedJar {
	j, _ := cookiejar.New(nil)
	return &trackedJar{jar: j, items: map[string]*http.Cookie{}}
}
func (j *trackedJar) Cookies(u *url.URL) []*http.Cookie { return j.jar.Cookies(u) }
func (j *trackedJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.jar.SetCookies(u, cookies)
	for _, original := range cookies {
		c := *original
		domain := c.Domain
		if domain == "" {
			domain = u.Hostname()
		}
		if strings.TrimPrefix(domain, ".") != u.Hostname() {
			continue
		}
		c.Domain = domain
		if c.Path == "" || c.Path[0] != '/' {
			i := strings.LastIndex(u.Path, "/")
			c.Path = "/"
			if i > 0 {
				c.Path = u.Path[:i]
			}
		}
		key := c.Domain + "\n" + c.Path + "\n" + c.Name
		if c.MaxAge < 0 || !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
			delete(j.items, key)
			continue
		}
		if c.MaxAge > 0 {
			c.Expires = time.Now().Add(time.Duration(c.MaxAge) * time.Second)
		}
		j.items[key] = &c
	}
}
func (j *trackedJar) removeName(u *url.URL, name string) {
	for key, c := range j.items {
		if c.Name == name {
			expired := *c
			expired.MaxAge = -1
			j.jar.SetCookies(u, []*http.Cookie{&expired})
			delete(j.items, key)
		}
	}
}
func (j *trackedJar) saved(host string) []map[string]any {
	items := make([]map[string]any, 0, len(j.items))
	keys := make([]string, 0, len(j.items))
	for key := range j.items {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		c := j.items[key]
		if c.Domain != host && c.Domain != "."+host {
			continue
		}
		if !c.Expires.IsZero() && c.Expires.Before(time.Now()) {
			continue
		}
		var expires any
		if !c.Expires.IsZero() {
			expires = c.Expires.Unix()
		}
		items = append(items, Document{"name": c.Name, "value": c.Value, "domain": c.Domain, "path": c.Path, "expires": expires})
	}
	return items
}
func (c *accountClient) cookies(value any, saved bool) error {
	var items []map[string]any
	if saved {
		switch list := value.(type) {
		case []any:
			for _, entry := range list {
				item, ok := entry.(map[string]any)
				if !ok {
					return fail("failed", "invalid_saved_session")
				}
				items = append(items, item)
			}
		case []map[string]any:
			items = list
		default:
			return fail("failed", "invalid_saved_session")
		}
	} else {
		values := map[string]any{}
		switch v := value.(type) {
		case string:
			for _, part := range strings.Split(v, ";") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				pair := strings.SplitN(part, "=", 2)
				if len(pair) != 2 {
					return fail("needs_credentials", "invalid_cookie_configuration")
				}
				values[pair[0]] = pair[1]
			}
		case map[string]any:
			values = v
		default:
			return fail("needs_credentials", "invalid_cookie_configuration")
		}
		if len(values) == 0 {
			return fail("needs_credentials", "invalid_cookie_configuration")
		}
		for name, v := range values {
			items = append(items, Document{"name": name, "value": v, "domain": c.origin.Hostname(), "path": "/"})
		}
	}
	for _, item := range items {
		name, value := text(item["name"]), text(item["value"])
		if _, ok := item["value"].(string); !ok {
			return fail("needs_credentials", "invalid_cookie_configuration")
		}
		domain, path := text(item["domain"]), text(item["path"])
		if domain == "" {
			domain = c.origin.Hostname()
		}
		if path == "" {
			path = "/"
		}
		if !cookieName.MatchString(name) || strings.ContainsAny(value, "\r\n;") || (domain != c.origin.Hostname() && domain != "."+c.origin.Hostname()) || !strings.HasPrefix(path, "/") {
			return fail("needs_credentials", "invalid_cookie_configuration")
		}
		cookie := &http.Cookie{Name: name, Value: value, Domain: domain, Path: path, Secure: true}
		// Go drops non-ASCII/control cookie values. Reject instead of silently
		// changing credentials or emitting net/http's raw-cookie warning.
		if err := cookie.Valid(); err != nil {
			return fail("needs_credentials", "invalid_cookie_configuration")
		}
		if expiry := item["expires"]; expiry != nil {
			n, ok := number(expiry)
			if !ok || n != math.Trunc(n) {
				return fail("failed", "invalid_saved_session")
			}
			cookie.Expires = time.Unix(int64(n), 0)
		}
		c.jar.SetCookies(c.origin, []*http.Cookie{cookie})
	}
	return nil
}
