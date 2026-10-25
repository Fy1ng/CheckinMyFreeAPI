// Package app connects the standalone HTTP UI, serial jobs and local lifecycle.
package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/auth"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/backup"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/storage"
	frontend "github.com/Fy1ng/CheckinMyFreeAPI/server"
)

type Options struct {
	DataDir          string
	Key              []byte
	Password         string
	Launch           platform.Launch
	DisableScheduler bool
	Shutdown         func()
	DesktopIdentity  http.Handler
	LocalMode        bool
}
type restoreContext struct {
	password, binding string
	expires           time.Time
}
type setupContext struct {
	token, csrf, origin string
	expires             time.Time
}
type App struct {
	Store       *storage.Store
	Jobs        *Jobs
	Runtime     *RuntimeConfig
	Backups     *backup.Manager
	opts        Options
	ctx         context.Context
	cancel      context.CancelFunc
	workers     sync.WaitGroup
	closeOnce   sync.Once
	closeErr    error
	mu          sync.RWMutex
	security    *auth.Service
	handler     http.Handler
	operation   sync.Mutex
	httpGate    sync.RWMutex
	backupBusy  atomic.Bool
	maintenance atomic.Bool
	setupAccess *auth.Access
	setup       map[string]setupContext
	previews    map[string]restoreContext
}

func New(ctx context.Context, options Options) (*App, error) {
	if options.LocalMode && (options.Launch.PublicURL != "" || options.Launch.TrustedProxyIPs != "" || (options.Launch.Host != "" && options.Launch.Host != "127.0.0.1" && options.Launch.Host != "::1")) {
		return nil, errors.New("本地免认证模式不能使用公网监听或反向代理")
	}
	if e := platform.PrivateDir(options.DataDir); e != nil {
		return nil, e
	}
	s, e := storage.Open(filepath.Join(options.DataDir, "webui.sqlite3"), options.Key)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(ctx)
	a := &App{Store: s, opts: options, ctx: ctx, cancel: cancel, setup: map[string]setupContext{}, previews: map[string]restoreContext{}}
	fail := func(e error) (*App, error) { cancel(); s.Close(); return nil, e }
	if _, _, e = s.Load(); e != nil {
		return fail(e)
	}
	if a.setupAccess, e = auth.NewAccess("", nil); e != nil {
		return fail(e)
	}
	if _, e = auth.NewAccess(options.Launch.PublicURL, splitPeers(options.Launch.TrustedProxyIPs)); e != nil {
		return fail(e)
	}
	if a.Runtime, e = OpenRuntime(options.DataDir); e != nil {
		return fail(e)
	}
	if a.Jobs, e = NewJobs(ctx, s); e != nil {
		return fail(e)
	}
	if a.Backups, e = backup.New(s); e != nil {
		return fail(e)
	}
	_ = s.InterruptPending()
	var exists int
	e = s.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='web_auth'").Scan(&exists)
	if e != nil {
		return fail(e)
	}
	var configured int
	if exists > 0 {
		if e = s.DB.QueryRow("SELECT count(*) FROM web_auth WHERE id=1").Scan(&configured); e != nil {
			return fail(e)
		}
	}
	if options.LocalMode || configured > 0 || options.Password != "" {
		if e = a.initializeAuth(options.Password); e != nil {
			return fail(e)
		}
	}
	if !options.DisableScheduler {
		a.workers.Add(2)
		go func() {
			defer a.workers.Done()
			a.Jobs.Scheduler(ctx, func(revision int) error { _, e := a.createBackup(revision); return e })
		}()
		go func() { defer a.workers.Done(); a.Jobs.Startup(ctx, a.Runtime, a.Ready) }()
	}
	return a, nil
}
func splitPeers(value string) []string {
	out := []string{}
	for _, p := range strings.Split(value, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
func (a *App) Ready() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.security != nil && !a.maintenance.Load()
}
func (a *App) Close() error {
	a.closeOnce.Do(func() {
		a.maintenance.Store(true)
		a.cancel()
		a.Jobs.Close()
		a.workers.Wait()
		a.httpGate.Lock()
		defer a.httpGate.Unlock()
		a.Backups.Close()
		a.closeErr = a.Store.Close()
	})
	return a.closeErr
}

func (a *App) initializeAuth(password string) error {
	s, e := auth.New(a.Store.DB, auth.Options{Password: password, LocalMode: a.opts.LocalMode, PublicOrigin: a.opts.Launch.PublicURL, TrustedProxyIPs: splitPeers(a.opts.Launch.TrustedProxyIPs), Maintenance: a.maintenance.Load, SecurityBusy: a.backupBusy.Load})
	if e != nil {
		return e
	}
	mux := http.NewServeMux()
	s.Register(mux)
	a.routes(mux)
	a.security = s
	a.handler = s.Guard(mux)
	a.setup = map[string]setupContext{}
	return nil
}
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Checkin-Runtime", "go")
	if r.URL.Path == "/api/desktop/identity" && a.opts.DesktopIdentity != nil {
		a.opts.DesktopIdentity.ServeHTTP(w, r)
		return
	}
	if r.URL.Path != "/api/backups/restore" || r.Method != "POST" {
		a.httpGate.RLock()
		defer a.httpGate.RUnlock()
	}
	// Request bodies are bounded for authentication handlers as well as app routes.
	limit := int64(1024 * 1024)
	if r.URL.Path == "/api/backups/preview" {
		limit = backup.MaxBackupBytes + 8192
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	a.mu.RLock()
	h := a.handler
	a.mu.RUnlock()
	if h != nil {
		h.ServeHTTP(w, r)
		return
	}
	a.bootstrap(w, r)
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func reject(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, Document{"error": message})
}

type endpoint func(http.ResponseWriter, *http.Request) error

func handle(f endpoint) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if e := f(w, r); e != nil {
			var httpError *auth.HTTPError
			if errors.As(e, &httpError) {
				auth.WriteError(w, e)
			} else if errors.Is(e, storage.ErrConflict) {
				reject(w, 409, "配置已更新, 请重新读取")
			} else {
				reject(w, 400, e.Error())
			}
		}
	}
}
func bad(message string) error  { return &auth.HTTPError{Status: 400, Message: message} }
func busy(message string) error { return &auth.HTTPError{Status: 409, Message: message} }
func readBody(r *http.Request, allowed ...string) (Document, error) {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		return nil, bad("请求需要 JSON 数据")
	}
	var d Document
	dec := json.NewDecoder(r.Body)
	if e := dec.Decode(&d); e != nil || d == nil {
		return nil, bad("请求字段无效")
	}
	var trailing any
	if dec.Decode(&trailing) != io.EOF {
		return nil, bad("请求字段无效")
	}
	set := map[string]bool{}
	for _, k := range allowed {
		set[k] = true
	}
	for k := range d {
		if !set[k] {
			return nil, bad("请求字段无效")
		}
	}
	return d, nil
}
func revisionBody(r *http.Request, extra ...string) (Document, int, error) {
	d, e := readBody(r, append([]string{"revision"}, extra...)...)
	if e != nil {
		return nil, 0, e
	}
	revision, ok := integer(d["revision"])
	if !ok {
		return nil, 0, bad("配置版本无效")
	}
	return d, revision, nil
}

var staticPaths = map[string]string{"/": "index.html", "/status": "index.html", "/backups": "backups.html", "/security": "security.html", "/app.js": "app.js", "/backups.js": "backups.js", "/security.js": "security.js", "/passkeys.js": "passkeys.js", "/style.css": "style.css", "/favicon.ico": "favicon.svg"}

func static(w http.ResponseWriter, r *http.Request) {
	name, ok := staticPaths[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	data, e := fs.ReadFile(frontend.Files, "static/"+name)
	if e != nil {
		reject(w, 500, "页面暂时不可用")
		return
	}
	w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(name)))
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

func (a *App) routes(mux *http.ServeMux) {
	for path := range staticPaths {
		mux.HandleFunc("GET "+path, static)
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, Document{"ok": true, "runtime": "go"}) })
	mux.HandleFunc("GET /api/config", handle(func(w http.ResponseWriter, r *http.Request) error {
		result, e := a.Store.Public()
		if e != nil {
			return errors.New("配置无法读取")
		}
		migration, e := a.Store.MigrationInfo()
		if e != nil {
			return errors.New("迁移信息无法读取")
		}
		result["migration"] = migration
		writeJSON(w, 200, result)
		return nil
	}))
	mux.HandleFunc("PUT /api/config", handle(a.saveConfig))
	mux.HandleFunc("GET /api/status", handle(func(w http.ResponseWriter, r *http.Request) error {
		d, e := a.Jobs.Status()
		if e != nil {
			return errors.New("任务状态无法读取")
		}
		writeJSON(w, 200, d)
		return nil
	}))
	mux.HandleFunc("GET /api/runs", handle(func(w http.ResponseWriter, r *http.Request) error {
		d, e := a.Jobs.History()
		if e != nil {
			return errors.New("运行记录无法读取")
		}
		writeJSON(w, 200, Document{"runs": d})
		return nil
	}))
	mux.HandleFunc("POST /api/runs", handle(a.start("checkin")))
	mux.HandleFunc("POST /api/runs/stop", handle(func(w http.ResponseWriter, r *http.Request) error {
		if _, e := readBody(r); e != nil {
			return e
		}
		writeJSON(w, 200, Document{"stopping": a.Jobs.Stop()})
		return nil
	}))
	mux.HandleFunc("POST /api/accounts/resolve", handle(a.resolve))
	mux.HandleFunc("GET /api/balances", handle(func(w http.ResponseWriter, r *http.Request) error {
		d, e := a.Jobs.BalanceSnapshot()
		if e != nil {
			return errors.New("余额状态无法读取")
		}
		writeJSON(w, 200, d)
		return nil
	}))
	mux.HandleFunc("POST /api/balances/refresh", handle(a.start("balance")))
	mux.HandleFunc("GET /api/automation", handle(func(w http.ResponseWriter, r *http.Request) error {
		config, _, e := a.Store.Load()
		if e != nil {
			return errors.New("配置无法读取")
		}
		d, e := a.Store.AutomationSnapshot(config)
		if e != nil {
			return errors.New("提醒状态无法读取")
		}
		writeJSON(w, 200, d)
		return nil
	}))
	mux.HandleFunc("POST /api/automation/summary", handle(a.start("summary")))
	mux.HandleFunc("GET /api/backups", handle(a.backupStatus))
	mux.HandleFunc("POST /api/backups", handle(a.backupCreate))
	mux.HandleFunc("GET /api/backups/{backup_id}", handle(a.backupRead))
	mux.HandleFunc("POST /api/backups/preview", handle(a.backupPreview))
	mux.HandleFunc("POST /api/backups/restore", handle(a.backupRestore))
	mux.HandleFunc("GET /api/runtime", handle(a.runtimeStatus))
	mux.HandleFunc("PUT /api/runtime", handle(a.runtimeSave))
	mux.HandleFunc("POST /api/runtime/autostart", handle(a.runtimeAutostart))
	mux.HandleFunc("POST /api/runtime/shutdown", handle(a.runtimeShutdown))
}
func (a *App) saveConfig(w http.ResponseWriter, r *http.Request) error {
	if !a.operation.TryLock() {
		return busy("请等待备份操作结束后保存配置")
	}
	defer a.operation.Unlock()
	body, revision, e := revisionBody(r, "config")
	if e != nil {
		return e
	}
	config, ok := body["config"].(map[string]any)
	if !ok {
		return bad("配置字段无效")
	}
	for _, account := range list(config["accounts"]) {
		cookies := text(account["cookies"])
		if !yes(account["enabled"]) || text(account["auth_type"]) != "cookie" || cookies == storage.SecretKeep || cookies == "" {
			continue
		}
		valid := false
		for _, part := range strings.Split(cookies, ";") {
			parts := strings.SplitN(strings.TrimSpace(part), "=", 2)
			if len(parts) == 2 && parts[0] == "session" && strings.TrimSpace(parts[1]) != "" {
				valid = true
			}
		}
		if !valid {
			return bad("Cookie 缺少非空 session, 请从浏览器复制登录 Cookie")
		}
	}
	_, _, e = a.Store.Save(config, revision)
	if e != nil {
		return e
	}
	a.Jobs.Notify()
	result, e := a.Store.Public()
	if e != nil {
		return errors.New("配置已保存, 请重新读取确认")
	}
	writeJSON(w, 200, result)
	return nil
}
func (a *App) start(kind string) endpoint {
	return func(w http.ResponseWriter, r *http.Request) error {
		if !a.operation.TryLock() {
			return busy("请等待备份操作结束后运行")
		}
		defer a.operation.Unlock()
		extra := []string{}
		if kind != "summary" {
			extra = append(extra, "account_id")
		}
		body, revision, e := revisionBody(r, extra...)
		if e != nil {
			return e
		}
		id := ""
		if v, ok := body["account_id"]; ok {
			id = text(v)
			if id == "" || len(id) > 128 {
				return bad("账号 ID 无效")
			}
		}
		d, e := a.Jobs.Start(revision, kind, "manual", id)
		if e != nil {
			return busy(e.Error())
		}
		writeJSON(w, 202, Document{"run": d})
		return nil
	}
}
func (a *App) resolve(w http.ResponseWriter, r *http.Request) error {
	if !a.operation.TryLock() {
		return busy("请等待当前操作结束")
	}
	defer a.operation.Unlock()
	a.Jobs.mu.Lock()
	defer a.Jobs.mu.Unlock()
	if a.Jobs.active != 0 {
		return busy("请等待当前任务结束后解除暂停")
	}
	body, revision, e := revisionBody(r, "account_id")
	if e != nil {
		return e
	}
	config, current, e := a.Store.Load()
	if e != nil {
		return errors.New("配置无法读取")
	}
	if revision != current {
		return storage.ErrConflict
	}
	id := text(body["account_id"])
	found := false
	for _, account := range list(config["accounts"]) {
		if text(account["id"]) == id {
			found = true
		}
	}
	if !found {
		return bad("账号 ID 无效")
	}
	if e = a.Store.ClearAttention(id); e != nil {
		return errors.New("暂停状态未能更新")
	}
	writeJSON(w, 200, Document{"resolved": true})
	return nil
}

func (a *App) private(r *http.Request) bool {
	a.mu.RLock()
	s := a.security
	a.mu.RUnlock()
	if s == nil {
		return false
	}
	origin, e := s.Origin(r)
	return e == nil && s.Access.PrivateRecovery(r, origin)
}
func (a *App) runtimeStatus(w http.ResponseWriter, r *http.Request) error {
	settings := a.Runtime.Get()
	installed := false
	canManage := a.private(r)
	if canManage {
		installed, _ = platform.Autostart(a.opts.Launch, "status")
	}
	writeJSON(w, 200, Document{"runtime": "go", "platform": runtime.GOOS, "settings": settings, "desktop": a.opts.Launch.Desktop, "autostart_enabled": installed, "can_manage_autostart": canManage, "can_shutdown": canManage && a.opts.Shutdown != nil})
	return nil
}
func (a *App) runtimeSave(w http.ResponseWriter, r *http.Request) error {
	if !a.operation.TryLock() {
		return busy("请等待备份或恢复操作结束")
	}
	defer a.operation.Unlock()
	body, e := readBody(r, "revision", "run_on_startup", "startup_delay_seconds")
	if e != nil {
		return e
	}
	revision, ok := integer(body["revision"])
	delay, valid := integer(body["startup_delay_seconds"])
	enabled, boolean := body["run_on_startup"].(bool)
	if !ok || !valid || !boolean || len(body) != 3 {
		return bad("启动设置无效")
	}
	if e = a.Runtime.Save(RuntimeSettings{revision, enabled, delay}); e != nil {
		return busy(e.Error())
	}
	return a.runtimeStatus(w, r)
}
func (a *App) runtimeAutostart(w http.ResponseWriter, r *http.Request) error {
	if !a.private(r) {
		return &auth.HTTPError{Status: 403, Message: "请通过本机或 SSH 转发入口管理自启"}
	}
	body, e := readBody(r, "enabled")
	if e != nil {
		return e
	}
	enabled, ok := body["enabled"].(bool)
	if !ok || len(body) != 1 {
		return bad("自启设置无效")
	}
	action := "remove"
	if enabled {
		action = "install"
	}
	if _, e = platform.Autostart(a.opts.Launch, action); e != nil {
		return errors.New("自启设置失败, 请通过命令行检查系统权限")
	}
	return a.runtimeStatus(w, r)
}
func (a *App) runtimeShutdown(w http.ResponseWriter, r *http.Request) error {
	if !a.private(r) || a.opts.Shutdown == nil {
		return &auth.HTTPError{Status: 403, Message: "只能通过本机管理入口退出程序"}
	}
	if _, e := readBody(r); e != nil {
		return e
	}
	writeJSON(w, 202, Document{"stopping": true})
	go func() { time.Sleep(150 * time.Millisecond); a.opts.Shutdown() }()
	return nil
}

func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func (a *App) bootstrap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; connect-src 'self'")
	if r.URL.Path == "/healthz" && r.Method == "GET" {
		writeJSON(w, 200, Document{"ok": true, "setup_required": true, "runtime": "go"})
		return
	}
	origin, e := a.setupAccess.Origin(r)
	host, _, peerErr := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if e != nil || peerErr != nil || ip == nil || !ip.IsLoopback() || !a.setupAccess.PrivateRecovery(r, origin) {
		reject(w, 403, "请先通过本机或 SSH 转发入口设置管理密码")
		return
	}
	if r.Method == "GET" {
		if _, ok := staticPaths[r.URL.Path]; ok {
			static(w, r)
			return
		}
	}
	if r.URL.Path == "/api/session" && r.Method == "GET" {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.handler != nil {
			writeJSON(w, 200, Document{"authenticated": false})
			return
		}
		for key, value := range a.setup {
			if time.Now().After(value.expires) {
				delete(a.setup, key)
			}
		}
		if len(a.setup) >= 16 {
			reject(w, 429, "初始化请求过多, 请稍后重试")
			return
		}
		s := setupContext{token: token(), csrf: token(), origin: origin, expires: time.Now().Add(10 * time.Minute)}
		a.setup[s.token] = s
		http.SetCookie(w, &http.Cookie{Name: "checkin_setup", Value: s.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 600})
		writeJSON(w, 200, Document{"authenticated": false, "setup_required": true, "setup_csrf": s.csrf, "password_login_allowed": true, "auth_mode": "password"})
		return
	}
	if r.URL.Path != "/api/setup" || r.Method != "POST" {
		reject(w, 401, "请先设置管理密码")
		return
	}
	if r.Header.Get("Origin") != origin {
		reject(w, 403, "请求来源不匹配")
		return
	}
	body, e := readBody(r, "password", "confirm_password")
	if e != nil {
		reject(w, 400, "初始化字段无效")
		return
	}
	password := text(body["password"])
	if password != text(body["confirm_password"]) || len([]rune(password)) < 16 || len([]rune(password)) > 512 {
		reject(w, 400, "请设置 16 至 512 字符的密码, 并确认两次输入相同")
		return
	}
	cookie, e := r.Cookie("checkin_setup")
	if e != nil {
		reject(w, 403, "初始化页面已失效, 请刷新")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.setup[cookie.Value]
	if !ok || s.origin != origin || time.Now().After(s.expires) || subtle.ConstantTimeCompare([]byte(s.csrf), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
		reject(w, 403, "初始化页面已失效, 请刷新")
		return
	}
	if a.security != nil {
		reject(w, 409, "管理员已配置, 请重新登录")
		return
	}
	if e = a.initializeAuth(password); e != nil {
		reject(w, 500, "初始化未完成, 请检查本机日志")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "checkin_setup", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	writeJSON(w, 201, Document{"configured": true})
}
