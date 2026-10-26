package app

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/checkin"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/storage"
)

const testPassword = "local-test-password-only"

func fixture(t *testing.T, configured bool) (*App, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	password := ""
	if configured {
		password = testPassword
	}
	a, e := New(context.Background(), Options{DataDir: dir, Key: bytes.Repeat([]byte{42}, 32), Password: password, DisableScheduler: true, Launch: platform.Launch{Executable: filepath.Join(dir, "checkin.exe"), DataDir: dir, KeyFile: filepath.Join(dir, "master.key"), Host: "127.0.0.1", Port: 18765}})
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewServer(a)
	t.Cleanup(func() { server.Close(); a.Close() })
	return a, server
}
func request(t *testing.T, a *App, method, path string, body any, cookies []*http.Cookie, csrf string) (int, Document, *httptest.ResponseRecorder) {
	t.Helper()
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	r := httptest.NewRequest(method, "http://127.0.0.1:18765"+path, bytes.NewReader(raw))
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://127.0.0.1:18765")
	if csrf != "" {
		r.Header.Set("X-CSRF-Token", csrf)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	var d Document
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	return w.Code, d, w
}
func login(t *testing.T, a *App) ([]*http.Cookie, string) {
	t.Helper()
	code, d, w := request(t, a, "POST", "/api/login", Document{"password": testPassword}, nil, "")
	if code != 200 {
		t.Fatalf("login %d %s", code, w.Body.String())
	}
	return w.Result().Cookies(), text(d["csrf"])
}
func accountConfig(t *testing.T, a *App) (Document, int) {
	t.Helper()
	config, revision, e := a.Store.Load()
	if e != nil {
		t.Fatal(e)
	}
	config["monitoring"].(map[string]any)["enabled"] = false
	config["accounts"] = []any{Document{"id": "primary", "name": "测试账户", "provider": "anyrouter", "auth_type": "password", "enabled": true, "username": "fixture-user", "password": "fixture-account-password"}}
	_, revision, e = a.Store.Save(config, revision)
	if e != nil {
		t.Fatal(e)
	}
	config, revision, e = a.Store.Load()
	if e != nil {
		t.Fatal(e)
	}
	return config, revision
}
func waitJob(t *testing.T, j *Jobs) {
	t.Helper()
	limit := time.Now().Add(5 * time.Second)
	for j.Running() {
		if time.Now().After(limit) {
			t.Fatal("job did not stop")
		}
		time.Sleep(time.Millisecond * 5)
	}
}
func success(a Document) Document {
	return Document{"id": a["id"], "name": a["name"], "provider": a["provider"], "success": true, "outcome": "success", "reason": "checkin_verified", "steps": []any{}}
}

func TestFirstSetupIsLocalOriginAndSingleUse(t *testing.T) {
	a, _ := fixture(t, false)
	code, session, w := request(t, a, "GET", "/api/session", nil, nil, "")
	if code != 200 || !yes(session["setup_required"]) {
		t.Fatal(code, session)
	}
	cookies := w.Result().Cookies()
	code, _, _ = request(t, a, "POST", "/api/setup", Document{"password": testPassword, "confirm_password": testPassword}, cookies, "wrong")
	if code != 403 {
		t.Fatal("missing setup csrf accepted", code)
	}
	code, _, _ = request(t, a, "POST", "/api/setup", Document{"password": testPassword, "confirm_password": testPassword}, cookies, text(session["setup_csrf"]))
	if code != 201 {
		t.Fatal("setup failed", code)
	}
	code, _, _ = request(t, a, "POST", "/api/setup", Document{"password": "overwrite-password", "confirm_password": "overwrite-password"}, cookies, text(session["setup_csrf"]))
	if code < 400 {
		t.Fatal("setup reused", code)
	}
	login(t, a)
}
func TestBootstrapRejectsRemoteForwardedAndCrossOrigin(t *testing.T) {
	a, _ := fixture(t, false)
	for _, change := range []func(*http.Request){func(r *http.Request) { r.RemoteAddr = "192.0.2.1:123" }, func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") }, func(r *http.Request) { r.Host = "untrusted.example" }} {
		r := httptest.NewRequest("GET", "http://127.0.0.1:18765/api/session", nil)
		r.RemoteAddr = "127.0.0.1:123"
		change(r)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal("nonprivate bootstrap accepted", w.Code)
		}
	}
}
func TestAppAPIContractSecretsAndRuntimeCAS(t *testing.T) {
	a, _ := fixture(t, true)
	cookies, csrf := login(t, a)
	config, revision := accountConfig(t, a)
	code, pub, _ := request(t, a, "GET", "/api/config", nil, cookies, csrf)
	if code != 200 || text(list(object(pub["config"])["accounts"])[0]["password"]) != storage.SecretKeep {
		t.Fatal(pub)
	}
	code, _, _ = request(t, a, "PUT", "/api/config", Document{"config": storage.Redact(config), "revision": revision - 1}, cookies, csrf)
	if code != 409 {
		t.Fatal("CAS accepted", code)
	}
	for _, path := range []string{"/api/status", "/api/runs", "/api/balances", "/api/automation", "/api/backups", "/api/runtime"} {
		code, d, w := request(t, a, "GET", path, nil, cookies, csrf)
		if code != 200 {
			t.Fatalf("%s %d %s", path, code, w.Body.String())
		}
		raw, _ := json.Marshal(d)
		if bytes.Contains(raw, []byte("fixture-account-password")) {
			t.Fatal("secret escaped", path)
		}
	}
	code, settings, _ := request(t, a, "GET", "/api/runtime", nil, cookies, csrf)
	if code != 200 {
		t.Fatal(settings)
	}
	body := Document{"revision": object(settings["settings"])["revision"], "run_on_startup": false, "startup_delay_seconds": 3}
	code, _, _ = request(t, a, "PUT", "/api/runtime", body, cookies, "wrong")
	if code != 403 {
		t.Fatal("runtime accepted wrong csrf")
	}
	code, _, _ = request(t, a, "PUT", "/api/runtime", body, cookies, csrf)
	if code != 200 {
		t.Fatal("runtime save failed", code)
	}
	code, _, _ = request(t, a, "PUT", "/api/runtime", body, cookies, csrf)
	if code != 409 {
		t.Fatal("runtime lost CAS", code)
	}
	if a.Runtime.Get().RunOnStartup {
		t.Fatal("runtime setting not saved")
	}
	reloaded, e := OpenRuntime(a.Store.DataDir)
	if e != nil || reloaded.Get().RunOnStartup {
		t.Fatal("runtime not persistent", e)
	}
	if _, after, e := a.Store.Load(); e != nil || after != revision {
		t.Fatal("runtime changed account configuration")
	}
}

func TestSingleAccountAndStartupDedupRespectBinding(t *testing.T) {
	a, _ := fixture(t, true)
	config, revision := accountConfig(t, a)
	var calls atomic.Int32
	a.Jobs.startupNetwork = func(context.Context, Document, Document) bool { return true }
	a.Jobs.executeAccount = func(_ context.Context, account, config Document, _ string, report func(Document)) (Document, []Document, Document) {
		calls.Add(1)
		report(Document{"stage": "verify_account"})
		return success(account), nil, nil
	}
	if _, e := a.Jobs.Start(revision, "checkin", "manual", "primary"); e != nil {
		t.Fatal(e)
	}
	waitJob(t, a.Jobs)
	if _, e := a.Jobs.Start(revision, "checkin", "startup", ""); e != nil {
		t.Fatal(e)
	}
	waitJob(t, a.Jobs)
	if calls.Load() != 1 {
		t.Fatal("startup duplicated confirmed checkin", calls.Load())
	}
	history, e := a.Jobs.History()
	if e != nil || text(list(object(history[0]["summary"])["accounts"])[0]["reason"]) != "startup_already_checked_in" {
		t.Fatal(history, e)
	}
	list(config["accounts"])[0]["password"] = "changed-fixture-password"
	_, revision, e = a.Store.Save(config, revision)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.Jobs.Start(revision, "checkin", "startup", ""); e != nil {
		t.Fatal(e)
	}
	waitJob(t, a.Jobs)
	if calls.Load() != 2 {
		t.Fatal("new credentials inherited old successful checkin", calls.Load())
	}
}
func TestUncertainAndRateLimitedAccountsNeverExecuteAtStartup(t *testing.T) {
	a, _ := fixture(t, true)
	config, revision := accountConfig(t, a)
	account := list(config["accounts"])[0]
	var calls atomic.Int32
	a.Jobs.startupNetwork = func(context.Context, Document, Document) bool { return true }
	a.Jobs.executeAccount = func(context.Context, Document, Document, string, func(Document)) (Document, []Document, Document) {
		calls.Add(1)
		return nil, nil, nil
	}
	for _, outcome := range []string{"uncertain", "rate_limited", "blocked", "needs_credentials"} {
		if e := a.Store.RecordAttention("primary", checkin.AccountBinding(account, config), Document{"outcome": outcome, "reason": "fixture-paused", "retry_after_seconds": 3600}); e != nil {
			t.Fatal(e)
		}
		if _, e := a.Jobs.Start(revision, "checkin", "startup", ""); e != nil {
			t.Fatal(e)
		}
		waitJob(t, a.Jobs)
	}
	if calls.Load() != 0 {
		t.Fatal("paused account executed")
	}
}
func TestCancellationNeverLeaksProgressSecretsAndPausesWrites(t *testing.T) {
	a, _ := fixture(t, true)
	config, revision := accountConfig(t, a)
	started := make(chan struct{})
	a.Jobs.executeAccount = func(ctx context.Context, account, config Document, kind string, report func(Document)) (Document, []Document, Document) {
		report(Document{"stage": "checkin", "password": "must-never-escape"})
		close(started)
		<-ctx.Done()
		return Document{"id": account["id"], "success": false, "outcome": "uncertain", "reason": "request_cancelled"}, nil, nil
	}
	if _, e := a.Jobs.Start(revision, "checkin", "manual", ""); e != nil {
		t.Fatal(e)
	}
	<-started
	if _, e := a.Jobs.Start(revision, "checkin", "manual", ""); e == nil {
		t.Fatal("parallel job accepted")
	}
	history, e := a.Jobs.History()
	raw, _ := json.Marshal(history)
	if e != nil || bytes.Contains(raw, []byte("must-never-escape")) || bytes.Contains(raw, []byte("fixture-account-password")) {
		t.Fatal("unsafe progress", e)
	}
	if !a.Jobs.Stop() {
		t.Fatal("stop failed")
	}
	waitJob(t, a.Jobs)
	pending, e := a.Store.Attention("primary", checkin.AccountBinding(list(config["accounts"])[0], config))
	if e != nil || text(pending["outcome"]) != "uncertain" {
		t.Fatal(pending, e)
	}
}
func TestBalanceFailureCannotUndoCheckinSuccess(t *testing.T) {
	a, _ := fixture(t, true)
	config, revision := accountConfig(t, a)
	object(config["monitoring"])["enabled"] = true
	_, revision, e := a.Store.Save(config, revision)
	if e != nil {
		t.Fatal(e)
	}
	a.Jobs.executeAccount = func(_ context.Context, account, config Document, _ string, _ func(Document)) (Document, []Document, Document) {
		return success(account), nil, Document{"success": false, "outcome": "failed", "reason": "balance_collection_failed"}
	}
	if _, e = a.Jobs.Start(revision, "checkin", "manual", ""); e != nil {
		t.Fatal(e)
	}
	waitJob(t, a.Jobs)
	history, e := a.Jobs.History()
	if e != nil || text(history[0]["state"]) != "succeeded" {
		t.Fatal(history, e)
	}
}
func TestRuntimeDefaultsAndBootTaskRunsOnce(t *testing.T) {
	a, _ := fixture(t, true)
	_, revision := accountConfig(t, a)
	settings := a.Runtime.Get()
	settings.StartupDelaySeconds = 0
	if e := a.Runtime.Save(settings); e != nil {
		t.Fatal(e)
	}
	var calls atomic.Int32
	a.Jobs.startupNetwork = func(context.Context, Document, Document) bool { return true }
	a.Jobs.executeAccount = func(_ context.Context, account, config Document, _ string, _ func(Document)) (Document, []Document, Document) {
		calls.Add(1)
		return success(account), nil, nil
	}
	a.Jobs.Startup(context.Background(), a.Runtime, func() bool { return true })
	waitJob(t, a.Jobs)
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
	_ = revision
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	a.Jobs.Startup(ctx, a.Runtime, func() bool { return true })
	waitJob(t, a.Jobs)
	if calls.Load() != 1 {
		t.Fatal("cancelled startup triggered checkin")
	}
}

func TestBackupRestoreIsAtomicAndKeepsCurrentAuth(t *testing.T) {
	a, _ := fixture(t, true)
	cookies, csrf := login(t, a)
	config, revision := accountConfig(t, a)
	object(config["backups"])["password"] = "fixture-backup-password"
	_, revision, e := a.Store.Save(config, revision)
	if e != nil {
		t.Fatal(e)
	}
	code, result, w := request(t, a, "POST", "/api/backups", Document{"revision": revision}, cookies, csrf)
	if code != 201 {
		t.Fatalf("backup %d %s", code, w.Body.String())
	}
	id := text(object(result["backup"])["id"])
	path, e := a.Backups.Read(id)
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	_ = writer.WriteField("revision", strconvForTest(revision))
	_ = writer.WriteField("password", "fixture-backup-password")
	part, _ := writer.CreateFormFile("file", "backup.nab")
	_, _ = part.Write(data)
	writer.Close()
	r := httptest.NewRequest("POST", "http://127.0.0.1:18765/api/backups/preview", &body)
	r.RemoteAddr = "127.0.0.1:123"
	r.Header.Set("Origin", "http://127.0.0.1:18765")
	r.Header.Set("Content-Type", writer.FormDataContentType())
	r.Header.Set("X-CSRF-Token", csrf)
	for _, c := range cookies {
		r.AddCookie(c)
	}
	w = httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("preview %d %s", w.Code, w.Body.String())
	}
	var preview Document
	json.Unmarshal(w.Body.Bytes(), &preview)
	code, _, w = request(t, a, "POST", "/api/backups/restore", Document{"revision": revision, "ticket": preview["ticket"], "admin_password": testPassword}, cookies, csrf)
	if code != 200 {
		t.Fatalf("restore %d %s", code, w.Body.String())
	}
	if a.Runtime.Get().RunOnStartup {
		t.Fatal("restore kept startup enabled")
	}
	code, _, _ = request(t, a, "GET", "/api/config", nil, cookies, csrf)
	if code != 401 {
		t.Fatal("restore did not revoke session")
	}
	login(t, a)
	config, _, e = a.Store.Load()
	if e != nil || yes(object(config["schedule"])["enabled"]) || yes(object(config["monitoring"])["enabled"]) {
		t.Fatal("restore kept automation enabled", e)
	}
}
func strconvForTest(v int) string { raw, _ := json.Marshal(v); return string(raw) }

func TestNoStartupRunWithNoAccounts(t *testing.T) {
	a, _ := fixture(t, true)
	s := a.Runtime.Get()
	s.StartupDelaySeconds = 0
	if e := a.Runtime.Save(s); e != nil {
		t.Fatal(e)
	}
	a.Jobs.Startup(context.Background(), a.Runtime, func() bool { return true })
	history, e := a.Jobs.History()
	if e != nil || len(history) != 0 {
		t.Fatal(history, e)
	}
}
func TestStaticEmbeddedAndNoTraversal(t *testing.T) {
	a, _ := fixture(t, true)
	for _, path := range []string{"/", "/status", "/backups", "/security", "/app.js", "/style.css", "/logo.png", "/favicon.ico"} {
		code, _, w := request(t, a, "GET", path, nil, nil, "")
		if code != 200 || w.Body.Len() == 0 {
			t.Fatal(path, code)
		}
		if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src") {
			t.Fatal("CSP absent")
		}
		if path == "/logo.png" || path == "/favicon.ico" {
			if w.Header().Get("Content-Type") != "image/png" || !bytes.HasPrefix(w.Body.Bytes(), []byte("\x89PNG\r\n\x1a\n")) {
				t.Fatal("logo is not served as PNG", path)
			}
		}
	}
	code, _, _ := request(t, a, "GET", "/server/app.py", nil, nil, "")
	if code == 200 {
		t.Fatal("filesystem exposed")
	}
}
