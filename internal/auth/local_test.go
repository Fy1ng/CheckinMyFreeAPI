package auth

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const localOrigin = "http://localhost:18765"

func localService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "local.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	s, err := New(db, Options{LocalMode: true})
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}
func localRequest(t *testing.T, s *Service, method, path string, payload any, csrf string, modify func(*http.Request)) *httptest.ResponseRecorder {
	t.Helper()
	data, _ := json.Marshal(payload)
	request := httptest.NewRequest(method, localOrigin+path, bytes.NewReader(data))
	request.RemoteAddr = "127.0.0.1:4567"
	request.Header.Set("Origin", localOrigin)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	if modify != nil {
		modify(request)
	}
	mux := http.NewServeMux()
	s.Register(mux)
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	mux.HandleFunc("PUT /api/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"saved": true}) })
	w := httptest.NewRecorder()
	s.Guard(mux).ServeHTTP(w, request)
	return w
}
func localCSRF(t *testing.T, s *Service) string {
	t.Helper()
	w := localRequest(t, s, "GET", "/api/session", nil, "", nil)
	if w.Code != 200 {
		t.Fatalf("local session %d %s", w.Code, w.Body.String())
	}
	value := decodeResponse(t, w)
	csrf, _ := value["csrf"].(string)
	if value["authenticated"] != true || value["local_mode"] != true || value["auth_mode"] != "local" || value["reauth_method"] != "none" || value["password_login_allowed"] != false || value["passkey_available"] != false || csrf == "" {
		t.Fatal("invalid local session policy", value)
	}
	if len(w.Result().Cookies()) != 0 {
		t.Fatal("local session unexpectedly requires a login cookie")
	}
	return csrf
}

func TestLocalModeOpensWithoutPasswordAndKeepsInvisibleRequestProtection(t *testing.T) {
	s, db := localService(t)
	if !s.LocalMode() {
		t.Fatal("local startup policy missing")
	}
	csrf := localCSRF(t, s)
	var count int
	if err := db.QueryRow("SELECT count(*) FROM web_auth WHERE length(salt)=16 AND length(digest)=64").Scan(&count); err != nil || count != 1 {
		t.Fatal("backup-compatible password row missing", count, err)
	}
	for _, path := range []string{"/api/config", "/api/security"} {
		w := localRequest(t, s, "GET", path, nil, "", nil)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	for _, token := range []string{"", "wrong"} {
		w := localRequest(t, s, "PUT", "/api/config", map[string]any{}, token, nil)
		if w.Code != 403 {
			t.Fatal("local mutation accepted missing or invalid CSRF", w.Code)
		}
	}
	w := localRequest(t, s, "PUT", "/api/config", map[string]any{}, csrf, nil)
	if w.Code != 200 {
		t.Fatal("valid local mutation rejected", w.Code, w.Body.String())
	}
	if second := localCSRF(t, s); csrf != second {
		t.Fatal("local session expired between reads")
	}
}

func TestLocalModeRejectsProxyRemoteAndCrossSiteRequests(t *testing.T) {
	s, _ := localService(t)
	csrf := localCSRF(t, s)
	for _, entry := range []struct {
		name   string
		change func(*http.Request)
	}{
		{"remote-peer", func(r *http.Request) { r.RemoteAddr = "192.0.2.1:4567" }},
		{"public-host", func(r *http.Request) { r.Host = "private.example.test" }},
		{"lookalike-localhost", func(r *http.Request) { r.Host = "localhost.evil.test:18765" }},
		{"forwarded", func(r *http.Request) { r.Header.Set("Forwarded", "for=127.0.0.1") }},
		{"forwarded-for", func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") }},
		{"forwarded-host", func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "localhost:18765") }},
		{"forwarded-proto", func(r *http.Request) { r.Header.Set("X-Forwarded-Proto", "http") }},
		{"cross-origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example.test") }},
		{"null-origin", func(r *http.Request) { r.Header.Set("Origin", "null") }},
		{"duplicate-origin", func(r *http.Request) { r.Header.Add("Origin", localOrigin) }},
		{"cross-site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }},
		{"same-site-different-origin", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") }},
	} {
		t.Run(entry.name, func(t *testing.T) {
			for _, method := range []string{"GET", "PUT"} {
				w := localRequest(t, s, method, "/api/config", nil, csrf, entry.change)
				if w.Code != 403 {
					t.Fatalf("%s %s accepted: %d %s", entry.name, method, w.Code, w.Body.String())
				}
			}
		})
	}
	w := localRequest(t, s, "PUT", "/api/config", nil, csrf, func(r *http.Request) { r.Header.Del("Origin") })
	if w.Code != 403 {
		t.Fatal("write without origin accepted")
	}
}

func TestLocalModeCSRFIsBoundToOriginRevisionAndLifecycle(t *testing.T) {
	s, db := localService(t)
	first := localCSRF(t, s)
	other := localRequest(t, s, "PUT", "/api/config", nil, first, func(r *http.Request) { r.Host = "127.0.0.1:18765"; r.Header.Set("Origin", "http://127.0.0.1:18765") })
	if other.Code != 403 {
		t.Fatal("CSRF token transferred between origins")
	}
	s.Invalidate()
	second := localCSRF(t, s)
	if first == second {
		t.Fatal("invalidate did not rotate local session")
	}
	if w := localRequest(t, s, "PUT", "/api/config", nil, first, nil); w.Code != 403 {
		t.Fatal("invalidated local CSRF accepted")
	}
	if _, err := db.Exec("UPDATE web_security SET revision=revision+1"); err != nil {
		t.Fatal(err)
	}
	third := localCSRF(t, s)
	if third == second {
		t.Fatal("security revision did not replace local CSRF")
	}
	if w := localRequest(t, s, "PUT", "/api/config", nil, second, nil); w.Code != 403 {
		t.Fatal("stale restored CSRF accepted")
	}
	otherService, err := New(db, Options{LocalMode: true})
	if err != nil {
		t.Fatal(err)
	}
	if localCSRF(t, otherService) == third {
		t.Fatal("CSRF survived local service restart")
	}
}

func TestLocalModeCannotBeCombinedWithPublicOrProxyConfiguration(t *testing.T) {
	s, db := localService(t)
	_ = s
	for _, options := range []Options{{LocalMode: true, PublicOrigin: testOrigin}, {LocalMode: true, TrustedProxyIPs: []string{"127.0.0.1"}}, {LocalMode: true, TrustedProxyIPs: []string{""}}} {
		if _, err := New(db, options); err == nil {
			t.Fatal("local mode accepted public or proxy configuration")
		}
	}
}

func TestLocalModeDisablesIdentityMutationAndProofIssuance(t *testing.T) {
	s, _ := localService(t)
	csrf := localCSRF(t, s)
	for _, path := range []string{"/api/login", "/api/logout", "/api/passkey/login/options", "/api/passkey/login/verify", "/api/security/reauth", "/api/security/reauth/options", "/api/security/reauth/verify", "/api/security/register/options", "/api/security/register/verify", "/api/security/mode"} {
		w := localRequest(t, s, "POST", path, map[string]any{}, csrf, nil)
		if w.Code != 403 {
			t.Fatal("local identity operation enabled", path, w.Code)
		}
	}
	w := localRequest(t, s, "DELETE", "/api/security/passkeys/fake-key", map[string]any{}, csrf, nil)
	if w.Code != 403 {
		t.Fatal("local mode enabled passkey deletion", w.Code)
	}
	r := httptest.NewRequest("POST", localOrigin+"/api/config", nil)
	r.RemoteAddr = "127.0.0.1:4567"
	r.Header.Set("Origin", localOrigin)
	if _, err := s.issueProof(r, "password", ""); err == nil {
		t.Fatal("local proof issued")
	}
	if _, err := s.ConsumeReauth(r, "ignored", false); err == nil {
		t.Fatal("local proof accepted")
	}
	if err := s.Reauthenticate(r, "ignored"); err == nil {
		t.Fatal("local reauth fell back to password verification")
	}
}

func authSnapshot(t *testing.T, db *sql.DB) []byte {
	t.Helper()
	all := map[string][][]any{}
	for _, table := range []string{"web_auth", "web_security", "web_passkeys"} {
		rows, err := db.Query("SELECT * FROM " + table + " ORDER BY id")
		if err != nil {
			t.Fatal(err)
		}
		columns, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		records := [][]any{}
		for rows.Next() {
			record := make([]any, len(columns))
			targets := make([]any, len(columns))
			for index := range record {
				targets[index] = &record[index]
			}
			if err = rows.Scan(targets...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			records = append(records, record)
		}
		if err = rows.Err(); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		rows.Close()
		all[table] = records
	}
	raw, err := json.Marshal(all)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLocalModePreservesExistingPasswordPasskeyAndSecurityMode(t *testing.T) {
	server, db := newService(t)
	device := newDevice(t)
	registerDevice(t, server, device)
	if _, err := db.Exec("UPDATE web_security SET mode='passkey',revision=revision+1; UPDATE web_passkeys SET verified=1,counter=7"); err != nil {
		t.Fatal(err)
	}
	before := authSnapshot(t, db)
	local, err := New(db, Options{LocalMode: true, Password: "must-not-replace-existing-password"})
	if err != nil {
		t.Fatal(err)
	}
	csrf := localCSRF(t, local)
	for _, path := range []string{"/api/security/mode", "/api/security/register/verify", "/api/logout"} {
		_ = localRequest(t, local, "POST", path, map[string]any{}, csrf, nil)
	}
	if after := authSnapshot(t, db); !bytes.Equal(before, after) {
		t.Fatal("local mode changed persisted administrator security")
	}
	state := decodeResponse(t, localRequest(t, local, "GET", "/api/security", nil, "", nil))
	if state["mode"] != "local" || state["can_register"] != false {
		t.Fatal(state)
	}
	protected, err := New(db, Options{PublicOrigin: testOrigin, TrustedProxyIPs: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	if protected.LocalMode() {
		t.Fatal("local mode persisted into server policy")
	}
	if w := authRequest(t, protected, "POST", "/api/login", map[string]any{"password": testPassword}, nil, ""); w.Code != 403 {
		t.Fatal("server passkey mode downgraded by local use")
	}
}

func TestServerModeDoesNotAcceptLocalSessionOrRequestFlags(t *testing.T) {
	s, db := localService(t)
	csrf := localCSRF(t, s)
	server, err := New(db, Options{})
	if err != nil {
		t.Fatal(err)
	}
	w := localRequest(t, server, "GET", "/api/config", nil, csrf, func(r *http.Request) { r.Header.Set("X-Checkin-Local", "true"); r.Header.Set("X-Local-Mode", "true") })
	if w.Code != 401 {
		t.Fatal("local request flags bypassed server login", w.Code)
	}
	state := decodeResponse(t, localRequest(t, server, "GET", "/api/session", nil, "", nil))
	if state["authenticated"] != false || state["password_login_allowed"] != true || state["local_mode"] == true {
		t.Fatal(state)
	}
	// Empty local instances keep only a hash of an unpredictable placeholder;
	// neither this synthetic attempted password nor local CSRF can log into a server.
	w = localRequest(t, server, "POST", "/api/login", map[string]any{"password": "unknown-local-placeholder"}, "", nil)
	if w.Code != 401 {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), csrf) {
		t.Fatal("local capability leaked in server response")
	}
}
