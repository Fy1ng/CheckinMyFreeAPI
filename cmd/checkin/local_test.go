package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
)

func TestLocalModeIsExplicitAndNeverBindsPublic(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{{"serve", "--local", "--host", "0.0.0.0"}, {"app", "--local", "--public-url", "https://admin.example.test"}, {"app", "--local", "--trusted-proxy-ips", "127.0.0.1"}} {
		if _, _, _, e := parse(append(args, "--data-dir", dir)); e == nil {
			t.Fatal("unsafe local launch accepted", args)
		}
	}
	_, _, local, e := parse([]string{"app", "--data-dir", dir})
	if e != nil || !local.launch.LocalMode {
		t.Fatal("desktop not local by default", e)
	}
	_, _, server, e := parse([]string{"serve", "--data-dir", dir})
	if e != nil || server.launch.LocalMode {
		t.Fatal("server silently lost authentication", e)
	}
	_, _, explicit, e := parse([]string{"serve", "--local", "--data-dir", dir})
	if e != nil || !explicit.launch.LocalMode || !strings.Contains(strings.Join(explicit.launch.Args(), " "), "--local") {
		t.Fatal("local runtime setting lost", e)
	}
	_, _, remote, e := parse([]string{"app", "--public-url", "https://admin.example.test", "--data-dir", dir})
	if e != nil || remote.launch.LocalMode {
		t.Fatal("public desktop origin lost authentication", e)
	}
	_, _, retained, e := parse([]string{"app", "--local=false", "--data-dir", dir})
	if e != nil || retained.launch.LocalMode || !retained.localExplicit {
		t.Fatal("explicit server authentication ignored", e)
	}
	retained.launch.Desktop = true
	if !strings.Contains(strings.Join(retained.launch.Args(), " "), "--local=false") {
		t.Fatal("explicit authentication lost on next desktop start")
	}
}

func TestLocalBackendNeedsNoSetupAndKeepsServerData(t *testing.T) {
	c := backendConfig(t)
	c.launch.LocalMode = true
	c.launch.Desktop = true
	c.passwordFile = filepath.Join(c.launch.DataDir, "nonexistent-inherited-password-file")
	backend, e := startOwnedBackend(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer backend.Stop()
	response, e := http.Get(backend.URL + "/api/session")
	if e != nil {
		t.Fatal(e)
	}
	var session map[string]any
	raw, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if json.Unmarshal(raw, &session) != nil || response.StatusCode != 200 || session["authenticated"] != true || session["auth_mode"] != "local" || session["setup_required"] == true {
		t.Fatal("local UI still requires verification", response.StatusCode, string(raw))
	}
	response, e = http.Get(backend.URL + "/api/config")
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("local account screen is locked", response.StatusCode)
	}
	var originalSalt, originalDigest []byte
	if e = backend.Application.Store.DB.QueryRow("SELECT salt,digest FROM web_auth WHERE id=1").Scan(&originalSalt, &originalDigest); e != nil {
		t.Fatal(e)
	}
	if e = backend.Stop(); e != nil {
		t.Fatal(e)
	}
	c.launch.LocalMode = false
	c.launch.Desktop = false
	c.passwordFile = ""
	server, e := startOwnedBackend(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer server.Stop()
	response, e = http.Get(server.URL + "/api/config")
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("local exemption migrated into server mode", response.StatusCode)
	}
	var salt, digest []byte
	if e = server.Application.Store.DB.QueryRow("SELECT salt,digest FROM web_auth WHERE id=1").Scan(&salt, &digest); e != nil || !bytes.Equal(salt, originalSalt) || !bytes.Equal(digest, originalDigest) {
		t.Fatal("changing runtime mode replaced stored authentication", e)
	}
}

func TestServerPasswordCanBeSetOfflineWithoutChangingPasskeyPolicy(t *testing.T) {
	c := backendConfig(t)
	c.launch.LocalMode = true
	backend, e := startOwnedBackend(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = backend.Application.Store.DB.Exec("UPDATE web_security SET mode='passkey' WHERE id=1"); e != nil {
		backend.Stop()
		t.Fatal(e)
	}
	password := []byte("new-server-admin-password-for-test")
	path := filepath.Join(c.launch.DataDir, "new-server-password")
	os.WriteFile(path, password, 0600)
	c.passwordFile = path
	c.confirm = true
	if e = setAdminPassword(c); e == nil {
		backend.Stop()
		t.Fatal("password changed while service owned data")
	}
	backend.Stop()
	c.confirm = false
	if e = setAdminPassword(c); e == nil {
		t.Fatal("offline password changed without explicit confirmation")
	}
	c.confirm = true
	if e = setAdminPassword(c); e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", filepath.Join(c.launch.DataDir, "webui.sqlite3"))
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var salt, digest []byte
	var mode string
	if e = db.QueryRow("SELECT salt,digest FROM web_auth WHERE id=1").Scan(&salt, &digest); e != nil {
		t.Fatal(e)
	}
	expected, e := scrypt.Key(password, salt, 16384, 8, 1, 64)
	if e != nil || !bytes.Equal(expected, digest) {
		t.Fatal("new password not recorded", e)
	}
	if e = db.QueryRow("SELECT mode FROM web_security WHERE id=1").Scan(&mode); e != nil || mode != "passkey" {
		t.Fatal("offline password reset downgraded passkey mode", mode, e)
	}
}
