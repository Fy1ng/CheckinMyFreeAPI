package app

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
)

func localNoAuthFixture(t *testing.T) *App {
	t.Helper()
	data := t.TempDir()
	a, err := New(context.Background(), Options{DataDir: data, Key: bytes.Repeat([]byte{73}, 32), LocalMode: true, DisableScheduler: true, Launch: platform.Launch{Executable: os.Args[0], DataDir: data, KeyFile: filepath.Join(data, "master.key"), Host: "127.0.0.1", Port: 18765, Desktop: true}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	return a
}

func TestLocalBackupRestoreRequiresNoAdminProofAndKeepsSessionProtection(t *testing.T) {
	a := localNoAuthFixture(t)
	status, session, _ := request(t, a, "GET", "/api/session", nil, nil, "")
	if status != 200 || !yes(session["authenticated"]) || !yes(session["local_mode"]) {
		t.Fatal(status, session)
	}
	csrf := text(session["csrf"])
	config, revision, err := a.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	object(config["backups"])["password"] = "synthetic-local-backup-password"
	_, revision, err = a.Store.Save(config, revision)
	if err != nil {
		t.Fatal(err)
	}
	result, err := a.createBackup(revision)
	if err != nil {
		t.Fatal(err)
	}
	path, err := a.Backups.Read(text(result["id"]))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := a.Backups.Preview(data, "synthetic-local-backup-password", revision)
	if err != nil {
		t.Fatal(err)
	}
	ticket := text(preview["ticket"])
	// HTTP preview normally stores the request's origin/CSRF binding.
	r := httptest.NewRequest("GET", "http://127.0.0.1:18765/api/session", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	a.previews[ticket] = restoreContext{"synthetic-local-backup-password", a.sessionBinding(r), time.Now().Add(time.Minute)}
	status, _, _ = request(t, a, "POST", "/api/backups/restore", Document{"revision": revision, "ticket": ticket}, nil, "")
	if status != 403 {
		t.Fatal("local restore accepted missing CSRF", status)
	}
	status, response, w := request(t, a, "POST", "/api/backups/restore", Document{"revision": revision, "ticket": ticket}, nil, csrf)
	if status != 200 || !yes(response["authenticated"]) || !yes(response["restored"]) {
		t.Fatal(status, w.Body.String())
	}
	status, renewed, _ := request(t, a, "GET", "/api/session", nil, nil, "")
	if status != 200 || !yes(renewed["authenticated"]) || text(renewed["csrf"]) == csrf {
		t.Fatal("local session did not transparently renew after restore", renewed)
	}
	if a.Runtime.Get().RunOnStartup {
		t.Fatal("restore kept startup enabled")
	}
}

func TestLocalNoAuthWebUIRealBrowser(t *testing.T) {
	if os.Getenv("CHECKIN_LOCAL_BROWSER_TESTS") != "1" {
		t.Skip("opt-in isolated local no-auth browser acceptance")
	}
	a := localNoAuthFixture(t)
	server := httptest.NewServer(a)
	defer server.Close()
	python := filepath.Join("..", "..", ".venv", "Scripts", "python.exe")
	if _, err := exec.LookPath(python); err != nil {
		python = filepath.Join("..", "..", ".venv", "bin", "python")
	}
	command := exec.Command(python, "local_noauth_fixture_test.py", server.URL)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("local no-auth browser acceptance: %v\n%s", err, output)
	}
	t.Log(string(output))
	var runs int
	if err = a.Store.DB.QueryRow("SELECT count(*) FROM runs").Scan(&runs); err != nil || runs != 0 {
		t.Fatal("UI validation ran account or notification tasks", runs, err)
	}
	config, _, err := a.Store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if yes(object(config["monitoring"])["enabled"]) {
		t.Fatal("restore should disable monitoring")
	}
	accounts := list(config["accounts"])
	if len(accounts) != 1 || text(accounts[0]["name"]) != "Local snapshot" {
		raw, _ := json.Marshal(config)
		t.Fatalf("snapshot was not restored: %s", raw)
	}
}
