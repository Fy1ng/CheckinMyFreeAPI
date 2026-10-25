package app

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/storage"
)

// Browser plugin not available. This opt-in integration test uses disposable Go
// application databases and Chrome profiles. No account or notification job runs.
func TestStandaloneGoWebUIRealBrowser(t *testing.T) {
	if os.Getenv("CHECKIN_GO_BROWSER_TESTS") != "1" {
		t.Skip("opt-in full Go application browser acceptance")
	}
	newFixture := func(public bool) (*App, *httptest.Server) {
		t.Helper()
		data := t.TempDir()
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		launch := platform.Launch{Executable: os.Args[0], DataDir: data, KeyFile: filepath.Join(data, "synthetic-master.key"), Host: "127.0.0.1", Port: 18765}
		password := ""
		if public {
			password = "synthetic-Go-app-browser-password"
			launch.PublicURL = "https://go-app.example.test"
			launch.TrustedProxyIPs = "127.0.0.1"
		}
		a, err := New(context.Background(), Options{DataDir: data, Key: key, Password: password, Launch: launch, DisableScheduler: true})
		if err != nil {
			t.Fatal(err)
		}
		if !public {
			// A genuine encrypted archive exercises the retained migration notice.
			config, _, err := a.Store.Load()
			if err != nil {
				t.Fatal(err)
			}
			plain, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			encrypted, err := storage.Encrypt(key, plain, []byte(storage.ConfigAAD+"0"))
			if err != nil {
				t.Fatal(err)
			}
			metadata := `{"from_schema":1,"source_revision":0,"converted_accounts":0,"disabled_accounts":0,"omitted_accounts":0,"schedule_disabled":false}`
			if _, err = a.Store.DB.Exec("INSERT INTO config_archive(source_revision,document,migration) VALUES(0,?,?)", encrypted, metadata); err != nil {
				t.Fatal(err)
			}
		}
		server := httptest.NewServer(a)
		t.Cleanup(func() {
			server.Close()
			if err := a.Close(); err != nil {
				t.Error(err)
			}
		})
		return a, server
	}
	local, localServer := newFixture(false)
	public, publicServer := newFixture(true)
	python := filepath.Join("..", "..", ".venv", "Scripts", "python.exe")
	if _, err := exec.LookPath(python); err != nil {
		python = filepath.Join("..", "..", ".venv", "bin", "python")
	}
	command := exec.Command(python, "webui_fixture_test.py", localServer.URL, publicServer.URL)
	out, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("full Go browser acceptance failed: %v\n%s", err, out)
	}
	t.Log(string(out))
	for _, a := range []*App{local, public} {
		var runs int
		if err = a.Store.DB.QueryRow("SELECT count(*) FROM runs").Scan(&runs); err != nil || runs != 0 {
			t.Fatalf("browser test must not run account or notification tasks: count=%d error=%v", runs, err)
		}
	}
	settings := local.Runtime.Get()
	if settings.RunOnStartup || settings.StartupDelaySeconds != 23 {
		t.Fatalf("runtime settings were not persisted: %+v", settings)
	}
	loaded, err := OpenRuntime(local.Store.DataDir)
	if err != nil || loaded.Get() != settings {
		t.Fatal("runtime settings did not survive reopening", err)
	}
}
