package auth

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Browser plugin not available. This optional test uses a disposable system
// Chrome profile and a CDP virtual authenticator, never a real user credential.
func TestRealChromePasskeyWebUI(t *testing.T) {
	if os.Getenv("CHECKIN_AUTH_BROWSER_TESTS") != "1" {
		t.Skip("opt-in isolated Chrome virtual-authenticator flow")
	}
	s, _ := newService(t)
	mux := http.NewServeMux()
	s.Register(mux)
	static := filepath.Join("..", "..", "server", "static")
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Path[1:]
		if name == "security" {
			name = "security.html"
		}
		if name != "security.html" && name != "security.js" && name != "passkeys.js" && name != "style.css" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, filepath.Join(static, name))
	})
	server := httptest.NewServer(s.Guard(mux))
	defer server.Close()
	python := filepath.Join("..", "..", ".venv", "Scripts", "python.exe")
	if _, err := exec.LookPath(python); err != nil {
		python = filepath.Join("..", "..", ".venv", "bin", "python")
	}
	command := exec.Command(python, "browser_fixture.py", server.URL)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("real browser flow failed: %v\n%s", err, out)
	} else {
		t.Log(string(out))
	}
}
