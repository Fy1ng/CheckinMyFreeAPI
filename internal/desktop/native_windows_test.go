//go:build desktop && windows

package desktop

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Browser plugin not available. This opt-in acceptance connects Playwright to
// an isolated WebView2 profile belonging to this test's temporary Wails process.
func TestNativeDesktopWebView2(t *testing.T) {
	if os.Getenv("CHECKIN_DESKTOP_NATIVE_TESTS") != "1" {
		t.Skip("opt-in disposable native Windows desktop acceptance")
	}
	root := t.TempDir()
	binary := filepath.Join(root, "desktop-fixture.exe")
	build := exec.Command("go", "build", "-tags", "desktop,desktoptest,production", "-ldflags", "-H=windowsgui", "-o", binary, "./testfixture")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, e := build.CombinedOutput(); e != nil {
		t.Fatalf("native fixture build: %v\n%s", e, output)
	}
	python := filepath.Join("..", "..", ".venv", "Scripts", "python.exe")
	command := exec.Command(python, "native_fixture.py", binary, root)
	if output, e := command.CombinedOutput(); e != nil {
		t.Fatalf("native WebView2 acceptance: %v\n%s", e, output)
	} else {
		t.Log(string(output))
	}
}
