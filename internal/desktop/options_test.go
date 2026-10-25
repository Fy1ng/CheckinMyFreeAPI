package desktop

import (
	"bytes"
	"context"
	"image/png"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestBackendOriginRestrictedToExplicitLoopback(t *testing.T) {
	for _, u := range []string{"http://localhost:8765", "http://127.0.0.1:8765/", "http://[::1]:8765"} {
		if _, e := validateURL(u); e != nil {
			t.Fatal(u, e)
		}
	}
	for _, u := range []string{"http://0.0.0.0:8765", "https://localhost:8765", "javascript:alert(1)", "http://localhost:8765/path", "http://localhost:8765?token=secret", "http://user:pass@localhost:8765", "http://localhost", "http://localhost:0", "http://localhost:65536", "http://localhost:08765", "http://127.1:8765", "http://localhost.example:8765", "http://localhost:8765/#route"} {
		if _, e := validateURL(u); e == nil {
			t.Fatal("untrusted backend accepted", u)
		}
	}
}

func TestActivationBoundedAndValidated(t *testing.T) {
	var mu sync.Mutex
	shown := []string{}
	a := activation{show: func(path string) { mu.Lock(); defer mu.Unlock(); shown = append(shown, path) }}
	a.request("/status")
	a.request("https://elsewhere.invalid")
	a.start("/", true)
	if len(shown) != 1 || shown[0] != "/status" {
		t.Fatal(shown)
	}
	a.request("/security")
	a.request("/status?token=secret")
	if len(shown) != 2 || shown[1] != "/security" {
		t.Fatal(shown)
	}
	var hidden activation
	hidden.show = func(string) { t.Fatal("hidden launch displayed a window") }
	hidden.start("/", true)
}

func TestProfileAndSingleInstanceKeyStableConcurrentAndPrivate(t *testing.T) {
	dir := t.TempDir()
	opts := Options{DataDir: dir, Start: func(context.Context) (Backend, error) { return Backend{}, nil }}
	clean, first, e := validate(opts)
	if e != nil {
		t.Fatal(e)
	}
	opts.DataDir = filepath.Join(dir, ".")
	_, second, e := validate(opts)
	if e != nil || first != second || clean.Path != "/" {
		t.Fatal("profile singleton changed", e)
	}
	const count = 10
	keys := make(chan [32]byte, count)
	errors := make(chan error, count)
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); k, e := instanceKey(dir); keys <- k; errors <- e }()
	}
	wg.Wait()
	close(keys)
	close(errors)
	for e := range errors {
		if e != nil {
			t.Fatal(e)
		}
	}
	var expected [32]byte
	for k := range keys {
		if expected == ([32]byte{}) {
			expected = k
		}
		if k != expected {
			t.Fatal("concurrent desktop keys differ")
		}
	}
	if expected == ([32]byte{}) {
		t.Fatal("zero instance key")
	}
	raw, e := os.ReadFile(filepath.Join(dir, "desktop-instance.key"))
	if e != nil || !bytes.Equal(raw, expected[:]) {
		t.Fatal("key not persisted", e)
	}
	if e = os.WriteFile(filepath.Join(dir, "desktop-instance.key"), []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = instanceKey(dir); e == nil {
		t.Fatal("invalid instance key silently regenerated")
	}
}

func TestDesktopIconIsSmallPNGWithTransparentCorners(t *testing.T) {
	icon, e := png.Decode(bytes.NewReader(appIcon()))
	if e != nil {
		t.Fatal(e)
	}
	if icon.Bounds().Dx() != 64 || icon.Bounds().Dy() != 64 {
		t.Fatal(icon.Bounds())
	}
	_, _, _, alpha := icon.At(0, 0).RGBA()
	if alpha != 0 {
		t.Fatal("icon corner is not transparent")
	}
}

func TestOptionsRejectMissingBackendBeforeNativeInitialization(t *testing.T) {
	if _, _, e := validate(Options{DataDir: t.TempDir()}); e == nil {
		t.Fatal("missing start accepted")
	}
}

func TestStartupFailureHasSafePersistentDiagnostic(t *testing.T) {
	dir := t.TempDir()
	e := startupFailure(Options{DataDir: dir, Hidden: true}, "desktop_backend_start_failed")
	if e == nil {
		t.Fatal("startup failure vanished")
	}
	raw, e := os.ReadFile(filepath.Join(dir, "desktop.log"))
	if e != nil || !bytes.Contains(raw, []byte("desktop_backend_start_failed")) {
		t.Fatal("safe startup diagnostic missing", e)
	}
}
