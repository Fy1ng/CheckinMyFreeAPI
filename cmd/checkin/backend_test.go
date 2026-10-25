package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/desktopcontrol"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
)

func backendConfig(t *testing.T) config {
	t.Helper()
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	dir := t.TempDir()
	_, _, c, e := parse([]string{"serve", "--data-dir", dir, "--port", strconv.Itoa(port)})
	if e != nil {
		t.Fatal(e)
	}
	c.passwordFile = filepath.Join(dir, "initial-password")
	if e = os.WriteFile(c.passwordFile, []byte("isolated-backend-test-password"), 0600); e != nil {
		t.Fatal(e)
	}
	return c
}

func TestDesktopAttachesWithoutStartingAnotherBackend(t *testing.T) {
	c := backendConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	owner, e := startOwnedBackend(ctx, c)
	if e != nil {
		t.Fatal(e)
	}
	defer owner.Stop()
	probeCtx, end := context.WithTimeout(context.Background(), 3*time.Second)
	defer end()
	address, e := desktopcontrol.Discover(probeCtx, c.launch.DataDir)
	if e != nil || address != owner.URL {
		t.Fatal("identity publication unavailable", address, e)
	}
	keyBefore, e := os.ReadFile(c.launch.KeyFile)
	if e != nil {
		t.Fatal(e)
	}
	_, revisionBefore, e := owner.Application.Store.Load()
	if e != nil {
		t.Fatal(e)
	}
	attached, address, e := startOrAttachBackend(probeCtx, c)
	if e != nil || attached != nil || address != owner.URL {
		t.Fatal("secondary instance started a backend", address, e)
	}
	_, revisionAfter, e := owner.Application.Store.Load()
	if e != nil || revisionBefore != revisionAfter {
		t.Fatal("attachment changed configuration")
	}
	history, e := owner.Application.Jobs.History()
	if e != nil || len(history) != 0 {
		t.Fatal("attachment ran an account task", history, e)
	}
	response, e := http.Get(address + "/api/config")
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 401 {
		t.Fatal("identity proof bypassed management authentication", response.StatusCode)
	}
	if e = owner.Stop(); e != nil {
		t.Fatal(e)
	}
	if _, e = os.Stat(filepath.Join(c.launch.DataDir, desktopcontrol.FileName)); !os.IsNotExist(e) {
		t.Fatal("identity record left after shutdown", e)
	}
	for _, file := range []string{"service.lock", "execution.lock"} {
		lock, e := platform.Lock(filepath.Join(c.launch.DataDir, file))
		if e != nil {
			t.Fatal("lifecycle lease not released", file, e)
		}
		lock.Close()
	}
	keyAfter, e := os.ReadFile(c.launch.KeyFile)
	if e != nil || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("backend stop replaced key")
	}
}

func TestWebShutdownClosesOwnedDesktopBackend(t *testing.T) {
	c := backendConfig(t)
	backend, e := startOwnedBackend(context.Background(), c)
	if e != nil {
		t.Fatal(e)
	}
	defer backend.Stop()
	request, e := http.NewRequest("POST", backend.URL+"/api/login", bytes.NewBufferString(`{"password":"isolated-backend-test-password"}`))
	if e != nil {
		t.Fatal(e)
	}
	request.Header.Set("Origin", backend.URL)
	request.Header.Set("Content-Type", "application/json")
	response, e := http.DefaultClient.Do(request)
	if e != nil {
		t.Fatal(e)
	}
	var session map[string]any
	raw, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if e = json.Unmarshal(raw, &session); e != nil || response.StatusCode != 200 {
		t.Fatal("login failed", response.StatusCode, e)
	}
	stop, e := http.NewRequest("POST", backend.URL+"/api/runtime/shutdown", bytes.NewBufferString("{}"))
	if e != nil {
		t.Fatal(e)
	}
	stop.Header.Set("Origin", backend.URL)
	stop.Header.Set("Content-Type", "application/json")
	stop.Header.Set("X-CSRF-Token", session["csrf"].(string))
	for _, cookie := range response.Cookies() {
		stop.AddCookie(cookie)
	}
	response, e = http.DefaultClient.Do(stop)
	if e != nil {
		t.Fatal(e)
	}
	response.Body.Close()
	if response.StatusCode != 202 {
		t.Fatal(response.StatusCode)
	}
	select {
	case <-backend.Done:
	case <-time.After(3 * time.Second):
		t.Fatal("web shutdown did not stop desktop-owned backend")
	}
}

func TestHeadlessAndDesktopLaunchContracts(t *testing.T) {
	c := backendConfig(t)
	c.launch.Desktop = true
	args := c.launch.Args()
	if len(args) < 2 || args[0] != "app" || args[1] != "--hidden" {
		t.Fatal(args)
	}
	c.launch.Desktop = false
	args = c.launch.Args()
	if args[0] != "serve" {
		t.Fatal(args)
	}
	command, _, parsed, e := parse([]string{"app", "--hidden", "--page", "/status", "--data-dir", c.launch.DataDir})
	if e != nil || command != "app" || !parsed.hidden || parsed.page != "/status" {
		t.Fatal(command, parsed, e)
	}
}
