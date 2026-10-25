package desktopcontrol

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func fixture(t *testing.T) (string, *Identity, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	var current atomic.Pointer[Identity]
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if i := current.Load(); i != nil {
			i.Handler().ServeHTTP(w, r)
		} else {
			http.Error(w, "starting", 503)
		}
	}))
	i, err := Publish(dir, server.URL)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	current.Store(i)
	t.Cleanup(func() {
		server.Close()
		if err := i.Close(); err != nil {
			t.Error(err)
		}
	})
	return dir, i, server
}

func newChallenge(t *testing.T) string {
	t.Helper()
	nonce, err := randomBytes(32)
	if err != nil {
		t.Fatal(err)
	}
	return encode(nonce)
}
func localRequest(t *testing.T, i *Identity, challenge string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("GET", i.record.URL+EndpointPath+"?challenge="+challenge, nil)
	r.RemoteAddr = "127.0.0.1:12000"
	return r
}

func TestDiscoverRealIdentityAndNeverExposesCapability(t *testing.T) {
	dir, i, server := fixture(t)
	result, err := Discover(context.Background(), dir)
	if err != nil || result != server.URL {
		t.Fatal(result, err)
	}
	w := httptest.NewRecorder()
	i.Handler().ServeHTTP(w, localRequest(t, i, newChallenge(t)))
	if w.Code != 200 || strings.Contains(w.Body.String(), i.record.Capability) || strings.Contains(w.Body.String(), dir) {
		t.Fatal("identity exposed private metadata")
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("identity was cacheable or cross-origin readable")
	}
	stored, err := os.ReadFile(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(stored), "password") || strings.Contains(string(stored), "cookie") || strings.Contains(string(stored), "master.key") {
		t.Fatal("unrelated credential in control record")
	}
}

func TestInvalidBaseURLsNeverPublish(t *testing.T) {
	for _, raw := range []string{"https://localhost:8765", "http://example.com:8765", "http://localhost.evil:8765", "http://localhost.:8765", "http://127.0.0.2:8765", "http://[::ffff:127.0.0.1]:8765", "http://user:password@localhost:8765", "http://localhost:8765/", "http://localhost:8765?secret=1", "http://localhost:8765?", "http://localhost:8765#fragment", "http://localhost:08765", "http://localhost:0", "http://localhost:65536", "http://LOCALHOST:8765", "http://localhost:8765\\evil"} {
		t.Run(raw, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := Publish(dir, raw); !errors.Is(err, ErrUntrusted) {
				t.Fatal("invalid URL accepted", err)
			}
			if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
				t.Fatal("invalid URL wrote a record")
			}
		})
	}
	for _, raw := range []string{"http://localhost:8765", "http://127.0.0.1:8765", "http://[::1]:8765", "http://localhost", "http://[::1]"} {
		if _, _, err := validBaseURL(raw); err != nil {
			t.Fatal("valid URL rejected", raw, err)
		}
	}
}

func TestProofRequiresActualLoopbackAndExactOrigin(t *testing.T) {
	_, i, _ := fixture(t)
	cases := map[string]func(*http.Request){
		"remote":             func(r *http.Request) { r.RemoteAddr = "192.0.2.8:10000" },
		"invalid peer":       func(r *http.Request) { r.RemoteAddr = "unknown" },
		"forged forwarded":   func(r *http.Request) { r.Header.Set("X-Forwarded-For", "127.0.0.1") },
		"forwarded empty":    func(r *http.Request) { r.Header["Forwarded"] = []string{} },
		"forwarded prefix":   func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "localhost") },
		"wrong host":         func(r *http.Request) { r.Host = "attacker.example" },
		"wrong port":         func(r *http.Request) { r.Host = "127.0.0.1:1" },
		"wrong origin":       func(r *http.Request) { r.Header.Set("Origin", "http://attacker.example") },
		"opaque origin":      func(r *http.Request) { r.Header.Set("Origin", "null") },
		"duplicate origin":   func(r *http.Request) { r.Header["Origin"] = []string{i.record.URL, i.record.URL} },
		"browser cross-site": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") },
		"browser other-port": func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "same-site") },
		"different endpoint": func(r *http.Request) { r.URL.Path = "/api/config" },
		"escaped path":       func(r *http.Request) { r.URL.RawPath = "/api/desktop/%69dentity" },
		"request body":       func(r *http.Request) { r.ContentLength = 1 },
		"unknown body":       func(r *http.Request) { r.ContentLength = -1 },
		"chunked body":       func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			r := localRequest(t, i, newChallenge(t))
			change(r)
			w := httptest.NewRecorder()
			i.Handler().ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatal(w.Code)
			}
		})
	}
	for _, remote := range []string{"127.0.0.1:20000", "[::1]:20000"} {
		r := localRequest(t, i, newChallenge(t))
		r.RemoteAddr = remote
		r.Header.Set("Origin", i.record.URL)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		w := httptest.NewRecorder()
		i.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatal("valid local proof rejected", remote, w.Code)
		}
	}
}

func TestProofMethodsChallengeBoundsAndReplay(t *testing.T) {
	_, i, _ := fixture(t)
	for _, query := range []string{"", "challenge=short", "challenge=" + strings.Repeat("A", 43) + "=", "challenge=" + newChallenge(t) + "&unknown=1", "challenge=" + newChallenge(t) + "&challenge=" + newChallenge(t), "challenge=%xx"} {
		r := localRequest(t, i, newChallenge(t))
		r.URL.RawQuery = query
		w := httptest.NewRecorder()
		i.Handler().ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal("invalid challenge accepted", query, w.Code)
		}
	}
	r := localRequest(t, i, newChallenge(t))
	r.Method = "POST"
	w := httptest.NewRecorder()
	i.Handler().ServeHTTP(w, r)
	if w.Code != 405 || w.Header().Get("Allow") != "GET" {
		t.Fatal(w.Code)
	}
	challenge := newChallenge(t)
	for attempt := 0; attempt < 2; attempt++ {
		w := httptest.NewRecorder()
		i.Handler().ServeHTTP(w, localRequest(t, i, challenge))
		expected := 200
		if attempt > 0 {
			expected = 409
		}
		if w.Code != expected {
			t.Fatal("challenge replay accepted", w.Code)
		}
	}
	i.mu.Lock()
	for len(i.nonces) < maxNonces {
		i.nonces[newChallenge(t)] = time.Now()
	}
	i.mu.Unlock()
	w = httptest.NewRecorder()
	i.Handler().ServeHTTP(w, localRequest(t, i, newChallenge(t)))
	if w.Code != 429 {
		t.Fatal("nonce cache unbounded", w.Code)
	}
	i.mu.Lock()
	for nonce := range i.nonces {
		i.nonces[nonce] = time.Now().Add(-2 * nonceTTL)
	}
	i.mu.Unlock()
	w = httptest.NewRecorder()
	i.Handler().ServeHTTP(w, localRequest(t, i, newChallenge(t)))
	if w.Code != 200 {
		t.Fatal("expired nonce cache did not clear", w.Code)
	}
}

func TestCloseOnlyRemovesOwnRecordAndIsIdempotent(t *testing.T) {
	dir, i, server := fixture(t)
	next, err := Publish(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err = i.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := readRecord(dir)
	if err != nil || !sameRecord(current, next.record) {
		t.Fatal("old instance deleted successor", err)
	}
	if err = i.Close(); err != nil {
		t.Fatal(err)
	}
	if err = next.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatal("own record retained")
	}
	w := httptest.NewRecorder()
	next.Handler().ServeHTTP(w, localRequest(t, next, newChallenge(t)))
	if w.Code != 503 {
		t.Fatal("closed listener issued proof", w.Code)
	}
}

func TestConcurrentPublishAndOldClosePreserveSuccessor(t *testing.T) {
	dir, i, server := fixture(t)
	var next *Identity
	var publishErr, closeErr error
	var wait sync.WaitGroup
	wait.Add(2)
	go func() { defer wait.Done(); next, publishErr = Publish(dir, server.URL) }()
	go func() { defer wait.Done(); closeErr = i.Close() }()
	wait.Wait()
	if publishErr != nil || closeErr != nil {
		t.Fatal(publishErr, closeErr)
	}
	defer next.Close()
	current, err := readRecord(dir)
	if err != nil || !sameRecord(current, next.record) {
		t.Fatal("publication raced with old close", err)
	}
}

func TestMissingMalformedAndNonRegularRecords(t *testing.T) {
	dir := t.TempDir()
	if _, err := Discover(context.Background(), dir); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	path := filepath.Join(dir, FileName)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(dir, "http://localhost:8765"); !errors.Is(err, ErrUntrusted) {
		t.Fatal("directory overwritten", err)
	}
	if _, err := Discover(context.Background(), dir); !errors.Is(err, ErrUntrusted) {
		t.Fatal("directory accepted", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{"not json", `{"version":1}`, strings.Repeat(" ", maxRecordBytes+1)} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
		if err := protectControl(path, dir); err != nil {
			t.Fatal(err)
		}
		if _, err := Discover(context.Background(), dir); !errors.Is(err, ErrUntrusted) {
			t.Fatal("malformed control record accepted", err)
		}
	}
	// A new owner of service.lock can replace a corrupted regular sidecar.
	i, err := Publish(dir, "http://localhost:8765")
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	r := i.record
	r.Version = 2
	writeRecord(t, dir, r)
	if _, err := Discover(context.Background(), dir); !errors.Is(err, ErrUntrusted) {
		t.Fatal(err)
	}
}

func writeRecord(t *testing.T, dir string, r record) {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, FileName)
	if err = os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
	if err = protectControl(path, dir); err != nil {
		t.Fatal(err)
	}
}

func TestDiscoverDoesNotTrustHealthJSONOrTransmitCapability(t *testing.T) {
	dir := t.TempDir()
	var requests atomic.Int32
	var leaked atomic.Bool
	var capability string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		dump := r.URL.String() + "\n" + r.Header.Get("Authorization") + "\n" + r.Header.Get("Cookie")
		if strings.Contains(dump, capability) {
			leaked.Store(true)
		}
		if r.URL.Path != EndpointPath {
			t.Error("client reached a management API")
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true,"runtime":"go"}`)
	}))
	defer server.Close()
	i, err := Publish(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	capability = i.record.Capability
	if _, err = Discover(context.Background(), dir); !errors.Is(err, ErrUntrusted) {
		t.Fatal("fake healthy listener trusted", err)
	}
	if requests.Load() != 1 || leaked.Load() {
		t.Fatal("capability sent to foreign listener")
	}
}

func TestDiscoverRejectsReplayedProofAndMalformedResponses(t *testing.T) {
	for _, kind := range []string{"replay", "wrong proof", "unknown field", "oversize", "trailing JSON", "wrong content type"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			var current *Identity
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				challenge := r.URL.Query().Get("challenge")
				p := proof{protocol, 1, current.record.Instance, challenge, encode(current.signature(challenge))}
				switch kind {
				case "replay":
					p.Challenge = newChallenge(t)
					p.Proof = encode(current.signature(p.Challenge))
				case "wrong proof":
					p.Proof = encode(make([]byte, 32))
				case "oversize":
					io.WriteString(w, strings.Repeat("x", maxProofBytes+1))
					return
				case "unknown field":
					io.WriteString(w, `{"not_a_proof":true}`)
					return
				case "wrong content type":
					w.Header().Set("Content-Type", "text/html")
				}
				_ = json.NewEncoder(w).Encode(p)
				if kind == "trailing JSON" {
					io.WriteString(w, `{}`)
				}
			}))
			defer server.Close()
			var err error
			current, err = Publish(dir, server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer current.Close()
			if _, err = Discover(context.Background(), dir); !errors.Is(err, ErrUntrusted) {
				t.Fatal("invalid response accepted", kind, err)
			}
		})
	}
}

func TestDiscoverNeverFollowsRedirects(t *testing.T) {
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer server.Close()
	dir := t.TempDir()
	i, err := Publish(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	if _, err = Discover(context.Background(), dir); !errors.Is(err, ErrUntrusted) {
		t.Fatal(err)
	}
	if redirected.Load() != 0 {
		t.Fatal("redirect followed")
	}
}

func TestDiscoveryContextDeadlineAndNoDNSProxyFallback(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:9876")
	t.Setenv("ALL_PROXY", "socks5://192.0.2.1:9876")
	dir, _, server := fixture(t)
	if result, err := Discover(context.Background(), dir); err != nil || result != server.URL {
		t.Fatal("environment proxy used", result, err)
	}
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer slow.Close()
	slowDir := t.TempDir()
	i, err := Publish(slowDir, slow.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err = Discover(ctx, slowDir); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if time.Since(start) > time.Second {
		t.Fatal("context deadline ignored")
	}
	dial := loopbackDialer("localhost", "8765")
	if _, err = dial(context.Background(), "tcp", "192.0.2.1:8765"); !errors.Is(err, ErrUntrusted) {
		t.Fatal("foreign dial allowed", err)
	}
}

func TestRecordRotationDuringHandshakeIsNotTrusted(t *testing.T) {
	dir := t.TempDir()
	var first, next *Identity
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		challenge := r.URL.Query().Get("challenge")
		p := proof{protocol, 1, first.record.Instance, challenge, encode(first.signature(challenge))}
		var err error
		next, err = Publish(dir, server.URL)
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(p)
	}))
	defer server.Close()
	var err error
	first, err = Publish(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	defer func() {
		if next != nil {
			next.Close()
		}
	}()
	if _, err = Discover(context.Background(), dir); !errors.Is(err, ErrUnavailable) {
		t.Fatal("rotated record trusted", err)
	}
}

func TestLocalhostProbeUsesLoopbackWithoutDNS(t *testing.T) {
	dir, i, server := fixture(t)
	u, _ := url.Parse(server.URL)
	i.Close()
	replacement, err := Publish(dir, "http://localhost:"+u.Port())
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	// A localhost publication itself is accepted without resolving localhost via DNS.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := loopbackDialer("localhost", strconvForTest(port))(ctx, "tcp", net.JoinHostPort("localhost", strconvForTest(port)))
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if runtime.GOOS != "windows" {
		info, err := os.Stat(filepath.Join(dir, FileName))
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("control file is not private", err)
		}
	}
}

func strconvForTest(value int) string { b, _ := json.Marshal(value); return string(b) }

func TestIPv6LoopbackIdentityProof(t *testing.T) {
	listener, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skip("IPv6 loopback unavailable")
	}
	var current atomic.Pointer[Identity]
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { current.Load().Handler().ServeHTTP(w, r) }))
	server.Listener.Close()
	server.Listener = listener
	server.Start()
	defer server.Close()
	dir := t.TempDir()
	i, err := Publish(dir, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer i.Close()
	current.Store(i)
	u, _ := url.Parse(server.URL)
	rawConn, rawErr := net.Dial("tcp", u.Host)
	if rawErr != nil {
		t.Skip("IPv6 loopback connections are unavailable on this host")
	}
	rawConn.Close()
	conn, err := loopbackDialer(u.Hostname(), u.Port())(context.Background(), "tcp", u.Host)
	if err != nil {
		t.Fatalf("IPv6 direct probe failed: %v", err)
	}
	conn.Close()
	actual, err := Discover(context.Background(), dir)
	if err != nil || actual != server.URL {
		t.Fatal(actual, err)
	}
}
