// Package desktopcontrol proves which private data directory owns a local
// checkin HTTP listener. It grants no account, configuration or shutdown access.
package desktopcontrol

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
)

const (
	EndpointPath   = "/api/desktop/identity"
	FileName       = "desktop-control.json"
	LockFileName   = "desktop-control.lock"
	protocol       = "checkin-desktop-identity-v1"
	maxRecordBytes = 4096
	maxProofBytes  = 2048
	probeTimeout   = 2 * time.Second
	nonceTTL       = time.Minute
	maxNonces      = 256
)

var (
	ErrUnavailable = errors.New("本机后台尚未就绪")
	ErrUntrusted   = errors.New("无法验证本机后台身份")
)

type record struct {
	Protocol   string `json:"protocol"`
	Version    int    `json:"version"`
	URL        string `json:"url"`
	Capability string `json:"capability"`
	Instance   string `json:"instance"`
}

type proof struct {
	Protocol  string `json:"protocol"`
	Version   int    `json:"version"`
	Instance  string `json:"instance"`
	Challenge string `json:"challenge"`
	Proof     string `json:"proof"`
}

// Identity owns one published record. Publish and Close must run while the
// caller holds the data directory's service and execution locks. A separate
// short-lived publication lock also protects a late Close from a successor.
type Identity struct {
	mu                       sync.Mutex
	path, dataDir, authority string
	record                   record
	key                      []byte
	closed                   bool
	nonces                   map[string]time.Time
}

// Publish records a listener which is already bound to baseURL. It may replace
// a regular stale control record after the caller obtains the service locks.
func Publish(dataDir, baseURL string) (*Identity, error) {
	base, authority, err := validBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if err = platform.PrivateDir(dataDir); err != nil {
		return nil, ErrUntrusted
	}
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, ErrUntrusted
	}
	if err = validateDirectory(abs); err != nil {
		return nil, err
	}
	lease, err := publicationLock(abs)
	if err != nil {
		return nil, err
	}
	defer lease.Close()
	path := filepath.Join(abs, FileName)
	if err = platform.PrivateFile(path); err != nil {
		return nil, ErrUntrusted
	}
	key, err := randomBytes(32)
	if err != nil {
		return nil, ErrUnavailable
	}
	instance, err := randomBytes(16)
	if err != nil {
		return nil, ErrUnavailable
	}
	r := record{protocol, 1, base, encode(key), encode(instance)}
	data, err := json.Marshal(r)
	if err != nil {
		return nil, ErrUnavailable
	}
	f, err := os.CreateTemp(abs, ".desktop-control-*")
	if err != nil {
		return nil, ErrUnavailable
	}
	name := f.Name()
	defer os.Remove(name)
	if err = protectControl(name, abs); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, ErrUnavailable
	}
	if err = platform.PrivateFile(path); err != nil {
		return nil, ErrUntrusted
	}
	if err = os.Rename(name, path); err != nil {
		return nil, ErrUnavailable
	}
	return &Identity{path: path, dataDir: abs, authority: authority, record: r, key: key, nonces: map[string]time.Time{}}, nil
}

func randomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	return b, err
}
func encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func decode(value string, length int) ([]byte, error) {
	b, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(b) != length || encode(b) != value {
		return nil, ErrUntrusted
	}
	return b, nil
}

func validBaseURL(raw string) (base, authority string, err error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "http" || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Host == "" || u.String() != raw {
		return "", "", ErrUntrusted
	}
	host := u.Hostname()
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return "", "", ErrUntrusted
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || u.Host != net.JoinHostPort(host, port) {
			return "", "", ErrUntrusted
		}
	} else {
		expected := host
		if host == "::1" {
			expected = "[::1]"
		}
		if u.Host != expected {
			return "", "", ErrUntrusted
		}
	}
	return raw, u.Host, nil
}

func validateDirectory(path string) error {
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			if os.IsNotExist(err) {
				return ErrUnavailable
			}
			return ErrUntrusted
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return ErrUntrusted
		}
		if filepath.Dir(p) == p {
			return nil
		}
	}
}

func publicationLock(dataDir string) (*os.File, error) {
	path := filepath.Join(dataDir, LockFileName)
	for attempt := 0; attempt < 30; attempt++ {
		if platform.PrivateFile(path) != nil {
			return nil, ErrUntrusted
		}
		lease, err := platform.Lock(path)
		if err == nil {
			if err = protectControl(path, dataDir); err != nil {
				lease.Close()
				return nil, ErrUntrusted
			}
			return lease, nil
		}
		if attempt < 29 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	return nil, ErrUnavailable
}

func (i *Identity) signature(challenge string) []byte {
	mac := hmac.New(sha256.New, i.key)
	_, _ = mac.Write([]byte(protocol + "\n" + i.record.URL + "\n" + i.record.Instance + "\n" + challenge))
	return mac.Sum(nil)
}

func (i *Identity) Handler() http.Handler { return http.HandlerFunc(i.serveHTTP) }
func (i *Identity) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", 405)
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	if err != nil || ip == nil || !ip.IsLoopback() || r.Host != i.authority || r.URL.Path != EndpointPath || r.URL.RawPath != "" || r.ContentLength != 0 || len(r.TransferEncoding) > 0 {
		http.Error(w, "local endpoint only", 403)
		return
	}
	for name := range r.Header {
		lower := strings.ToLower(name)
		if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") {
			http.Error(w, "local endpoint only", 403)
			return
		}
	}
	if values := r.Header.Values("Origin"); len(values) > 1 || (len(values) == 1 && values[0] != i.record.URL) {
		http.Error(w, "origin rejected", 403)
		return
	}
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "none" && site != "same-origin" {
		http.Error(w, "origin rejected", 403)
		return
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query) != 1 || len(query["challenge"]) != 1 {
		http.Error(w, "invalid challenge", 400)
		return
	}
	challenge := query.Get("challenge")
	if _, err = decode(challenge, 32); err != nil {
		http.Error(w, "invalid challenge", 400)
		return
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		http.Error(w, "listener unavailable", 503)
		return
	}
	now := time.Now()
	for nonce, at := range i.nonces {
		if now.Sub(at) >= nonceTTL {
			delete(i.nonces, nonce)
		}
	}
	if _, seen := i.nonces[challenge]; seen {
		http.Error(w, "challenge already used", 409)
		return
	}
	if len(i.nonces) >= maxNonces {
		http.Error(w, "try later", 429)
		return
	}
	i.nonces[challenge] = now
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(proof{protocol, 1, i.record.Instance, challenge, encode(i.signature(challenge))})
}

func readRecord(dataDir string) (record, error) {
	abs, err := filepath.Abs(dataDir)
	if err != nil {
		return record{}, ErrUntrusted
	}
	if err = validateDirectory(abs); err != nil {
		return record{}, err
	}
	f, err := openControl(filepath.Join(abs, FileName), abs)
	if err != nil {
		return record{}, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxRecordBytes {
		return record{}, ErrUntrusted
	}
	b, err := io.ReadAll(io.LimitReader(f, maxRecordBytes+1))
	if err != nil || len(b) > maxRecordBytes {
		return record{}, ErrUntrusted
	}
	var r record
	if err = strictJSON(b, &r); err != nil {
		return record{}, err
	}
	if r.Protocol != protocol || r.Version != 1 {
		return record{}, ErrUntrusted
	}
	if _, _, err = validBaseURL(r.URL); err != nil {
		return record{}, err
	}
	if _, err = decode(r.Capability, 32); err != nil {
		return record{}, err
	}
	if _, err = decode(r.Instance, 16); err != nil {
		return record{}, err
	}
	return r, nil
}

func strictJSON(data []byte, out any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(out) != nil {
		return ErrUntrusted
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ErrUntrusted
	}
	return nil
}

// Discover sends a fresh random challenge. The private capability is never
// transmitted, including to a foreign service which has taken a stale port.
func Discover(ctx context.Context, dataDir string) (string, error) {
	r, err := readRecord(dataDir)
	if err != nil {
		return "", err
	}
	key, err := decode(r.Capability, 32)
	if err != nil {
		return "", err
	}
	nonce, err := randomBytes(32)
	if err != nil {
		return "", ErrUnavailable
	}
	challenge := encode(nonce)
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	u, _ := url.Parse(r.URL)
	port := u.Port()
	if port == "" {
		port = "80"
	}
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 8192, DialContext: loopbackDialer(u.Hostname(), port)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", r.URL+EndpointPath+"?challenge="+challenge, nil)
	if err != nil {
		return "", ErrUntrusted
	}
	request.Header.Set("Accept", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return "", ErrUnavailable
	}
	defer response.Body.Close()
	contentType, _, e := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || e != nil || contentType != "application/json" || response.ContentLength > maxProofBytes {
		return "", ErrUntrusted
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, maxProofBytes+1))
	if ctx.Err() != nil {
		return "", ErrUnavailable
	}
	if err != nil || len(b) > maxProofBytes {
		return "", ErrUntrusted
	}
	var p proof
	if err = strictJSON(b, &p); err != nil {
		return "", err
	}
	if p.Protocol != protocol || p.Version != 1 || p.Instance != r.Instance || p.Challenge != challenge {
		return "", ErrUntrusted
	}
	received, err := decode(p.Proof, 32)
	if err != nil {
		return "", ErrUntrusted
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(protocol + "\n" + r.URL + "\n" + r.Instance + "\n" + challenge))
	if !hmac.Equal(received, mac.Sum(nil)) {
		return "", ErrUntrusted
	}
	current, err := readRecord(dataDir)
	if err != nil {
		return "", err
	}
	if !sameRecord(r, current) {
		return "", ErrUnavailable
	}
	return r.URL, nil
}

func loopbackDialer(host, port string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != net.JoinHostPort(host, port) {
			return nil, ErrUntrusted
		}
		ips := []string{host}
		if host == "localhost" {
			ips = []string{"127.0.0.1", "::1"}
		}
		for _, ip := range ips {
			conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, ErrUnavailable
	}
}

func sameRecord(a, b record) bool {
	return a.Protocol == b.Protocol && a.Version == b.Version && a.URL == b.URL && a.Instance == b.Instance && hmac.Equal([]byte(a.Capability), []byte(b.Capability))
}

// Close removes only this publication. It leaves a successor's record intact.
func (i *Identity) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	i.closed = true
	i.nonces = nil
	lease, err := publicationLock(i.dataDir)
	if err != nil {
		return err
	}
	defer lease.Close()
	current, err := readRecord(i.dataDir)
	if errors.Is(err, ErrUnavailable) {
		return nil
	}
	if err != nil {
		return err
	}
	if !sameRecord(i.record, current) {
		return nil
	}
	if err = os.Remove(i.path); err != nil && !os.IsNotExist(err) {
		return ErrUnavailable
	}
	return nil
}
