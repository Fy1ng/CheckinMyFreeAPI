// Package desktop adds an optional native window and tray to the existing HTTP
// application. It does not expose account operations through native bindings.
package desktop

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
)

type Backend struct {
	// URL is the already-started, authenticated loopback HTTP application's origin.
	URL string
	// Stop is nil when the desktop attached to a separately-owned server.
	Stop func() error
	// Done closes when the HTTP backend exits, so no disconnected shell is left.
	Done <-chan struct{}
}

type Options struct {
	DataDir, Version, Path string
	Hidden                 bool
	// Start runs only after the native single-instance claim has succeeded.
	Start func(context.Context) (Backend, error)
}

func validPath(path string) (string, error) {
	if path == "" {
		return "/", nil
	}
	switch path {
	case "/", "/status", "/backups", "/security":
		return path, nil
	}
	return "", errors.New("桌面页面无效")
}

func validateURL(address string) (string, error) {
	u, e := url.Parse(address)
	if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Opaque != "" {
		return "", errors.New("桌面界面需要本机 HTTP 管理地址")
	}
	host := u.Hostname()
	if host != "localhost" && host != "127.0.0.1" && host != "::1" {
		return "", errors.New("桌面界面只允许本机管理地址")
	}
	port, e := strconv.Atoi(u.Port())
	if e != nil || port < 1 || port > 65535 {
		return "", errors.New("桌面管理端口无效")
	}
	if u.Host != net.JoinHostPort(host, strconv.Itoa(port)) {
		return "", errors.New("桌面管理地址无效")
	}
	return "http://" + u.Host, nil
}

func validate(options Options) (Options, string, error) {
	if options.Start == nil {
		return options, "", errors.New("桌面应用缺少后台启动入口")
	}
	if options.DataDir == "" {
		return options, "", errors.New("桌面应用缺少私有数据目录")
	}
	p, e := validPath(options.Path)
	if e != nil {
		return options, "", e
	}
	options.Path = p
	abs, e := filepath.Abs(options.DataDir)
	if e != nil {
		return options, "", e
	}
	if e = platform.PrivateDir(abs); e != nil {
		return options, "", e
	}
	options.DataDir = abs
	identity := filepath.Clean(abs)
	if runtime.GOOS == "windows" {
		identity = strings.ToLower(identity)
	}
	digest := sha256.Sum256([]byte(identity))
	return options, "cn.checkinmyfreeapi.desktop.p" + hex.EncodeToString(digest[:16]), nil
}

func instanceKey(dataDir string) ([32]byte, error) {
	var key [32]byte
	// Serialize key creation, so a simultaneous second launch never observes
	// an empty file between O_EXCL and the completed fsync.
	var lease *os.File
	var lockError error
	for attempt := 0; attempt < 100; attempt++ {
		lease, lockError = platform.Lock(filepath.Join(dataDir, "desktop-instance.lock"))
		if lockError == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if lockError != nil {
		return key, errors.New("桌面实例设置正在使用, 请稍后重试")
	}
	defer lease.Close()
	path := filepath.Join(dataDir, "desktop-instance.key")
	if e := platform.PrivateFile(path); e != nil {
		return key, e
	}
	load := func() ([32]byte, error) {
		var result [32]byte
		f, e := os.Open(path)
		if e != nil {
			return result, e
		}
		defer f.Close()
		b, e := io.ReadAll(io.LimitReader(f, 33))
		if e != nil || len(b) != 32 {
			return result, errors.New("桌面实例密钥无效, 请检查私有数据目录")
		}
		copy(result[:], b)
		return result, nil
	}
	if _, e := os.Stat(path); e == nil {
		return load()
	} else if !os.IsNotExist(e) {
		return key, e
	}
	if _, e := rand.Read(key[:]); e != nil {
		return key, e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if os.IsExist(e) {
		return load()
	}
	if e != nil {
		return key, e
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if e = platform.ProtectFile(path); e != nil {
		return key, e
	}
	if _, e = f.Write(key[:]); e != nil {
		return key, e
	}
	if e = f.Sync(); e != nil {
		return key, e
	}
	if e = f.Close(); e != nil {
		return key, e
	}
	ok = true
	return key, nil
}

// activation waits until the native event loop is ready and keeps a bounded
// single pending page. Invalid IPC payloads cannot turn the shell into a browser.
type activation struct {
	mu      sync.Mutex
	ready   bool
	pending string
	show    func(string)
}

func (a *activation) request(path string) {
	path, e := validPath(path)
	if e != nil {
		return
	}
	a.mu.Lock()
	if !a.ready {
		a.pending = path
		a.mu.Unlock()
		return
	}
	show := a.show
	a.mu.Unlock()
	show(path)
}
func (a *activation) start(defaultPath string, hidden bool) {
	a.mu.Lock()
	a.ready = true
	path := a.pending
	a.pending = ""
	show := a.show
	a.mu.Unlock()
	if path != "" {
		show(path)
	} else if !hidden {
		show(defaultPath)
	}
}
