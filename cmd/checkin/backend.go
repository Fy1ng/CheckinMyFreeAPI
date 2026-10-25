package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/app"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/desktopcontrol"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
)

// backendSession owns one already-listening backend. Done closes after jobs,
// requests and database handles have stopped and both lifecycle locks release.
type backendSession struct {
	URL         string
	Application *app.App
	Done        chan struct{}
	cancel      context.CancelFunc
	err         error
}

func (b *backendSession) Stop() error { b.cancel(); <-b.Done; return b.err }
func (b *backendSession) Err() error  { <-b.Done; return b.err }

func startOwnedBackend(parent context.Context, c config) (result *backendSession, err error) {
	if err = c.launch.Validate(); err != nil {
		return nil, err
	}
	if err = platform.PrivateDir(c.launch.DataDir); err != nil {
		return nil, err
	}
	cleanup := []func(){}
	release := func() {
		for i := len(cleanup) - 1; i >= 0; i-- {
			cleanup[i]()
		}
	}
	complete := false
	defer func() {
		if !complete {
			release()
		}
	}()
	for _, name := range []string{"service.lock", "execution.lock"} {
		lease, e := platform.Lock(filepath.Join(c.launch.DataDir, name))
		if e != nil {
			return nil, e
		}
		cleanup = append(cleanup, func() { _ = lease.Close() })
	}
	key, e := loadKey(c.launch.DataDir, c.launch.KeyFile)
	if e != nil {
		return nil, e
	}
	logPath := filepath.Join(c.launch.DataDir, "server.log")
	if e = platform.PrivateFile(logPath); e != nil {
		return nil, e
	}
	logger := &rotatingLog{path: logPath}
	previous := log.Writer()
	log.SetOutput(logger)
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)
	log.SetPrefix("[UTC] ")
	cleanup = append(cleanup, func() { log.SetOutput(previous); _ = logger.Close() })
	password := ""
	if !c.launch.LocalMode {
		password = os.Getenv("CHECKIN_WEB_PASSWORD")
	}
	if !c.launch.LocalMode && c.passwordFile != "" {
		password, e = readSecretFile(c.passwordFile)
		if e != nil {
			return nil, e
		}
	}
	ctx, cancel := context.WithCancel(parent)
	cleanup = append(cleanup, cancel)
	listener, e := net.Listen("tcp", net.JoinHostPort(c.launch.Host, strconv.Itoa(c.launch.Port)))
	if e != nil {
		log.Print("监听端口失败")
		return nil, errors.New("本机监听端口不可用, 请检查已有实例或选择其他端口")
	}
	cleanup = append(cleanup, func() { _ = listener.Close() })
	// localhost is a browser secure context for WebAuthn; requests still pass
	// through the exact same Origin, session and CSRF checks as the WebUI.
	baseURL := "http://" + net.JoinHostPort("localhost", strconv.Itoa(c.launch.Port))
	identity, e := desktopcontrol.Publish(c.launch.DataDir, baseURL)
	if e != nil {
		return nil, errors.New("无法创建私有本机实例记录")
	}
	cleanup = append(cleanup, func() { _ = identity.Close() })
	application, e := app.New(ctx, app.Options{DataDir: c.launch.DataDir, Key: key, Password: password, Launch: c.launch, LocalMode: c.launch.LocalMode, Shutdown: cancel, DesktopIdentity: identity.Handler()})
	if e != nil {
		log.Print("服务初始化失败")
		return nil, e
	}
	cleanup = append(cleanup, func() { _ = application.Close() })
	server := &http.Server{Handler: application, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024, ErrorLog: log.New(logger, "[HTTP] ", log.Ldate|log.Ltime|log.LUTC)}
	backend := &backendSession{URL: baseURL, Application: application, Done: make(chan struct{}), cancel: cancel}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	go func() {
		select {
		case e := <-serveErr:
			if e != nil && !errors.Is(e, http.ErrServerClosed) {
				backend.err = errors.New("HTTP服务异常退出")
			}
		case <-ctx.Done():
		}
		cancel()
		stopCtx, end := context.WithTimeout(context.Background(), 15*time.Second)
		if server.Shutdown(stopCtx) != nil {
			_ = server.Close()
		}
		end()
		log.Print("Go服务已停止")
		release()
		close(backend.Done)
	}()
	log.Print("Go服务已启动, 本机端口 ", c.launch.Port)
	complete = true
	return backend, nil
}

// A GUI attaches only after a fresh proof using a capability from its private
// data directory. It never uses an arbitrary listener's health response.
func existingBackend(ctx context.Context, c config) (string, error) {
	return desktopcontrol.Discover(ctx, c.launch.DataDir)
}

func startOrAttachBackend(ctx context.Context, c config) (*backendSession, string, error) {
	address, e := existingBackend(ctx, c)
	if e == nil {
		return nil, address, nil
	}
	if !errors.Is(e, desktopcontrol.ErrUnavailable) {
		return nil, "", errors.New("无法验证该数据目录的后台身份, 请检查实例记录或使用浏览器管理")
	}
	backend, e := startOwnedBackend(ctx, c)
	if e == nil {
		return backend, backend.URL, nil
	}
	if !errors.Is(e, platform.ErrLocked) {
		return nil, "", e
	}
	// A concurrently-starting headless service may not have published yet.
	deadline := time.NewTimer(4 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, "", ctx.Err()
		case <-deadline.C:
			return nil, "", errors.New("该配置已有任务或旧版本服务运行, 请先停止旧实例或通过浏览器管理")
		case <-ticker.C:
			address, lookupErr := existingBackend(ctx, c)
			if lookupErr == nil {
				return nil, address, nil
			}
			if !errors.Is(lookupErr, desktopcontrol.ErrUnavailable) {
				return nil, "", errors.New("后台身份验证失败, 已拒绝连接")
			}
		}
	}
}
