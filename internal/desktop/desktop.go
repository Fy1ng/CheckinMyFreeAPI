//go:build desktop && (windows || linux)

package desktop

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

func Available() bool { return true }

type host struct {
	app       *application.App
	window    *application.WebviewWindow // accessed only on the native main thread
	backend   Backend
	activator activation
	quitting  atomic.Bool
	stopOnce  sync.Once
	stopError error
	cancel    context.CancelFunc
}

func (h *host) stop() {
	h.stopOnce.Do(func() {
		h.quitting.Store(true)
		h.cancel()
		if h.backend.Stop != nil {
			h.stopError = h.backend.Stop()
		}
	})
}
func (h *host) quit() {
	if h.quitting.CompareAndSwap(false, true) {
		h.app.Quit()
	}
}
func (h *host) show(path string) {
	if h.quitting.Load() {
		return
	}
	address := h.backend.URL + path
	if h.window == nil {
		window := h.app.Window.NewWithOptions(application.WebviewWindowOptions{Name: "checkin-console", Title: "CheckinMyFreeAPI", Width: 1280, Height: 900, MinWidth: 390, MinHeight: 580, URL: address, BackgroundColour: application.NewRGB(248, 250, 247), DevToolsEnabled: false, DefaultContextMenuDisabled: true, KeyBindings: map[string]func(application.Window){"Ctrl+Q": func(application.Window) { h.quit() }}, Permissions: map[application.PermissionType]application.Permission{
			application.PermissionMicrophone: application.PermissionDeny, application.PermissionCamera: application.PermissionDeny, application.PermissionGeolocation: application.PermissionDeny, application.PermissionNotifications: application.PermissionDeny, application.PermissionClipboardRead: application.PermissionDeny,
		}})
		window.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
			if !h.quitting.Load() {
				event.Cancel()
				window.Hide()
			}
		})
		// The existing HTTP page deliberately does not load Wails' browser RPC
		// runtime. Mark only this native window ready through Wails' public Go
		// method so ExecJS can install the renderer guard after each page load.
		guard := func(*application.WindowEvent) {
			window.HandleMessage("wails:runtime:ready")
			window.ExecJS(navigationScript(h.backend.URL))
		}
		window.OnWindowEvent(events.Windows.WebViewNavigationCompleted, guard)
		window.OnWindowEvent(events.Linux.WindowLoadFinished, guard)
		h.window = window
	} else {
		// A normal launch or tray click activates the current page and keeps
		// any unsaved form state. Explicit page switches may navigate.
		if path != "/" {
			encoded, _ := json.Marshal(address)
			h.window.ExecJS(`(() => { const target = ` + string(encoded) + `; if (location.href !== target) location.assign(target); })();`)
		}
		h.window.Restore()
		h.window.Show().Focus()
	}
}

func Run(options Options) error {
	options, id, e := validate(options)
	if e != nil {
		return e
	}
	if e = checkEnvironment(); e != nil {
		reportEnvironmentError()
		return e
	}
	key, e := instanceKey(options.DataDir)
	if e != nil {
		return e
	}
	profile := filepath.Join(options.DataDir, "desktop-webview")
	if e = platform.PrivateDir(profile); e != nil {
		return e
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &host{cancel: cancel}
	defer h.stop()
	h.activator.show = func(path string) { application.InvokeAsync(func() { h.show(path) }) }
	h.app = application.New(application.Options{
		Name: "CheckinMyFreeAPI", Description: "NewAPI check-in and balance monitor", Icon: appIcon(), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		Assets:  application.AssetOptions{Handler: http.NotFoundHandler()},
		Windows: application.WindowsOptions{DisableQuitOnLastWindowClosed: true, WebviewUserDataPath: profile, AdditionalBrowserArgs: testBrowserArgs()},
		Linux:   application.LinuxOptions{DisableQuitOnLastWindowClosed: true, ApplicationID: id, ProgramName: "checkinmyfreeapi"},
		SingleInstance: &application.SingleInstanceOptions{UniqueID: id, EncryptionKey: key, AdditionalData: map[string]string{"path": options.Path, "hidden": boolString(options.Hidden)}, OnSecondInstanceLaunch: func(data application.SecondInstanceData) {
			if data.AdditionalData["hidden"] != "true" {
				h.activator.request(data.AdditionalData["path"])
			}
		}},
		OnShutdown: h.stop, ErrorHandler: func(error) { log.Print("桌面运行时出现错误, 可通过控制台版本检查环境") },
	})
	// Wails takes its native single-instance claim inside application.New. A
	// secondary process notifies the primary and exits before reaching Start.
	backend, e := options.Start(ctx)
	if e != nil {
		return startupFailure(options, "desktop_backend_start_failed")
	}
	h.backend = backend
	h.backend.URL, e = validateURL(backend.URL)
	if e != nil {
		return startupFailure(options, "desktop_backend_origin_invalid")
	}
	tray := h.app.SystemTray.New()
	tray.SetIcon(appIcon())
	tray.SetTooltip("CheckinMyFreeAPI - 签到管理")
	menu := application.NewMenu()
	menu.Add("打开控制台").OnClick(func(*application.Context) { h.activator.request("/") })
	menu.Add("查看 Status").OnClick(func(*application.Context) { h.activator.request("/status") })
	menu.Add("在浏览器中打开").OnClick(func(*application.Context) {
		if platform.OpenBrowser(h.backend.URL) != nil {
			log.Print("无法打开系统浏览器")
		}
	})
	menu.AddSeparator()
	menu.Add("退出程序").OnClick(func(*application.Context) { h.quit() })
	tray.SetMenu(menu)
	tray.OnClick(func() { h.activator.request("/") })
	h.app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		h.activator.start(options.Path, options.Hidden)
		if h.backend.Done != nil {
			go func() {
				select {
				case <-h.backend.Done:
					h.quit()
				case <-ctx.Done():
				}
			}()
		}
	})
	if e = h.app.Run(); e != nil {
		return e
	}
	h.stop()
	return h.stopError
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
