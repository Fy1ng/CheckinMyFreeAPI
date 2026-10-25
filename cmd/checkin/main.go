// Command checkin runs the HTTP-only application without a Python runtime.
package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/app"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/auth"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/backup"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/desktop"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"golang.org/x/term"
)

var version = "dev"

type config struct {
	launch                                         platform.Launch
	passwordFile, backupFile, recoveryPasswordFile string
	background, confirm, clearPasskeys, hidden     bool
	page                                           string
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func defaultDir() string {
	root, e := os.UserConfigDir()
	if e != nil {
		return "checkin-data"
	}
	return filepath.Join(root, "CheckinMyFreeAPI")
}

func parse(args []string) (string, string, config, error) {
	command, action := "serve", ""
	if desktop.Available() {
		command = "app"
	}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command = args[0]
		args = args[1:]
	}
	if command == "autostart" || command == "service" || command == "security" || command == "backup" {
		if len(args) == 0 {
			return command, action, config{}, errors.New("请指定操作, 使用 --help 查看示例")
		}
		action = args[0]
		args = args[1:]
	}
	c := config{}
	f := flag.NewFlagSet("checkin "+command, flag.ContinueOnError)
	f.SetOutput(os.Stdout)
	f.StringVar(&c.launch.DataDir, "data-dir", env("CHECKIN_WEB_DATA_DIR", defaultDir()), "私有数据目录")
	f.StringVar(&c.launch.KeyFile, "key-file", os.Getenv("CHECKIN_WEB_KEY_FILE"), "原始32字节主密钥, 默认数据目录/master.key")
	f.StringVar(&c.launch.Host, "host", env("CHECKIN_WEB_HOST", "127.0.0.1"), "监听地址")
	port, _ := strconv.Atoi(env("CHECKIN_WEB_PORT", "8765"))
	f.IntVar(&c.launch.Port, "port", port, "本机WebUI端口")
	f.StringVar(&c.launch.PublicURL, "public-url", os.Getenv("CHECKIN_WEB_PUBLIC_URL"), "显式HTTPS管理origin")
	f.StringVar(&c.launch.TrustedProxyIPs, "trusted-proxy-ips", os.Getenv("CHECKIN_WEB_TRUSTED_PROXY_IPS"), "可信反向代理IP, 逗号分隔")
	f.StringVar(&c.passwordFile, "password-file", os.Getenv("CHECKIN_WEB_PASSWORD_FILE"), "首次管理密码文件, 未设置时通过本机页面初始化")
	f.BoolVar(&c.background, "background", false, "分离到后台, 不打开浏览器")
	f.BoolVar(&c.hidden, "hidden", false, "桌面启动时隐藏到托盘")
	f.StringVar(&c.page, "page", "/", "桌面初始页面: /, /status, /backups, /security")
	f.BoolVar(&c.confirm, "confirm", false, "确认离线安全恢复")
	f.BoolVar(&c.clearPasskeys, "clear-passkeys", false, "安全恢复时删除所有Passkey")
	f.StringVar(&c.backupFile, "file", "", "备份文件路径")
	f.StringVar(&c.recoveryPasswordFile, "recovery-password-file", "", "恢复密码文件, 未设置时终端安全输入")
	f.Usage = func() {
		fmt.Fprintf(f.Output(), "CheckinMyFreeAPI %s\n\n", version)
		fmt.Fprintln(f.Output(), "用法: checkin [app|serve|open|version] [选项]")
		fmt.Fprintln(f.Output(), "      checkin autostart install|remove|status [选项]")
		fmt.Fprintln(f.Output(), "      checkin service install|uninstall|start|stop|status [选项]")
		fmt.Fprintln(f.Output(), "      checkin security reset --confirm [--clear-passkeys] [选项]")
		fmt.Fprintln(f.Output(), "      checkin backup inspect|restore --file backup.nab [选项]")
		fmt.Fprintln(f.Output())
		f.PrintDefaults()
	}
	if e := f.Parse(args); e != nil {
		return command, action, c, e
	}
	if f.NArg() != 0 {
		return command, action, c, errors.New("存在无法识别的参数")
	}
	var e error
	if c.launch.Executable, e = platform.Executable(); e != nil {
		return command, action, c, e
	}
	if c.launch.DataDir, e = filepath.Abs(c.launch.DataDir); e != nil {
		return command, action, c, e
	}
	if c.launch.KeyFile == "" {
		c.launch.KeyFile = filepath.Join(c.launch.DataDir, "master.key")
	}
	if c.launch.KeyFile, e = filepath.Abs(c.launch.KeyFile); e != nil {
		return command, action, c, e
	}
	if c.launch.Host != "127.0.0.1" && c.launch.Host != "::1" && c.launch.Host != "0.0.0.0" {
		return command, action, c, errors.New("监听地址仅允许127.0.0.1, ::1或容器内部0.0.0.0")
	}
	if e = c.launch.Validate(); e != nil {
		return command, action, c, e
	}
	peers := []string{}
	for _, peer := range strings.Split(c.launch.TrustedProxyIPs, ",") {
		if peer = strings.TrimSpace(peer); peer != "" {
			peers = append(peers, peer)
		}
	}
	if _, e = auth.NewAccess(c.launch.PublicURL, peers); e != nil {
		return command, action, c, e
	}
	return command, action, c, nil
}

func main() {
	if e := run(os.Args[1:]); e != nil && !errors.Is(e, flag.ErrHelp) {
		fmt.Fprintln(os.Stderr, "CheckinMyFreeAPI:", e)
		os.Exit(1)
	}
}
func run(args []string) error {
	command, action, c, e := parse(args)
	if e != nil {
		return e
	}
	switch command {
	case "app":
		if !desktop.Available() {
			return errors.New("当前为无GUI服务器版, 请使用桌面版程序或通过浏览器管理")
		}
		c.launch.Desktop = true
		return desktop.Run(desktop.Options{DataDir: c.launch.DataDir, Version: version, Path: c.page, Hidden: c.hidden || c.background, Start: func(ctx context.Context) (desktop.Backend, error) {
			backend, address, e := startOrAttachBackend(ctx, c)
			if e != nil {
				return desktop.Backend{}, e
			}
			if backend == nil {
				return desktop.Backend{URL: address}, nil
			}
			return desktop.Backend{URL: address, Stop: backend.Stop, Done: backend.Done}, nil
		}})
	case "version":
		fmt.Println("CheckinMyFreeAPI", version)
		return nil
	case "open":
		return platform.OpenBrowser("http://" + net.JoinHostPort("127.0.0.1", strconv.Itoa(c.launch.Port)))
	case "autostart":
		c.launch.Desktop = desktop.Available()
		enabled, e := platform.Autostart(c.launch, action)
		if e != nil {
			return e
		}
		fmt.Printf("autostart=%t\n", enabled)
		return nil
	case "service":
		if e = platform.Service(c.launch, action); e == nil {
			fmt.Println("服务操作已完成")
		}
		return e
	case "security":
		if action != "reset" || !c.confirm {
			return errors.New("离线恢复需要 security reset --confirm, 并先停止服务")
		}
		return reset(c)
	case "backup":
		return backupCommand(c, action)
	case "serve":
		if c.background {
			return platform.Background(c.launch)
		}
		if handled, e := platform.RunService(func(ctx context.Context) error { return serve(ctx, c) }); handled || e != nil {
			return e
		}
		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()
		return serve(ctx, c)
	default:
		return errors.New("未知命令, 使用 checkin --help 查看用法")
	}
}

func loadKey(dataDir, path string) ([]byte, error) {
	if e := platform.PrivateFile(path); e != nil {
		return nil, e
	}
	key, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		if _, dbErr := os.Stat(filepath.Join(dataDir, "webui.sqlite3")); !os.IsNotExist(dbErr) {
			return nil, errors.New("已有数据库但主密钥缺失, 请恢复对应密钥")
		}
		if e = platform.PrivateDir(filepath.Dir(path)); e != nil {
			return nil, e
		}
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return nil, e
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return nil, e
		}
		if e = platform.ProtectFile(path); e != nil {
			f.Close()
			os.Remove(path)
			return nil, e
		}
		if _, e = f.Write(key); e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e != nil {
			return nil, e
		}
	} else if e != nil {
		return nil, e
	}
	if len(key) != 32 {
		return nil, errors.New("主密钥文件必须是32原始字节")
	}
	return key, nil
}
func readSecretFile(path string) (string, error) {
	if e := platform.PrivateFile(path); e != nil {
		return "", e
	}
	f, e := os.Open(path)
	if e != nil {
		return "", errors.New("密码文件无法读取")
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 4097))
	if e != nil || len(data) > 4096 {
		return "", errors.New("密码文件无效")
	}
	return strings.TrimSpace(string(data)), nil
}

func serve(parent context.Context, c config) error {
	backend, err := startOwnedBackend(parent, c)
	if err != nil {
		return err
	}
	defer backend.Stop()
	<-backend.Done
	return backend.Err()
}
func reset(c config) error {
	if e := platform.PrivateDir(c.launch.DataDir); e != nil {
		return e
	}
	lock, e := platform.Lock(filepath.Join(c.launch.DataDir, "service.lock"))
	if e != nil {
		return e
	}
	defer lock.Close()
	path := filepath.Join(c.launch.DataDir, "webui.sqlite3")
	if e = platform.PrivateFile(path); e != nil {
		return e
	}
	if _, e = os.Stat(path); e != nil {
		return errors.New("数据库不存在")
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if e = auth.Reset(db, c.clearPasskeys); e != nil {
		return e
	}
	fmt.Println("已恢复密码模式并撤销旧管理会话. 管理密码保持原值.")
	return nil
}
func recoveryPassword(c config) (string, error) {
	if c.recoveryPasswordFile != "" {
		return readSecretFile(c.recoveryPasswordFile)
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("需要交互终端或 --recovery-password-file")
	}
	fmt.Fprint(os.Stderr, "备份恢复密码: ")
	b, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), e
}
func backupCommand(c config, action string) error {
	if action != "inspect" && action != "restore" {
		return errors.New("备份操作仅支持 inspect 或 restore")
	}
	if c.backupFile == "" {
		return errors.New("请通过 --file 指定备份文件")
	}
	if e := platform.PrivateFile(c.backupFile); e != nil {
		return e
	}
	f, e := os.Open(c.backupFile)
	if e != nil {
		return errors.New("备份文件无法读取")
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, backup.MaxBackupBytes+1))
	if e != nil || len(data) > backup.MaxBackupBytes {
		return errors.New("备份文件无效或超出64MiB限制")
	}
	password, e := recoveryPassword(c)
	if e != nil {
		return e
	}
	var result map[string]any
	if action == "inspect" {
		result, e = backup.Inspect(data, password)
	} else {
		if !c.confirm {
			return errors.New("离线恢复需要 --confirm, 且目标数据目录和密钥位置须为空")
		}
		if e = platform.PrivateDir(c.launch.DataDir); e != nil {
			return e
		}
		lock, err := platform.Lock(filepath.Join(c.launch.DataDir, "service.lock"))
		if err != nil {
			return err
		}
		defer lock.Close()
		result, e = backup.RestoreOffline(data, password, c.launch.DataDir, c.launch.KeyFile)
		if e == nil {
			settings, err := app.OpenRuntime(c.launch.DataDir)
			if err != nil {
				return err
			}
			s := settings.Get()
			s.RunOnStartup = false
			if err = settings.Save(s); err != nil {
				return err
			}
		}
	}
	if e != nil {
		return e
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

type rotatingLog struct {
	mu   sync.Mutex
	path string
	f    *os.File
	size int64
}

func (l *rotatingLog) Write(b []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		f, e := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return 0, e
		}
		l.f = f
		info, e := f.Stat()
		if e == nil {
			l.size = info.Size()
		}
	}
	if l.size+int64(len(b)) > 5*1024*1024 {
		l.f.Close()
		l.f = nil
		for i := 2; i >= 1; i-- {
			source := l.path + "." + strconv.Itoa(i)
			target := l.path + "." + strconv.Itoa(i+1)
			if e := platform.PrivateFile(source); e != nil {
				return 0, e
			}
			if e := platform.PrivateFile(target); e != nil {
				return 0, e
			}
			_ = os.Remove(target)
			_ = os.Rename(source, target)
		}
		target := l.path + ".1"
		if e := platform.PrivateFile(target); e != nil {
			return 0, e
		}
		_ = os.Remove(target)
		_ = os.Rename(l.path, target)
		f, e := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if e != nil {
			return 0, e
		}
		l.f = f
		l.size = 0
	}
	n, e := l.f.Write(b)
	l.size += int64(n)
	return n, e
}
func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f != nil {
		return l.f.Close()
	}
	return nil
}
