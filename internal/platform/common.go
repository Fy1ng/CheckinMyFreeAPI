package platform

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const ServiceName = "CheckinMyFreeAPI"

func Executable() (string, error) {
	p, e := os.Executable()
	if e != nil {
		return "", e
	}
	return filepath.EvalSymlinks(p)
}

// PrivateDir rejects symlink components rather than following credential paths.
func PrivateDir(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for p := abs; ; p = filepath.Dir(p) {
		info, e := os.Lstat(p)
		if e == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("数据目录不能经过符号链接")
		}
		if e != nil && !os.IsNotExist(e) {
			return e
		}
		parent := filepath.Dir(p)
		if parent == p {
			break
		}
	}
	_, statErr := os.Stat(abs)
	if err = os.MkdirAll(abs, 0700); err != nil {
		return err
	}
	if os.IsNotExist(statErr) {
		return protectDirectory(abs)
	}
	return nil
}

func PrivateFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("数据或密钥路径必须为普通文件")
	}
	return nil
}

func SystemdUnit(exe, dataDir, keyFile, host string, port int) (string, error) {
	for _, p := range []string{exe, dataDir, keyFile, host} {
		if strings.ContainsAny(p, "\r\n\x00") {
			return "", errors.New("服务参数无效")
		}
	}
	if !filepath.IsAbs(exe) || !filepath.IsAbs(dataDir) || !filepath.IsAbs(keyFile) {
		return "", errors.New("服务路径必须为绝对路径")
	}
	// systemd expands percent specifiers even inside quotes.
	quote := func(s string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(s) + `"`
	}
	return fmt.Sprintf("[Unit]\nDescription=CheckinMyFreeAPI\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nExecStart=%s serve --data-dir %s --key-file %s --host %s --port %d\nRestart=on-failure\nRestartSec=10\nUMask=0077\nNoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=strict\nReadWritePaths=%s\n\n[Install]\nWantedBy=default.target\n", quote(exe), quote(dataDir), quote(keyFile), quote(host), port, quote(dataDir)), nil
}
