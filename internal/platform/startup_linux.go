//go:build linux

package platform

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func unit(c Launch, system bool) (string, error) {
	text, e := SystemdUnit(c.Executable, c.DataDir, c.KeyFile, c.Host, c.Port)
	if e != nil {
		return "", e
	}
	quote := func(s string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "%", "%%").Replace(s) + `"`
	}
	for _, v := range []string{c.PublicURL, c.TrustedProxyIPs} {
		if strings.ContainsAny(v, "\n\r\x00") {
			return "", errors.New("服务参数无效")
		}
	}
	extra := ""
	if c.PublicURL != "" {
		extra += " --public-url " + quote(c.PublicURL)
	}
	if c.TrustedProxyIPs != "" {
		extra += " --trusted-proxy-ips " + quote(c.TrustedProxyIPs)
	}
	text = strings.Replace(text, "\nRestart=", ""+extra+"\nRestart=", 1)
	if system {
		text = strings.Replace(text, "WantedBy=default.target", "WantedBy=multi-user.target", 1)
	}
	return text, nil
}
func systemctl(system bool, args ...string) error {
	if !system {
		args = append([]string{"--user"}, args...)
	}
	if e := exec.Command("systemctl", args...).Run(); e != nil {
		return errors.New("systemd 操作失败, 请检查当前用户的服务管理权限")
	}
	return nil
}
func userUnitPath() (string, error) {
	root, e := os.UserConfigDir()
	return filepath.Join(root, "systemd", "user", "checkinmyfreeapi.service"), e
}
func Autostart(c Launch, action string) (bool, error) {
	if e := c.Validate(); e != nil {
		return false, e
	}
	path, e := userUnitPath()
	if e != nil {
		return false, e
	}
	switch action {
	case "status":
		return systemctl(false, "is-enabled", "--quiet", "checkinmyfreeapi.service") == nil, nil
	case "install":
		content, e := unit(c, false)
		if e != nil {
			return false, e
		}
		if e = PrivateDir(filepath.Dir(path)); e != nil {
			return false, e
		}
		if e = PrivateFile(path); e != nil {
			return false, e
		}
		if e = os.WriteFile(path, []byte(content), 0600); e != nil {
			return false, e
		}
		if e = systemctl(false, "daemon-reload"); e != nil {
			return false, e
		}
		e = systemctl(false, "enable", "checkinmyfreeapi.service")
		return e == nil, e
	case "remove":
		if e = systemctl(false, "disable", "checkinmyfreeapi.service"); e != nil {
			return false, e
		}
		if e = PrivateFile(path); e != nil {
			return false, e
		}
		e = os.Remove(path)
		if os.IsNotExist(e) {
			e = nil
		}
		if e != nil {
			return false, e
		}
		return false, systemctl(false, "daemon-reload")
	}
	return false, errors.New("自启操作无效")
}
func Service(c Launch, action string) error {
	const path = "/etc/systemd/system/checkinmyfreeapi.service"
	switch action {
	case "install":
		content, e := unit(c, true)
		if e != nil {
			return e
		}
		if e = PrivateFile(path); e != nil {
			return e
		}
		if e = os.WriteFile(path, []byte(content), 0644); e != nil {
			return e
		}
		if e = systemctl(true, "daemon-reload"); e != nil {
			return e
		}
		return systemctl(true, "enable", "checkinmyfreeapi.service")
	case "start", "stop":
		return systemctl(true, action, "checkinmyfreeapi.service")
	case "status":
		return systemctl(true, "is-active", "--quiet", "checkinmyfreeapi.service")
	case "uninstall":
		if systemctl(true, "is-active", "--quiet", "checkinmyfreeapi.service") == nil {
			return errors.New("请先停止服务再卸载")
		}
		if e := systemctl(true, "disable", "checkinmyfreeapi.service"); e != nil {
			return e
		}
		if e := PrivateFile(path); e != nil {
			return e
		}
		if e := os.Remove(path); e != nil {
			return e
		}
		return systemctl(true, "daemon-reload")
	}
	return errors.New("服务操作无效")
}
func RunService(run func(context.Context) error) (bool, error) { return false, nil }
func Background(c Launch) error {
	cmd := exec.Command(c.Executable, c.Args()...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start()
}
func OpenBrowser(address string) error { return exec.Command("xdg-open", address).Start() }
