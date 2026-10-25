//go:build linux

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// Graphical session autostart carries DISPLAY and the session bus. A systemd
// server unit deliberately keeps running without either of those GUI resources.
func desktopEntry(c Launch) (string, error) {
	if e := c.Validate(); e != nil {
		return "", e
	}
	args := append([]string{c.Executable}, c.Args()...)
	quoted := make([]string, len(args))
	for i, value := range args {
		if strings.ContainsAny(value, "\r\n\x00") {
			return "", errors.New("自启参数无效")
		}
		quoted[i] = `"` + strings.NewReplacer(`\`, `\\\\`, `"`, `\\"`, `$`, `\\$`, "`", "\\`", "%", "%%").Replace(value) + `"`
	}
	return "[Desktop Entry]\nType=Application\nVersion=1.0\nName=CheckinMyFreeAPI\nComment=NewAPI check-in and balance monitor\nExec=" + strings.Join(quoted, " ") + "\nTerminal=false\nStartupNotify=false\nX-GNOME-Autostart-enabled=true\n", nil
}

func desktopAutostart(c Launch, action string) (bool, error) {
	root, e := os.UserConfigDir()
	if e != nil {
		return false, e
	}
	path := filepath.Join(root, "autostart", "checkinmyfreeapi.desktop")
	if e = PrivateFile(path); e != nil {
		return false, e
	}
	switch action {
	case "status":
		content, e := os.ReadFile(path)
		if os.IsNotExist(e) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		expected, e := desktopEntry(c)
		return string(content) == expected, e
	case "install":
		content, e := desktopEntry(c)
		if e != nil {
			return false, e
		}
		if e = PrivateDir(filepath.Dir(path)); e != nil {
			return false, e
		}
		if e = os.WriteFile(path, []byte(content), 0600); e != nil {
			return false, e
		}
		return true, nil
	case "remove":
		e = os.Remove(path)
		if os.IsNotExist(e) {
			e = nil
		}
		return false, e
	}
	return false, errors.New("自启操作无效")
}
