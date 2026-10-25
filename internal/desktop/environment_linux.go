//go:build desktop && linux

package desktop

import (
	"errors"
	"os"
)

func checkEnvironment() error {
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return errors.New("桌面版需要图形会话, 无桌面服务器请使用 serve 模式")
	}
	return nil
}
func reportEnvironmentError()   {}
func reportStartupError(string) {}
