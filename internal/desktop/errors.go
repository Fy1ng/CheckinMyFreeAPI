package desktop

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
)

// Startup diagnostics contain fixed codes only. A backend's original exception
// can contain a URL, response or credential and is never copied into this log.
func startupFailure(options Options, code string) error {
	message := "桌面启动未完成, 请查看数据目录中的 desktop.log, 或运行 checkin-cli.exe serve 检查后台."
	path := filepath.Join(options.DataDir, "desktop.log")
	if platform.PrivateFile(path) == nil {
		if f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600); e == nil {
			if e = platform.ProtectFile(path); e == nil {
				_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().UTC().Format(time.RFC3339), code)
			}
			f.Close()
		}
	}
	if !options.Hidden {
		reportStartupError(message)
	}
	return errors.New(message)
}
