//go:build !desktop || (!windows && !linux)

package desktop

import "errors"

func Available() bool { return false }
func Run(options Options) error {
	return errors.New("此程序未包含桌面界面, 请使用桌面版本或通过浏览器访问 WebUI")
}
