//go:build desktop && windows

package desktop

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func checkEnvironment() error {
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		for _, view := range []uint32{registry.WOW64_32KEY, registry.WOW64_64KEY} {
			key, e := registry.OpenKey(root, `SOFTWARE\Microsoft\EdgeUpdate\Clients`, registry.READ|view)
			if e != nil {
				continue
			}
			names, _ := key.ReadSubKeyNames(-1)
			for _, name := range names {
				client, e := registry.OpenKey(key, name, registry.READ|view)
				if e != nil {
					continue
				}
				label, _, _ := client.GetStringValue("name")
				version, _, _ := client.GetStringValue("pv")
				client.Close()
				if strings.Contains(strings.ToLower(label), "webview2") && version != "" && version != "0.0.0.0" {
					key.Close()
					return nil
				}
			}
			key.Close()
		}
	}
	return errors.New("未找到 Microsoft Edge WebView2 Runtime, 请安装后使用桌面版, 或通过控制台版本启动 WebUI")
}
func reportEnvironmentError() {
	reportStartupError("未找到 Microsoft Edge WebView2 Runtime. 请安装 WebView2 Runtime 后重试, 或运行 checkin-cli.exe serve 并通过浏览器访问 WebUI.")
}
func reportStartupError(text string) {
	message, _ := windows.UTF16PtrFromString(text)
	title, _ := windows.UTF16PtrFromString("CheckinMyFreeAPI")
	_, _, _ = windows.NewLazySystemDLL("user32.dll").NewProc("MessageBoxW").Call(0, uintptr(unsafe.Pointer(message)), uintptr(unsafe.Pointer(title)), 0x10)
}
