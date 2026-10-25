package platform

import (
	"fmt"
	"strconv"
)

type Launch struct {
	Executable, DataDir, KeyFile, Host, PublicURL, TrustedProxyIPs string
	Port                                                           int
	Desktop                                                        bool
	LocalMode                                                      bool
}

func (c Launch) Args() []string {
	a := []string{"serve", "--data-dir", c.DataDir, "--key-file", c.KeyFile, "--host", c.Host, "--port", strconv.Itoa(c.Port)}
	if c.Desktop {
		a = append([]string{"app", "--hidden"}, a[1:]...)
	}
	if c.PublicURL != "" {
		a = append(a, "--public-url", c.PublicURL)
	}
	if c.TrustedProxyIPs != "" {
		a = append(a, "--trusted-proxy-ips", c.TrustedProxyIPs)
	}
	if c.LocalMode {
		a = append(a, "--local")
	} else if c.Desktop {
		a = append(a, "--local=false")
	}
	return a
}

func (c Launch) Validate() error {
	if c.Executable == "" || c.DataDir == "" || c.KeyFile == "" || c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("启动配置无效")
	}
	if c.LocalMode && (c.Host != "127.0.0.1" && c.Host != "::1" || c.PublicURL != "" || c.TrustedProxyIPs != "") {
		return fmt.Errorf("本地免认证模式仅允许本机监听, 不能配置公网入口或反向代理")
	}
	return nil
}
