package platform

import (
	"fmt"
	"strconv"
)

type Launch struct {
	Executable, DataDir, KeyFile, Host, PublicURL, TrustedProxyIPs string
	Port                                                           int
	Desktop                                                        bool
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
	return a
}

func (c Launch) Validate() error {
	if c.Executable == "" || c.DataDir == "" || c.KeyFile == "" || c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("启动配置无效")
	}
	return nil
}
