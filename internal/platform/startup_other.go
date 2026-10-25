//go:build !windows && !linux

package platform

import (
	"context"
	"errors"
)

func Autostart(c Launch, action string) (bool, error) {
	return false, errors.New("当前平台暂不支持自启")
}
func Service(c Launch, action string) error {
	return errors.New("当前平台暂不支持系统服务")
}
func RunService(run func(context.Context) error) (bool, error) { return false, nil }
func Background(c Launch) error                                { return errors.New("当前平台暂不支持后台启动") }
func OpenBrowser(address string) error                         { return errors.New("请手动打开本机 WebUI 地址") }
