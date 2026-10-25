//go:build windows

package platform

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func commandLine(c Launch) string {
	if strings.EqualFold(filepath.Base(c.Executable), "checkin-cli.exe") {
		candidate := filepath.Join(filepath.Dir(c.Executable), "checkin.exe")
		if info, e := os.Lstat(candidate); e == nil && info.Mode().IsRegular() {
			c.Executable = candidate
		}
	}
	a := []string{syscall.EscapeArg(c.Executable)}
	for _, v := range c.Args() {
		a = append(a, syscall.EscapeArg(v))
	}
	return strings.Join(a, " ")
}

func Autostart(c Launch, action string) (bool, error) {
	if e := c.Validate(); e != nil {
		return false, e
	}
	if action == "status" {
		k, e := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
		if errors.Is(e, registry.ErrNotExist) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		defer k.Close()
		v, _, e := k.GetStringValue(ServiceName)
		if errors.Is(e, registry.ErrNotExist) {
			return false, nil
		}
		return v == commandLine(c), e
	}
	k, _, e := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if e != nil {
		return false, e
	}
	defer k.Close()
	switch action {
	case "install":
		return true, k.SetStringValue(ServiceName, commandLine(c))
	case "remove":
		e = k.DeleteValue(ServiceName)
		if errors.Is(e, registry.ErrNotExist) {
			e = nil
		}
		return false, e
	}
	return false, errors.New("自启操作无效")
}

func Service(c Launch, action string) error {
	if e := c.Validate(); e != nil {
		return e
	}
	m, e := mgr.Connect()
	if e != nil {
		return errors.New("Windows 服务操作需要管理员权限")
	}
	defer m.Disconnect()
	if action == "install" {
		s, e := m.CreateService(ServiceName, c.Executable, mgr.Config{DisplayName: ServiceName, Description: "NewAPI check-in and balance monitor", StartType: mgr.StartAutomatic, DelayedAutoStart: true}, c.Args()...)
		if e != nil {
			return e
		}
		defer s.Close()
		_ = s.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: 10000000000}}, 86400)
		return nil
	}
	s, e := m.OpenService(ServiceName)
	if e != nil {
		return e
	}
	defer s.Close()
	switch action {
	case "start":
		return s.Start()
	case "stop":
		_, e = s.Control(svc.Stop)
		return e
	case "uninstall":
		status, e := s.Query()
		if e != nil {
			return e
		}
		if status.State != svc.Stopped {
			return errors.New("请先停止服务再卸载")
		}
		return s.Delete()
	case "status":
		_, e = s.Query()
		return e
	}
	return errors.New("服务操作无效")
}

type serviceHandler struct{ run func(context.Context) error }

func (h serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes <- svc.Status{State: svc.StartPending}
	done := make(chan error, 1)
	go func() { done <- h.run(ctx) }()
	current := svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	changes <- current
	for {
		select {
		case e := <-done:
			if e != nil {
				return true, 1
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				changes <- current
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				cancel()
				if e := <-done; e != nil {
					return true, 1
				}
				return false, 0
			}
		}
	}
}
func RunService(run func(context.Context) error) (bool, error) {
	inside, e := svc.IsWindowsService()
	if e != nil || !inside {
		return false, e
	}
	return true, svc.Run(ServiceName, serviceHandler{run})
}
func Background(c Launch) error {
	cmd := exec.Command(c.Executable, c.Args()...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.DETACHED_PROCESS | windows.CREATE_NEW_PROCESS_GROUP}
	return cmd.Start()
}
func OpenBrowser(address string) error {
	cmd := exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", address)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd.Start()
}
