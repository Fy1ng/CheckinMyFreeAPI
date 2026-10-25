//go:build windows

package platform

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// Lock uses the same first-byte OS lock as the Python application.
func Lock(path string) (*os.File, error) {
	if e := PrivateFile(path); e != nil {
		return nil, e
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if info, err := f.Stat(); err == nil && info.Size() == 0 {
		_, _ = f.WriteAt([]byte{1}, 0)
	}
	err = windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
	if err != nil {
		f.Close()
		return nil, errors.New("该数据目录已有服务或任务运行")
	}
	return f, nil
}
