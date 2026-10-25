//go:build !windows

package platform

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func Lock(path string) (*os.File, error) {
	if e := PrivateFile(path); e != nil {
		return nil, e
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("该数据目录已有服务或任务运行")
	}
	return f, nil
}
