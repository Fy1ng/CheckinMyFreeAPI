//go:build !windows

package desktopcontrol

import (
	"os"
	"syscall"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"golang.org/x/sys/unix"
)

func protectControl(path, dataDir string) error { return platform.ProtectFile(path) }
func openControl(path, dataDir string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrUnavailable
		}
		return nil, ErrUntrusted
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, ErrUntrusted
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		f.Close()
		return nil, ErrUntrusted
	}
	return f, nil
}
