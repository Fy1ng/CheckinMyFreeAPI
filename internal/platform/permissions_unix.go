//go:build !windows

package platform

import "os"

func ProtectFile(path string) error      { return os.Chmod(path, 0600) }
func protectDirectory(path string) error { return os.Chmod(path, 0700) }
