//go:build windows

package platform

import (
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrivateACLDoesNotInheritSharedRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "app-data")
	if e := PrivateDir(dir); e != nil {
		t.Fatal(e)
	}
	file := filepath.Join(dir, "master.key")
	if e := os.WriteFile(file, []byte("fixture-key"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := ProtectFile(file); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{dir, file} {
		sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			t.Fatal(e)
		}
		sddl := sd.String()
		if !strings.Contains(sddl, "D:P") || strings.Contains(sddl, ";;;BU)") || strings.Contains(sddl, ";;;WD)") || strings.Contains(sddl, ";;;AU)") {
			t.Fatal("unprotected private ACL", sddl)
		}
	}
}
func TestCLIAutostartPrefersSilentSibling(t *testing.T) {
	dir := t.TempDir()
	gui := filepath.Join(dir, "checkin.exe")
	cli := filepath.Join(dir, "checkin-cli.exe")
	os.WriteFile(gui, []byte("fixture"), 0600)
	launch := Launch{Executable: cli, DataDir: dir, KeyFile: filepath.Join(dir, "master.key"), Host: "127.0.0.1", Port: 8765}
	line := commandLine(launch)
	if strings.Contains(line, "checkin-cli.exe") || !strings.Contains(line, "checkin.exe") {
		t.Fatal("CLI registered visible console", line)
	}
}
