package platform

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLockExclusiveAndReleased(t *testing.T) {
	p := filepath.Join(t.TempDir(), "service.lock")
	f, e := Lock(p)
	if e != nil {
		t.Fatal(e)
	}
	if second, e := Lock(p); e == nil {
		second.Close()
		t.Fatal("second lock accepted")
	}
	f.Close()
	third, e := Lock(p)
	if e != nil {
		t.Fatal(e)
	}
	third.Close()
}
func TestPrivateFileRejectsDirectory(t *testing.T) {
	if PrivateFile(t.TempDir()) == nil {
		t.Fatal("directory accepted")
	}
}
func TestSystemdQuoting(t *testing.T) {
	base := t.TempDir()
	exe := filepath.Join(base, "checkin%test")
	data := filepath.Join(base, "with spaces")
	unit, e := SystemdUnit(exe, data, filepath.Join(data, "master.key"), "127.0.0.1", 8765)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(unit, "checkin%%test") || !strings.Contains(unit, `ReadWritePaths="`) {
		t.Fatal(unit)
	}
	if _, e := SystemdUnit(exe+"\nExecStart=bad", data, data, "127.0.0.1", 1); e == nil {
		t.Fatal("newline accepted")
	}
}
