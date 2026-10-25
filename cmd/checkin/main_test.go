package main

import (
	"bytes"
	"context"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyNeverReplaced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "master.key")
	first, e := loadKey(dir, path)
	if e != nil {
		t.Fatal(e)
	}
	second, e := loadKey(dir, path)
	if e != nil || !bytes.Equal(first, second) {
		t.Fatal("key replaced", e)
	}
	if e = os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(dir, "webui.sqlite3"), []byte("existing"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = loadKey(dir, path); e == nil {
		t.Fatal("missing key regenerated for an existing database")
	}
}

func TestServeRefusesOrphanedPythonWorkerLock(t *testing.T) {
	dir := t.TempDir()
	lock, e := platform.Lock(filepath.Join(dir, "execution.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	_, _, c, e := parse([]string{"serve", "--data-dir", dir})
	if e != nil {
		t.Fatal(e)
	}
	if e = serve(context.Background(), c); e == nil {
		t.Fatal("service started alongside an orphaned worker")
	}
	if _, e = os.Stat(c.launch.KeyFile); !os.IsNotExist(e) {
		t.Fatal("key mutated before obtaining both lifecycle locks")
	}
}
func TestKeyLengthAndFileType(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.key")
	os.WriteFile(p, []byte("invalid"), 0600)
	if _, e := loadKey(dir, p); e == nil {
		t.Fatal("invalid key accepted")
	}
	if _, e := loadKey(dir, dir); e == nil {
		t.Fatal("directory accepted")
	}
}
func TestParsePreservesExplicitStorageAndStartupArgs(t *testing.T) {
	dir := t.TempDir()
	_, _, c, e := parse([]string{"serve", "--data-dir", dir, "--key-file", filepath.Join(dir, "original.key"), "--port", "18765"})
	if e != nil {
		t.Fatal(e)
	}
	if c.launch.DataDir != dir || c.launch.Port != 18765 {
		t.Fatal(c)
	}
	if _, _, _, e = parse([]string{"serve", "--host", "untrusted.example"}); e == nil {
		t.Fatal("external bind accepted")
	}
	if _, _, _, e = parse([]string{"serve", "--port", "0"}); e == nil {
		t.Fatal("invalid port accepted")
	}
}
func TestLogRotationBounded(t *testing.T) {
	p := filepath.Join(t.TempDir(), "server.log")
	l := &rotatingLog{path: p}
	defer l.Close()
	data := bytes.Repeat([]byte("a"), 1024*1024)
	for i := 0; i < 23; i++ {
		if _, e := l.Write(data); e != nil {
			t.Fatal(e)
		}
	}
	for i := 1; i <= 3; i++ {
		info, e := os.Stat(p + "." + string(rune('0'+i)))
		if e != nil || info.Size() > 5*1024*1024 {
			t.Fatal("invalid log rotation", i, e)
		}
	}
	if _, e := os.Stat(p + ".4"); !os.IsNotExist(e) {
		t.Fatal("rotation not bounded")
	}
}
