//go:build !windows

package desktopcontrol

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestUnixPermissionsAndSymlinksAreRejected(t *testing.T) {
	dir, i, _ := fixture(t)
	path := filepath.Join(dir, FileName)
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Discover(context.Background(), dir); !errors.Is(err, ErrUntrusted) {
		t.Fatal("public record accepted", err)
	}
	os.Chmod(path, 0600)
	i.Close()
	target := filepath.Join(t.TempDir(), "unrelated-file")
	os.WriteFile(target, []byte("untouched"), 0600)
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(dir, "http://localhost:8765"); !errors.Is(err, ErrUntrusted) {
		t.Fatal("symlink overwritten", err)
	}
	if _, err := Discover(context.Background(), dir); !errors.Is(err, ErrUntrusted) {
		t.Fatal("symlink read", err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "untouched" {
		t.Fatal("symlink target changed")
	}
	os.Remove(path)
	linkedDir := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, linkedDir); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(linkedDir, "http://localhost:8765"); !errors.Is(err, ErrUntrusted) {
		t.Fatal("symlink directory accepted", err)
	}
}
