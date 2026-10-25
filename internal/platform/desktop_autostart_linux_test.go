//go:build linux

package platform

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDesktopAutostartUsesSessionEntryAndHiddenGUI(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", root)
	c := Launch{Executable: filepath.Join(root, "app%name"), DataDir: filepath.Join(root, "private data"), KeyFile: filepath.Join(root, "private data", "master.key"), Host: "127.0.0.1", Port: 8765, Desktop: true}
	entry, e := desktopEntry(c)
	if e != nil {
		t.Fatal(e)
	}
	for _, value := range []string{`"app" "--hidden"`, `app%%name`, "Terminal=false"} {
		if !strings.Contains(entry, value) {
			t.Fatal(value, entry)
		}
	}
	if enabled, e := Autostart(c, "install"); e != nil || !enabled {
		t.Fatal(enabled, e)
	}
	if enabled, e := Autostart(c, "status"); e != nil || !enabled {
		t.Fatal(enabled, e)
	}
	if enabled, e := Autostart(c, "remove"); e != nil || enabled {
		t.Fatal(enabled, e)
	}
	if enabled, e := Autostart(c, "status"); e != nil || enabled {
		t.Fatal(enabled, e)
	}
	c.PublicURL = "bad\nvalue"
	if _, e := desktopEntry(c); e == nil {
		t.Fatal("newline accepted")
	}
}

func TestLocalHeadlessUnitRetainsExplicitLocalPolicy(t *testing.T) {
	root := t.TempDir()
	c := Launch{Executable: filepath.Join(root, "checkin"), DataDir: root, KeyFile: filepath.Join(root, "master.key"), Host: "127.0.0.1", Port: 8765, LocalMode: true}
	content, e := unit(c, true)
	if e != nil || !strings.Contains(content, " --local\n") {
		t.Fatal("local policy omitted from systemd unit", content, e)
	}
	c.Host = "0.0.0.0"
	if _, e = unit(c, true); e == nil {
		t.Fatal("unsafe local unit accepted")
	}
}
