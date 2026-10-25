// Command license-notices collects licenses for modules linked into checkin.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

type module struct {
	Path, Version, Dir string
	Main               bool
}

func main() {
	out := flag.String("out", "", "destination notice file")
	desktop := flag.Bool("desktop", false, "include Windows desktop-linked modules")
	linuxDesktop := flag.Bool("linux-desktop", false, "include modules for the current native Linux GTK desktop")
	flag.Parse()
	if *out == "" {
		fail(errors.New("--out is required"))
	}
	modules := map[string]module{}
	if e := collect(modules, "nogui", runtime.GOOS, runtime.GOARCH, "0"); e != nil {
		fail(e)
	}
	if *desktop {
		if e := collect(modules, "desktop,production", "windows", "amd64", "0"); e != nil {
			fail(e)
		}
	}
	if *linuxDesktop {
		if runtime.GOOS != "linux" {
			fail(errors.New("--linux-desktop requires a native Linux host with GTK development libraries"))
		}
		if e := collect(modules, "desktop,production,gtk3", "linux", runtime.GOARCH, "1"); e != nil {
			fail(e)
		}
	}
	if (*desktop || *linuxDesktop) && modules["github.com/wailsapp/wails/v3"].Path == "" {
		fail(errors.New("desktop target does not link Wails; check the desktop build tag before publishing"))
	}
	root, e := exec.Command("go", "env", "GOROOT").Output()
	if e != nil {
		fail(e)
	}
	var text strings.Builder
	text.WriteString("CheckinMyFreeAPI standalone dependency licenses\n\n")
	goLicense, e := os.ReadFile(filepath.Join(strings.TrimSpace(string(root)), "LICENSE"))
	if e != nil {
		fail(e)
	}
	fmt.Fprintf(&text, "=== Go standard library ===\n\n%s\n\n", goLicense)
	names := make([]string, 0, len(modules))
	for name := range modules {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		m := modules[name]
		files, e := os.ReadDir(m.Dir)
		if e != nil {
			fail(fmt.Errorf("cannot inspect license for %s", name))
		}
		found := false
		for _, file := range files {
			upper := strings.ToUpper(file.Name())
			if file.IsDir() || !licenseFile(upper) {
				continue
			}
			license, e := os.ReadFile(filepath.Join(m.Dir, file.Name()))
			if e != nil {
				fail(e)
			}
			fmt.Fprintf(&text, "=== %s %s / %s ===\n\n%s\n\n", m.Path, m.Version, file.Name(), license)
			found = true
		}
		if !found {
			fail(fmt.Errorf("license text missing for %s", name))
		}
	}
	if e = os.WriteFile(*out, []byte(text.String()), 0644); e != nil {
		fail(e)
	}
	fmt.Printf("Collected Go standard library and %d linked module licenses.\n", len(modules))
}

func collect(modules map[string]module, tags, goos, goarch, cgo string) error {
	command := exec.Command("go", "list", "-mod=readonly", "-tags="+tags, "-deps", "-json", "./cmd/checkin")
	command.Env = environment(map[string]string{"GOOS": goos, "GOARCH": goarch, "CGO_ENABLED": cgo})
	command.Stderr = os.Stderr
	data, e := command.Output()
	if e != nil {
		return fmt.Errorf("could not resolve linked Go modules for %s/%s (%s): %w", goos, goarch, tags, e)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var pkg struct{ Module *module }
		e = decoder.Decode(&pkg)
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if pkg.Module != nil && !pkg.Module.Main {
			modules[pkg.Module.Path] = *pkg.Module
		}
	}
}

// The collector itself always runs on the host. Only go list targets another
// OS, so Windows GUI notices can be collected by a Linux release builder.
func environment(values map[string]string) []string {
	env := []string{}
	for _, entry := range os.Environ() {
		key, _, ok := strings.Cut(entry, "=")
		replaced := false
		if ok {
			for name := range values {
				if strings.EqualFold(key, name) {
					replaced = true
					break
				}
			}
		}
		if !replaced {
			env = append(env, entry)
		}
	}
	for key, value := range values {
		env = append(env, key+"="+value)
	}
	return env
}

func licenseFile(name string) bool {
	for _, base := range []string{"LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT"} {
		if name == base || strings.HasPrefix(name, base+".") || strings.HasPrefix(name, base+"-") || strings.HasPrefix(name, base+"_") {
			return true
		}
	}
	return false
}
func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
