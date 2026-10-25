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
	"sort"
	"strings"
)

type module struct {
	Path, Version, Dir string
	Main               bool
}

func main() {
	out := flag.String("out", "", "destination notice file")
	flag.Parse()
	if *out == "" {
		fail(errors.New("--out is required"))
	}
	command := exec.Command("go", "list", "-mod=readonly", "-deps", "-json", "./cmd/checkin")
	data, e := command.Output()
	if e != nil {
		fail(errors.New("could not resolve linked Go modules"))
	}
	modules := map[string]module{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		var pkg struct{ Module *module }
		e = decoder.Decode(&pkg)
		if e == io.EOF {
			break
		}
		if e != nil {
			fail(e)
		}
		if pkg.Module != nil && !pkg.Module.Main {
			modules[pkg.Module.Path] = *pkg.Module
		}
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
			if file.IsDir() || !(upper == "LICENSE" || strings.HasPrefix(upper, "LICENSE.") || upper == "COPYING" || strings.HasPrefix(upper, "COPYING.")) {
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
func fail(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
