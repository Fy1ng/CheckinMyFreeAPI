//go:build desktop && desktoptest && windows

// This disposable fixture is never linked into the released application.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/app"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/desktop"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
)

func count(path string) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		panic(e)
	}
	_, _ = f.WriteString("1\n")
	f.Close()
}
func main() {
	data := flag.String("data-dir", "", "temporary data directory")
	port := flag.Int("port", 0, "loopback port")
	hidden := flag.Bool("hidden", false, "hide window")
	page := flag.String("page", "/", "initial local page")
	flag.Parse()
	if *data == "" || *port < 1024 {
		panic("disposable test data and port required")
	}
	e := desktop.Run(desktop.Options{DataDir: *data, Version: "native-test", Path: *page, Hidden: *hidden, Start: func(ctx context.Context) (desktop.Backend, error) {
		count(filepath.Join(*data, "fixture-start-count"))
		ln, e := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(*port))
		if e != nil {
			return desktop.Backend{}, e
		}
		done := make(chan struct{})
		var once sync.Once
		finish := func() { once.Do(func() { close(done) }) }
		launch := platform.Launch{Executable: os.Args[0], DataDir: *data, KeyFile: filepath.Join(*data, "fixture.key"), Host: "127.0.0.1", Port: *port}
		a, e := app.New(ctx, app.Options{DataDir: *data, Key: bytes.Repeat([]byte{44}, 32), Password: "native-desktop-test-password", DisableScheduler: true, Launch: launch, Shutdown: finish})
		if e != nil {
			ln.Close()
			return desktop.Backend{}, e
		}
		mux := http.NewServeMux()
		mux.HandleFunc("POST /fixture/quit", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(202)
			go func() { time.Sleep(100 * time.Millisecond); finish() }()
		})
		mux.Handle("/", a)
		srv := &http.Server{Handler: mux, ReadHeaderTimeout: 3 * time.Second}
		go func() { _ = srv.Serve(ln) }()
		stop := func() error {
			count(filepath.Join(*data, "fixture-stop-count"))
			finish()
			stopCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = srv.Shutdown(stopCtx)
			return a.Close()
		}
		return desktop.Backend{URL: fmt.Sprintf("http://localhost:%d", *port), Stop: stop, Done: done}, nil
	}})
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
