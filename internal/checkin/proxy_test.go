package checkin

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestProxyValidationAndNoDefaultFallback(t *testing.T) {
	for _, proxy := range []string{"socks5://user:password@127.0.0.1:1080", "socks5://u%40example:p%3Aa%40ss@localhost:1080", "socks5://%E7%94%A8%E6%88%B7:%E5%AF%86%E7%A0%81@localhost:1080", "socks5://localhost:1080", "http://u:p@example.com:8080", "https://u:p@[::1]:8080"} {
		if _, err := ResolveProxy(Document{"proxy": proxy}, nil); err != nil {
			t.Fatalf("valid proxy rejected: %v", err)
		}
	}
	for _, proxy := range []string{"socks5://u@localhost:1080", "socks5://:p@localhost:1080", "socks5://u:@localhost:1080", "socks5://u:%00@localhost:1080", "socks5://u:%7F@localhost:1080", "socks5://u:%FF@localhost:1080", "socks5://u:%zz@localhost:1080", "socks5://" + strings.Repeat("a", 256) + ":p@localhost:1080", "socks4://u:p@localhost:1080", "http://localhost", "http://localhost:0", "http://localhost:99999", "http://localhost:123/path", "http://localhost:123?x=y", "http://localhost:123#frag", "http://bad_host:123", "http://localhost:123\r\n", "http://localhost\\evil:123"} {
		if _, err := ResolveProxy(Document{"proxy": proxy}, nil); err == nil {
			t.Fatal("invalid proxy accepted")
		}
	}
	if _, err := ResolveProxy(Document{"proxy": "default"}, Document{}); err == nil {
		t.Fatal("missing default proxy fell back")
	}
	if p, err := ResolveProxy(Document{"proxy": "direct"}, Document{"proxy_url": "invalid"}); err != nil || p != "" {
		t.Fatal("explicit direct invalid")
	}
}

func TestSOCKS5ActuallySendsDecodedAuthenticationAndDoesNotFallback(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 2)
		if _, e = io.ReadFull(conn, header); e != nil {
			done <- e
			return
		}
		methods := make([]byte, int(header[1]))
		if _, e = io.ReadFull(conn, methods); e != nil {
			done <- e
			return
		}
		if header[0] != 5 {
			done <- fmt.Errorf("wrong SOCKS version")
			return
		}
		if _, e = conn.Write([]byte{5, 2}); e != nil {
			done <- e
			return
		}
		if _, e = io.ReadFull(conn, header); e != nil {
			done <- e
			return
		}
		user := make([]byte, int(header[1]))
		if _, e = io.ReadFull(conn, user); e != nil {
			done <- e
			return
		}
		length := make([]byte, 1)
		if _, e = io.ReadFull(conn, length); e != nil {
			done <- e
			return
		}
		password := make([]byte, int(length[0]))
		if _, e = io.ReadFull(conn, password); e != nil {
			done <- e
			return
		}
		if string(user) != "用户@example" || string(password) != "密码:p@ss" {
			done <- fmt.Errorf("RFC1929 credential decoding differs")
			return
		}
		_, e = conn.Write([]byte{1, 1})
		done <- e
	}()
	a := testAccount()
	a["proxy"] = "socks5://%E7%94%A8%E6%88%B7%40example:%E5%AF%86%E7%A0%81%3Ap%40ss@" + listener.Addr().String()
	r := New(Document{"http": Document{"timeout_seconds": 5}}, &memorySessions{})
	result := runTest(r, a)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	assertReason(t, result, "failed", "proxy_authentication_failed")
	encoded := fmt.Sprint(result)
	if strings.Contains(encoded, "@example") || strings.Contains(encoded, "p@ss") {
		t.Fatal("proxy credentials leaked")
	}
}

func TestHTTPProxyConnectAuthenticationIsIsolated(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		req, e := http.ReadRequest(bufio.NewReader(conn))
		if e != nil {
			done <- e
			return
		}
		if req.Method != "CONNECT" || req.Host != "anyrouter.top:443" || req.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:password")) {
			done <- fmt.Errorf("wrong CONNECT proxy credentials")
			return
		}
		_, e = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		done <- e
	}()
	a := testAccount()
	a["proxy"] = "http://user:password@" + listener.Addr().String()
	r := New(Document{"http": Document{"timeout_seconds": 5}}, &memorySessions{})
	result := r.Execute(context.Background(), a, nil)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	assertReason(t, result, "failed", "proxy_authentication_failed")
}
