package auth

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// Access uses an explicit public origin and individual proxy addresses. Forwarded
// Host headers never broaden the list of allowed application origins.
type Access struct {
	PublicOrigin    string
	publicAuthority string
	peers           map[netip.Addr]bool
}

func NewAccess(public string, peers []string) (*Access, error) {
	a := &Access{peers: make(map[netip.Addr]bool)}
	if public != "" {
		u, err := url.Parse(public)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || !asciiAuthority(public) || loopbackName(u.Hostname()) {
			return nil, errors.New("CHECKIN_WEB_PUBLIC_URL must be an HTTPS origin without a path, query or credentials")
		}
		authority, err := normalizeAuthority(u.Host, "443")
		if err != nil {
			return nil, err
		}
		a.publicAuthority, a.PublicOrigin = authority, "https://"+authority
	}
	if len(peers) > 32 {
		return nil, errors.New("at most 32 individual proxy IP addresses are allowed")
	}
	for _, p := range peers {
		ip, err := netip.ParseAddr(p)
		if err != nil || ip.Zone() != "" {
			return nil, errors.New("trusted proxy must be an individual IP address")
		}
		a.peers[ip.Unmap()] = true
	}
	return a, nil
}

func asciiAuthority(s string) bool {
	for _, c := range s {
		if c <= 32 || c >= 127 || c == '\\' {
			return false
		}
	}
	return s != ""
}

func normalizeAuthority(value, defaultPort string) (string, error) {
	if !asciiAuthority(value) || strings.HasSuffix(value, ":") {
		return "", errors.New("invalid request host")
	}
	u, err := url.Parse("http://" + value)
	if err != nil || u.Host != value || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Hostname() == "" {
		return "", errors.New("invalid request host")
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		ip, err := netip.ParseAddr(host)
		if err != nil || ip.Zone() != "" {
			return "", errors.New("invalid request host")
		}
		host = "[" + host + "]"
	} else {
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return "", errors.New("invalid request host")
			}
		}
	}
	port := u.Port()
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", errors.New("invalid request port")
		}
		if port != defaultPort {
			host += ":" + port
		}
	}
	return host, nil
}

func loopbackName(s string) bool { return s == "localhost" || s == "127.0.0.1" || s == "::1" }

func peerIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}

func (a *Access) TrustedPeer(r *http.Request) bool { return a.peers[peerIP(r)] }

func (a *Access) Origin(r *http.Request) (string, error) {
	authority, err := normalizeAuthority(r.Host, "")
	if err != nil {
		return "", failure(403, "请求域名未获允许")
	}
	publicAuthority, _ := normalizeAuthority(r.Host, "443")
	if a.PublicOrigin != "" && publicAuthority == a.publicAuthority {
		if r.TLS == nil && !(a.TrustedPeer(r) && r.Header.Get("X-Forwarded-Proto") == "https") {
			return "", failure(403, "公网访问需要通过受信任的 HTTPS 入口")
		}
		return a.PublicOrigin, nil
	}
	u, _ := url.Parse("http://" + authority)
	if !loopbackName(u.Hostname()) {
		return "", failure(403, "请求域名未获允许")
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host, nil
}

func (a *Access) ClientIP(r *http.Request) string {
	if a.TrustedPeer(r) {
		if ip, err := netip.ParseAddr(r.Header.Get("X-Forwarded-For")); err == nil && ip.Zone() == "" {
			return ip.Unmap().String()
		}
	}
	ip := peerIP(r)
	if !ip.IsValid() {
		return "unknown"
	}
	return ip.String()
}

func (a *Access) PrivateRecovery(r *http.Request, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || !loopbackName(u.Hostname()) {
		return false
	}
	for key := range r.Header {
		k := strings.ToLower(key)
		if k == "forwarded" || strings.HasPrefix(k, "x-forwarded-") {
			return false
		}
	}
	return peerIP(r).IsLoopback() || a.TrustedPeer(r)
}
