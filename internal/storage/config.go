package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

const SecretKeep = "__UNCHANGED_SECRET__"

var notificationNames = strings.Fields("EMAIL_USER EMAIL_PASS EMAIL_TO EMAIL_SENDER CUSTOM_SMTP_SERVER PUSHPLUS_TOKEN SERVERPUSHKEY DINGDING_WEBHOOK FEISHU_WEBHOOK WEIXIN_WEBHOOK GOTIFY_URL GOTIFY_TOKEN GOTIFY_PRIORITY TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID BARK_KEY BARK_SERVER FY1PUSH_SERVER FY1PUSH_TOKEN FY1PUSH_CHANNEL")
var secretNotificationNames = strings.Fields("EMAIL_PASS PUSHPLUS_TOKEN SERVERPUSHKEY DINGDING_WEBHOOK FEISHU_WEBHOOK WEIXIN_WEBHOOK GOTIFY_URL GOTIFY_TOKEN TELEGRAM_BOT_TOKEN BARK_KEY BARK_SERVER FY1PUSH_TOKEN")
var accountSecrets = []string{"password", "cookies", "system_access_token"}
var cookieName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
var digits = regexp.MustCompile(`^[0-9]+$`)
var clockPattern = regexp.MustCompile(`^(?:[01][0-9]|2[0-3]):[0-5][0-9]$`)

func DefaultConfig() Document {
	return Document{
		"schema_version": 2, "accounts": []any{}, "proxy_url": "", "notifications": Document{},
		"schedule":   Document{"enabled": false, "mode": "interval", "interval_minutes": 360, "cron": "0 8 * * *"},
		"monitoring": Document{"enabled": true, "interval_minutes": 60},
		"automation": Document{"low_balance": Document{"enabled": false, "threshold": 1, "cooldown_minutes": 360}, "recovery": Document{"enabled": false, "cooldown_minutes": 60}, "daily_summary": Document{"enabled": false, "time": "23:55"}},
		"backups":    Document{"enabled": false, "time": "03:00", "retain_count": 7, "password": ""},
		"http":       Document{"timeout_seconds": 30}, "webui_url": "",
	}
}
func allowed(d Document, names string) error {
	if d == nil {
		return errors.New("Configuration object is invalid")
	}
	set := map[string]bool{}
	for _, k := range strings.Fields(names) {
		set[k] = true
	}
	for k := range d {
		if !set[k] {
			return errors.New("Configuration contains an unsupported field")
		}
	}
	return nil
}
func validText(v any, max int, empty bool) error {
	s, ok := v.(string)
	if !ok || !utf8.ValidString(s) || utf8.RuneCountInString(s) > max || (!empty && s == "") {
		return errors.New("Configuration field has an invalid format or length")
	}
	for _, c := range s {
		if c < 32 || c == 127 {
			return errors.New("Configuration field contains control characters")
		}
	}
	if s == SecretKeep {
		return errors.New("A secret marker has no stored value; enter a value or clear the field")
	}
	return nil
}
func boolean(v any) error {
	if _, ok := v.(bool); !ok {
		return errors.New("Configuration switch must be true or false")
	}
	return nil
}
func integer(v any, lo, hi int) error {
	n, ok := Number(v)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < float64(lo) || n > float64(hi) {
		return fmt.Errorf("Configuration integer must be between %d and %d", lo, hi)
	}
	return nil
}
func threshold(v any) error {
	n, ok := Number(v)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 || n > 1e12 {
		return errors.New("Balance threshold must be a finite number between 0 and 1000000000000")
	}
	return nil
}
func mergeSettings(defaults Document, value any) (Document, error) {
	d := Object(value)
	if d == nil {
		return nil, errors.New("Configuration settings must be an object")
	}
	for k, v := range d {
		if _, ok := defaults[k]; !ok {
			return nil, errors.New("Configuration contains an unsupported field")
		}
		defaults[k] = v
	}
	return defaults, nil
}
func ValidProxy(value any, optional bool) (any, error) {
	if optional && value == nil {
		return nil, nil
	}
	if validText(value, 4096, false) != nil {
		return nil, errors.New("Proxy must be an HTTP(S) or SOCKS5 URL with explicit port")
	}
	s := strings.TrimSpace(String(value))
	if optional && (s == "direct" || s == "default") {
		return s, nil
	}
	u, e := url.Parse(s)
	if e != nil || !(u.Scheme == "http" || u.Scheme == "https" || u.Scheme == "socks5") || u.Hostname() == "" || u.Port() == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(s, "\\ \t\r\n") || !validHost(u.Hostname()) {
		return nil, errors.New("Proxy must be an HTTP(S) or SOCKS5 URL with explicit port")
	}
	p, e := strconv.Atoi(u.Port())
	if e != nil || p < 1 || p > 65535 {
		return nil, errors.New("Proxy port is invalid")
	}
	if u.Scheme == "socks5" && u.User != nil {
		password, has := u.User.Password()
		username := u.User.Username()
		if !has || len([]byte(username)) < 1 || len([]byte(username)) > 255 || len([]byte(password)) < 1 || len([]byte(password)) > 255 {
			return nil, errors.New("SOCKS5 authentication requires username and password of 1 to 255 UTF-8 bytes each")
		}
	}
	return s, nil
}
func validHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	ascii, err := idna.Lookup.ToASCII(host)
	if err != nil {
		return false
	}
	host = ascii
	host = strings.TrimSuffix(host, ".")
	if len(host) > 253 || host == "" {
		return false
	}
	for _, part := range strings.Split(host, ".") {
		if len(part) < 1 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func NormalizeOrigin(value any) (string, error) {
	if value == "" {
		return "", nil
	}
	if validText(value, 2048, false) != nil {
		return "", errors.New("WebUI URL is invalid")
	}
	s := strings.TrimSpace(String(value))
	u, e := url.Parse(s)
	if e != nil || !(u.Scheme == "https" || u.Scheme == "http") || u.Hostname() == "" || !validHost(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(s, "\\ \t\r\n") || strings.HasSuffix(u.Host, ":") {
		return "", errors.New("WebUI URL must be an HTTPS origin or HTTP loopback origin")
	}
	if u.Scheme == "http" {
		ip := net.ParseIP(u.Hostname())
		if u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return "", errors.New("HTTP WebUI URL must use loopback")
		}
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return "", errors.New("WebUI port is invalid")
		}
	}
	host := u.Hostname()
	if net.ParseIP(host) == nil {
		host, e = idna.Lookup.ToASCII(host)
		if e != nil {
			return "", errors.New("WebUI hostname is invalid")
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if u.Port() != "" {
		host += ":" + u.Port()
	}
	return u.Scheme + "://" + strings.ToLower(host), nil
}
func normalizeCookies(v any) (string, error) {
	parts := [][2]string{}
	if d := Object(v); d != nil {
		for k, v := range d {
			if _, ok := v.(string); !ok {
				return "", errors.New("Cookie value must be a string")
			}
			parts = append(parts, [2]string{k, String(v)})
		}
	} else {
		if e := validText(v, 65536, true); e != nil {
			return "", e
		}
		for _, p := range strings.Split(String(v), ";") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			kv := strings.SplitN(p, "=", 2)
			if len(kv) != 2 {
				return "", errors.New("Account cookies must contain named cookie values")
			}
			parts = append(parts, [2]string{strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])})
		}
	}
	if len(parts) > 200 {
		return "", errors.New("Account cookies have too many entries")
	}
	seen := map[string]bool{}
	result := []string{}
	for _, p := range parts {
		if validText(p[0], 256, false) != nil || validText(p[1], 16384, true) != nil || !cookieName.MatchString(p[0]) || seen[p[0]] {
			return "", errors.New("Cookie names must be unique valid HTTP tokens")
		}
		for _, c := range p[1] {
			if !(c == 33 || c >= 35 && c <= 43 || c >= 45 && c <= 58 || c >= 60 && c <= 91 || c >= 93 && c <= 126) {
				return "", errors.New("Cookie value contains unsupported characters")
			}
		}
		seen[p[0]] = true
		result = append(result, p[0]+"="+p[1])
	}
	header := strings.Join(result, "; ")
	if len(header) > 65536 {
		return "", errors.New("Account cookies exceed the maximum supported size")
	}
	return header, nil
}
func apiUser(v any) (string, error) {
	if raw, ok := v.(json.Number); ok {
		v = raw.String()
	} else if n, ok := Number(v); ok {
		if n != math.Trunc(n) || n < 1 || n > 9007199254740991 {
			return "", errors.New("API user ID must be a positive integer")
		}
		v = strconv.FormatFloat(n, 'f', 0, 64)
	}
	if e := validText(v, 128, true); e != nil {
		return "", e
	}
	s := strings.TrimSpace(String(v))
	if s == "" {
		return s, nil
	}
	if !digits.MatchString(s) {
		return "", errors.New("API user ID must be a positive integer")
	}
	s = strings.TrimLeft(s, "0")
	if s == "" {
		return "", errors.New("API user ID must be a positive integer")
	}
	return s, nil
}
func validateAccounts(value any, proxy string) ([]any, error) {
	a := Array(value)
	if a == nil || len(a) > 100 {
		return nil, errors.New("Accounts must be an array with at most 100 entries")
	}
	out := []any{}
	seen := map[string]bool{}
	for _, v := range a {
		d := Object(v)
		if e := allowed(d, "id name provider auth_type enabled cookies username password system_access_token api_user expected_username proxy low_balance_threshold"); e != nil {
			return nil, e
		}
		if e := validText(d["id"], 128, false); e != nil {
			return nil, e
		}
		id := String(d["id"])
		if strings.TrimSpace(id) != id || seen[id] {
			return nil, errors.New("Account IDs must be unique and have no surrounding whitespace")
		}
		seen[id] = true
		if _, ok := d["name"]; !ok {
			d["name"] = id
		}
		if e := validText(d["name"], 256, false); e != nil {
			return nil, e
		}
		provider := String(d["provider"])
		auth := String(d["auth_type"])
		if provider != "anyrouter" && provider != "agentrouter" {
			return nil, errors.New("Only AnyRouter and AgentRouter are supported")
		}
		if auth != "password" && (auth != "cookie" || provider != "anyrouter") {
			return nil, errors.New("Account authentication is not supported by this provider")
		}
		if _, ok := d["enabled"]; !ok {
			d["enabled"] = true
		}
		if e := boolean(d["enabled"]); e != nil {
			return nil, e
		}
		if d["low_balance_threshold"] != nil {
			if e := threshold(d["low_balance_threshold"]); e != nil {
				return nil, e
			}
		}
		for _, k := range []string{"username", "password", "system_access_token", "expected_username"} {
			if v, ok := d[k]; ok {
				if e := validText(v, 8192, true); e != nil {
					return nil, e
				}
			}
		}
		if v, ok := d["api_user"]; ok {
			u, e := apiUser(v)
			if e != nil {
				return nil, e
			}
			d["api_user"] = u
		}
		if v, ok := d["cookies"]; ok {
			c, e := normalizeCookies(v)
			if e != nil {
				return nil, e
			}
			d["cookies"] = c
		}
		if auth == "password" {
			if String(d["cookies"]) != "" || String(d["system_access_token"]) != "" {
				return nil, errors.New("Account cannot combine different authentication credentials")
			}
		} else {
			if String(d["username"]) != "" || String(d["password"]) != "" || String(d["system_access_token"]) != "" {
				return nil, errors.New("Account cannot combine different authentication credentials")
			}
		}
		if v, ok := d["proxy"]; ok {
			p, e := ValidProxy(v, true)
			if e != nil {
				return nil, e
			}
			d["proxy"] = p
		}
		if Bool(d["enabled"]) {
			if d["proxy"] == "default" && proxy == "" {
				return nil, errors.New("A default proxy is required by an account but no proxy URL is configured")
			}
			if auth == "password" {
				if String(d["username"]) == "" || String(d["password"]) == "" {
					return nil, errors.New("Password authentication requires username and password")
				}
			} else if String(d["api_user"]) == "" || String(d["cookies"]) == "" {
				return nil, errors.New("Cookie authentication requires credentials and API user ID")
			}
		}
		out = append(out, d)
	}
	return out, nil
}
func Validate(config Document) (Document, error) {
	if e := allowed(config, "schema_version accounts proxy_url notifications schedule monitoring automation backups http webui_url"); e != nil {
		return nil, e
	}
	encoded, encodeErr := json.Marshal(config)
	if encodeErr != nil {
		return nil, errors.New("Configuration has an invalid JSON value")
	}
	var input Document
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&input) != nil {
		return nil, errors.New("Configuration has an invalid JSON value")
	}
	d := DefaultConfig()
	for k, v := range input {
		d[k] = v
	}
	if e := integer(d["schema_version"], 2, 2); e != nil {
		return nil, e
	}
	if d["proxy_url"] != "" {
		p, e := ValidProxy(d["proxy_url"], false)
		if e != nil {
			return nil, e
		}
		d["proxy_url"] = p
	}
	a, e := validateAccounts(d["accounts"], String(d["proxy_url"]))
	if e != nil {
		return nil, e
	}
	d["accounts"] = a
	origin, e := NormalizeOrigin(d["webui_url"])
	if e != nil {
		return nil, e
	}
	d["webui_url"] = origin
	notifications := Object(d["notifications"])
	if e = allowed(notifications, strings.Join(notificationNames, " ")); e != nil {
		return nil, e
	}
	for k, v := range notifications {
		if e = validText(v, 8192, true); e != nil {
			return nil, e
		}
		if k == "GOTIFY_PRIORITY" && v != "" {
			i, e := strconv.Atoi(String(v))
			if e != nil || i < 1 || i > 10 {
				return nil, errors.New("Gotify priority must be between 1 and 10")
			}
		}
	}
	if server := String(notifications["FY1PUSH_SERVER"]); server != "" {
		u, e := url.Parse(strings.TrimSpace(server))
		if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (strings.TrimRight(u.Path, "/") != "" && strings.TrimRight(u.Path, "/") != "/v1/push") || !(u.Scheme == "https" || u.Scheme == "http") || u.Hostname() == "" || u.Scheme == "http" && (u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1") || strings.ContainsAny(server, "\\ \t\n\r") {
			return nil, errors.New("Fy1Push server must be an HTTPS root or /v1/push URL")
		}
	}
	if channel := String(notifications["FY1PUSH_CHANNEL"]); channel != "" {
		if utf8.RuneCountInString(channel) > 24 {
			return nil, errors.New("Fy1Push channel exceeds 24 characters")
		}
		for _, c := range channel {
			if !unicode.IsLetter(c) && !unicode.IsNumber(c) && !strings.ContainsRune("-_ .", c) || c == ' ' {
				return nil, errors.New("Fy1Push channel contains unsupported characters")
			}
		}
	}
	for _, c := range String(notifications["FY1PUSH_TOKEN"]) {
		if c < 33 || c > 126 {
			return nil, errors.New("Fy1Push token contains unsupported characters")
		}
	}
	defaults := DefaultConfig()
	schedule, e := mergeSettings(Object(defaults["schedule"]), d["schedule"])
	if e != nil {
		return nil, e
	}
	if e = boolean(schedule["enabled"]); e != nil {
		return nil, e
	}
	if e = integer(schedule["interval_minutes"], 30, 10080); e != nil {
		return nil, e
	}
	if schedule["mode"] != "interval" && schedule["mode"] != "cron" {
		return nil, errors.New("Schedule mode must be interval or cron")
	}
	if e = ValidateCron(String(schedule["cron"])); e != nil {
		return nil, e
	}
	if Bool(schedule["enabled"]) {
		enabled := false
		for _, v := range a {
			enabled = enabled || Bool(Object(v)["enabled"])
		}
		if !enabled {
			return nil, errors.New("An enabled schedule requires at least one enabled account")
		}
	}
	d["schedule"] = schedule
	monitoring, e := mergeSettings(Object(defaults["monitoring"]), d["monitoring"])
	if e != nil {
		return nil, e
	}
	if e = boolean(monitoring["enabled"]); e != nil {
		return nil, e
	}
	if e = integer(monitoring["interval_minutes"], 30, 10080); e != nil {
		return nil, e
	}
	d["monitoring"] = monitoring
	automation := Object(d["automation"])
	if e = allowed(automation, "low_balance recovery daily_summary"); e != nil {
		return nil, e
	}
	for name, v := range Object(defaults["automation"]) {
		part := automation[name]
		if part == nil {
			part = Document{}
		}
		settings, e := mergeSettings(Object(v), part)
		if e != nil {
			return nil, e
		}
		if e = boolean(settings["enabled"]); e != nil {
			return nil, e
		}
		if v, ok := settings["cooldown_minutes"]; ok {
			if e = integer(v, 1, 10080); e != nil {
				return nil, e
			}
		}
		if name == "low_balance" {
			if e = threshold(settings["threshold"]); e != nil {
				return nil, e
			}
		}
		if name == "daily_summary" && !clockPattern.MatchString(String(settings["time"])) {
			return nil, errors.New("Daily summary time must use HH:MM in UTC+8")
		}
		automation[name] = settings
	}
	d["automation"] = automation
	backups, e := mergeSettings(Object(defaults["backups"]), d["backups"])
	if e != nil {
		return nil, e
	}
	if e = boolean(backups["enabled"]); e != nil {
		return nil, e
	}
	if e = integer(backups["retain_count"], 1, 90); e != nil {
		return nil, e
	}
	if e = validText(backups["password"], 512, true); e != nil {
		return nil, e
	}
	if p := String(backups["password"]); p != "" && utf8.RuneCountInString(p) < 16 || p == "" && Bool(backups["enabled"]) {
		return nil, errors.New("Backup recovery password requires 16 to 512 characters")
	}
	if !clockPattern.MatchString(String(backups["time"])) {
		return nil, errors.New("Backup time must use HH:MM in UTC+8")
	}
	d["backups"] = backups
	h, e := mergeSettings(Object(defaults["http"]), d["http"])
	if e != nil {
		return nil, e
	}
	if e = integer(h["timeout_seconds"], 5, 120); e != nil {
		return nil, e
	}
	d["http"] = h
	finalJSON, _ := json.Marshal(d)
	if len(finalJSON) > 1024*1024 {
		return nil, errors.New("Configuration exceeds the maximum supported size")
	}
	return d, nil
}
func Redact(config Document) Document {
	d := Clone(config)
	if String(d["proxy_url"]) != "" {
		d["proxy_url"] = SecretKeep
	}
	for _, v := range Array(d["accounts"]) {
		a := Object(v)
		for _, k := range accountSecrets {
			if String(a[k]) != "" {
				a[k] = SecretKeep
			}
		}
		if p := String(a["proxy"]); p != "" && p != "direct" && p != "default" {
			a["proxy"] = SecretKeep
		}
	}
	for _, k := range secretNotificationNames {
		if String(Object(d["notifications"])[k]) != "" {
			Object(d["notifications"])[k] = SecretKeep
		}
	}
	if b := Object(d["backups"]); String(b["password"]) != "" {
		b["password"] = SecretKeep
	}
	return d
}
func restoreSecret(target, old Document, k string) error {
	if target[k] == SecretKeep {
		if String(old[k]) == "" {
			return errors.New("A secret marker has no stored value; enter a value or clear the field")
		}
		target[k] = old[k]
	}
	return nil
}
func RestoreSecrets(config, old Document) (Document, error) {
	d := Clone(config)
	if d == nil {
		return nil, errors.New("Configuration must be an object")
	}
	if e := restoreSecret(d, old, "proxy_url"); e != nil {
		return nil, e
	}
	previous := map[string]Document{}
	for _, v := range Array(old["accounts"]) {
		a := Object(v)
		previous[String(a["id"])] = a
	}
	for _, v := range Array(d["accounts"]) {
		a := Object(v)
		if a == nil {
			continue
		}
		p := previous[String(a["id"])]
		if e := restoreSecret(a, p, "proxy"); e != nil {
			return nil, e
		}
		if String(p["provider"]) != String(a["provider"]) || String(p["auth_type"]) != String(a["auth_type"]) {
			p = nil
		}
		for _, k := range accountSecrets {
			if e := restoreSecret(a, p, k); e != nil {
				return nil, e
			}
		}
	}
	for _, k := range secretNotificationNames {
		if e := restoreSecret(Object(d["notifications"]), Object(old["notifications"]), k); e != nil {
			return nil, e
		}
	}
	if e := restoreSecret(Object(d["backups"]), Object(old["backups"]), "password"); e != nil {
		return nil, e
	}
	return d, nil
}

// ValidateCron enforces numeric five-field cron and a minimum 30-minute gap.
func ValidateCron(expr string) error {
	p := strings.Fields(expr)
	if len(p) != 5 {
		return errors.New("Cron must contain five numeric fields")
	}
	bounds := [][2]int{{0, 59}, {0, 23}, {1, 31}, {1, 12}, {0, 7}}
	sets := make([]map[int]bool, 5)
	for i, field := range p {
		set := map[int]bool{}
		for _, item := range strings.Split(field, ",") {
			split := strings.Split(item, "/")
			if len(split) > 2 || split[0] == "" {
				return errors.New("Cron field is invalid")
			}
			step := 1
			if len(split) == 2 {
				n, e := strconv.Atoi(split[1])
				if e != nil || n < 1 || n > bounds[i][1]-bounds[i][0]+1 {
					return errors.New("Cron step is invalid")
				}
				step = n
			}
			lo, hi := bounds[i][0], bounds[i][1]
			base := split[0]
			if base != "*" {
				r := strings.Split(base, "-")
				n, e := strconv.Atoi(r[0])
				if e != nil {
					return errors.New("Cron accepts numeric fields only")
				}
				lo, hi = n, n
				if len(r) == 2 {
					hi, e = strconv.Atoi(r[1])
					if e != nil {
						return errors.New("Cron range is invalid")
					}
				} else if len(r) > 2 {
					return errors.New("Cron range is invalid")
				} else if len(split) == 2 {
					hi = bounds[i][1]
				}
			}
			if lo < bounds[i][0] || hi > bounds[i][1] || lo > hi {
				return errors.New("Cron range is invalid")
			}
			for n := lo; n <= hi; n += step {
				set[n] = true
			}
		}
		if len(set) == 0 {
			return errors.New("Cron field is empty")
		}
		sets[i] = set
	}
	prev := -1
	first := -1
	for h := 0; h < 24; h++ {
		if !sets[1][h] {
			continue
		}
		for m := 0; m < 60; m++ {
			if !sets[0][m] {
				continue
			}
			at := h*60 + m
			if prev >= 0 && at-prev < 30 {
				return errors.New("Cron must have at least 30 minutes between runs")
			}
			if first < 0 {
				first = at
			}
			prev = at
		}
	}
	if prev >= 0 && 1440-prev+first < 30 {
		return errors.New("Cron must have at least 30 minutes between runs")
	}
	return nil
}
func DisableAutomatic(config Document) {
	for _, k := range []string{"schedule", "monitoring", "backups"} {
		if d := Object(config[k]); d != nil {
			d["enabled"] = false
		}
	}
	for _, v := range Object(config["automation"]) {
		if d := Object(v); d != nil {
			d["enabled"] = false
		}
	}
}

func migrate(d Document, revision int) (Document, Document, error) {
	if _, ok := d["schema_version"]; ok {
		if Int(d["schema_version"]) != 2 {
			return nil, nil, ErrInvalid
		}
		converted := 0
		for _, v := range Array(d["accounts"]) {
			a := Object(v)
			if a["provider"] == "agentrouter" && a["auth_type"] == "system_token" {
				a["auth_type"] = "password"
				a["enabled"] = false
				for _, k := range []string{"cookies", "system_access_token", "username", "password"} {
					delete(a, k)
				}
				converted++
			}
		}
		if converted == 0 {
			return d, nil, nil
		}
		enabled := false
		for _, v := range Array(d["accounts"]) {
			enabled = enabled || Bool(Object(v)["enabled"])
		}
		disabled := Bool(Object(d["schedule"])["enabled"]) && !enabled
		if disabled {
			Object(d["schedule"])["enabled"] = false
		}
		return d, Document{"from_schema": 2, "source_revision": revision, "converted_accounts": converted, "disabled_accounts": converted, "omitted_accounts": 0, "schedule_disabled": disabled}, nil
	}
	out := DefaultConfig()
	if v, ok := d["proxy_url"]; ok {
		out["proxy_url"] = v
	}
	if v, ok := d["notifications"]; ok {
		out["notifications"] = v
	}
	if v, ok := d["schedule"]; ok && Object(v) == nil {
		return nil, nil, ErrInvalid
	}
	if v, ok := d["providers"]; ok && Object(v) == nil {
		return nil, nil, ErrInvalid
	}
	if v, ok := Object(d["schedule"])["interval_minutes"]; ok {
		Object(out["schedule"])["interval_minutes"] = v
	}
	accounts := Array(d["accounts"])
	_, hasAccounts := d["accounts"]
	if accounts == nil && hasAccounts || len(accounts) > 100 {
		return nil, nil, ErrInvalid
	}
	seen := map[string]bool{}
	omitted, disabled := 0, 0
	for _, v := range accounts {
		a := Object(v)
		if a == nil {
			return nil, nil, ErrInvalid
		}
		provider := String(a["provider"])
		if _, exists := a["provider"]; !exists {
			provider = "anyrouter"
		}
		origin := "https://anyrouter.top"
		if provider == "agentrouter" {
			origin = "https://agentrouter.org"
		}
		override := Object(Object(d["providers"])[provider])
		overrideValue, hasOverride := Object(d["providers"])[provider]
		if provider != "anyrouter" && provider != "agentrouter" || hasOverride && Object(overrideValue) == nil || override["domain"] != nil && strings.TrimRight(String(override["domain"]), "/") != origin {
			omitted++
			continue
		}
		id := String(a["id"])
		if validText(id, 128, false) != nil || strings.TrimSpace(id) != id || seen[id] {
			omitted++
			continue
		}
		seen[id] = true
		name := String(a["name"])
		if name == "" {
			name = id
		}
		if validText(name, 256, false) != nil {
			omitted++
			continue
		}
		enabled := true
		if v, ok := a["enabled"]; ok {
			enabled = Bool(v)
		}
		n := Document{"id": id, "name": name, "provider": provider, "enabled": enabled, "auth_type": "cookie"}
		for _, k := range []string{"api_user", "expected_username", "proxy"} {
			if a[k] != nil {
				n[k] = a[k]
			}
		}
		if provider == "agentrouter" {
			n["auth_type"] = "password"
			n["enabled"] = false
		} else if a["auth"] != nil {
			n["enabled"] = false
			n["cookies"] = ""
		} else if String(a["email"]) != "" || String(a["username"]) != "" || String(a["password"]) != "" {
			n["auth_type"] = "password"
			n["username"] = a["username"]
			if String(n["username"]) == "" {
				n["username"] = String(a["email"])
			}
			n["password"] = String(a["password"])
		} else {
			n["cookies"] = a["cookies"]
			if n["cookies"] == nil {
				n["cookies"] = ""
			}
		}
		validated, e := validateAccounts([]any{n}, String(out["proxy_url"]))
		if e != nil {
			n["enabled"] = false
			for _, k := range []string{"api_user", "expected_username", "proxy", "username", "password", "cookies"} {
				if n[k] == nil {
					continue
				}
				var err error
				switch k {
				case "api_user":
					n[k], err = apiUser(n[k])
				case "proxy":
					n[k], err = ValidProxy(n[k], true)
				case "cookies":
					n[k], err = normalizeCookies(n[k])
				default:
					err = validText(n[k], 8192, true)
				}
				if err != nil {
					delete(n, k)
				}
			}
			validated, e = validateAccounts([]any{n}, String(out["proxy_url"]))
			if e != nil {
				return nil, nil, e
			}
		}
		n = Object(validated[0])
		if !Bool(n["enabled"]) {
			disabled++
		}
		out["accounts"] = append(Array(out["accounts"]), n)
	}
	return out, Document{"from_schema": 1, "source_revision": revision, "converted_accounts": len(Array(out["accounts"])), "disabled_accounts": disabled, "omitted_accounts": omitted, "schedule_disabled": true}, nil
}
