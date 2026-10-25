package checkin

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var errRejected = errors.New("notification rejected")
var errUnconfirmed = errors.New("provider acceptance unconfirmed")

// Deliver attempts each configured channel once. Acceptance is evidence from
// the provider only; it does not claim delivery to a user's device.
func Deliver(ctx context.Context, notifications map[string]any, title, content string) map[string]any {
	return (&notifier{}).deliver(ctx, notifications, title, content)
}

type notifier struct{ transport http.RoundTripper }

func (n *notifier) post(ctx context.Context, endpoint string, payload Document, headers map[string]string, fy bool) error {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return errUnconfirmed
	}
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(encoded))
	if err != nil {
		return errUnconfirmed
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.Protocols = new(http.Protocols)
	transport.Protocols.SetHTTP1(true)
	var rt http.RoundTripper = transport
	if n.transport != nil {
		rt = n.transport
	}
	client := &http.Client{Transport: rt, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return errUnconfirmed
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || fy && response.StatusCode != 200 {
		return errRejected
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		return errUnconfirmed
	}
	var result Document
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	err = decoder.Decode(&result)
	var extra any
	if trailing := decoder.Decode(&extra); trailing != io.EOF {
		err = errUnconfirmed
	}
	if fy {
		if err != nil || result == nil || result["ok"] != true || result["accepted"] != true {
			return errUnconfirmed
		}
		return nil
	}
	if err != nil || result == nil {
		return nil
	}
	if value, ok := result["ok"].(bool); ok && !value {
		return errRejected
	}
	for key, allowed := range map[string][]float64{"errcode": {0}, "StatusCode": {0}, "code": {0, 200}, "ret": {0, 1, 200}} {
		if value, present := result[key]; present && value != nil {
			v, ok := number(value)
			found := false
			if ok {
				for _, a := range allowed {
					if a == v {
						found = true
					}
				}
			}
			if !found {
				return errRejected
			}
		}
	}
	return nil
}

func (n *notifier) deliver(ctx context.Context, cfg Document, title, content string) Document {
	type channel struct {
		name       string
		configured bool
		send       func() error
	}
	get := func(key string) string { return text(cfg[key]) }
	post := func(endpoint string, payload Document) error { return n.post(ctx, endpoint, payload, nil, false) }
	channels := []channel{
		{"Email", get("EMAIL_USER") != "" && get("EMAIL_PASS") != "" && get("EMAIL_TO") != "", func() error { return sendEmail(ctx, cfg, title, content) }},
		{"PushPlus", get("PUSHPLUS_TOKEN") != "", func() error {
			return post("http://www.pushplus.plus/send", Document{"token": get("PUSHPLUS_TOKEN"), "title": title, "content": content, "template": "html"})
		}},
		{"Server Push", get("SERVERPUSHKEY") != "", func() error {
			return post("https://sctapi.ftqq.com/"+url.PathEscape(get("SERVERPUSHKEY"))+".send", Document{"title": title, "desp": content})
		}},
		{"DingTalk", get("DINGDING_WEBHOOK") != "", func() error {
			return post(get("DINGDING_WEBHOOK"), Document{"msgtype": "text", "text": Document{"content": title + "\n" + content}})
		}},
		{"Feishu", get("FEISHU_WEBHOOK") != "", func() error {
			return post(get("FEISHU_WEBHOOK"), Document{"msg_type": "interactive", "card": Document{"elements": []any{Document{"tag": "markdown", "content": content, "text_align": "left"}}, "header": Document{"template": "blue", "title": Document{"content": title, "tag": "plain_text"}}}})
		}},
		{"WeChat Work", get("WEIXIN_WEBHOOK") != "", func() error {
			return post(get("WEIXIN_WEBHOOK"), Document{"msgtype": "text", "text": Document{"content": title + "\n" + content}})
		}},
		{"Gotify", get("GOTIFY_URL") != "" && get("GOTIFY_TOKEN") != "", func() error {
			u, err := url.Parse(get("GOTIFY_URL"))
			if err != nil {
				return errUnconfirmed
			}
			query := u.Query()
			query.Set("token", get("GOTIFY_TOKEN"))
			u.RawQuery = query.Encode()
			priority := 9
			if v, err := strconv.Atoi(get("GOTIFY_PRIORITY")); err == nil {
				priority = v
			} else if v, ok := number(cfg["GOTIFY_PRIORITY"]); ok {
				priority = int(v)
			}
			if priority < 1 {
				priority = 1
			}
			if priority > 10 {
				priority = 10
			}
			return post(u.String(), Document{"title": title, "message": content, "priority": priority})
		}},
		{"Telegram", get("TELEGRAM_BOT_TOKEN") != "" && get("TELEGRAM_CHAT_ID") != "", func() error {
			return post("https://api.telegram.org/bot"+get("TELEGRAM_BOT_TOKEN")+"/sendMessage", Document{"chat_id": get("TELEGRAM_CHAT_ID"), "text": "<b>" + title + "</b>\n\n" + content, "parse_mode": "HTML"})
		}},
		{"Bark", get("BARK_KEY") != "", func() error {
			server := get("BARK_SERVER")
			if server == "" {
				server = "https://api.day.app"
			}
			return post(strings.TrimRight(server, "/")+"/push", Document{"device_key": get("BARK_KEY"), "title": title, "body": content, "icon": "https://anyrouter.top/favicon.ico", "group": "AnyRouter"})
		}},
		{"Fy1Push", get("FY1PUSH_SERVER") != "" && get("FY1PUSH_TOKEN") != "", func() error {
			endpoint, err := Fy1PushEndpoint(get("FY1PUSH_SERVER"))
			if err != nil {
				return errUnconfirmed
			}
			group, err := Fy1PushChannel(get("FY1PUSH_CHANNEL"))
			if err != nil {
				return errUnconfirmed
			}
			if err = ValidateFy1PushToken(get("FY1PUSH_TOKEN")); err != nil {
				return errUnconfirmed
			}
			limit := 40
			if group != "default" {
				limit = 40 - 5 - utf8.RuneCountInString(group)
			}
			summary, err := Fy1PushSummary(title, limit)
			if err != nil {
				return errUnconfirmed
			}
			body, err := Fy1PushSummary(content, 100)
			if err != nil {
				return errUnconfirmed
			}
			random := make([]byte, 16)
			if _, err = rand.Read(random); err != nil {
				return errUnconfirmed
			}
			random[6] = (random[6] & 15) | 64
			random[8] = (random[8] & 63) | 128
			id := fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(random[:4]), hex.EncodeToString(random[4:6]), hex.EncodeToString(random[6:8]), hex.EncodeToString(random[8:10]), hex.EncodeToString(random[10:]))
			return n.post(ctx, endpoint, Document{"title": summary, "body": body, "channel": group}, map[string]string{"Authorization": "Bearer " + get("FY1PUSH_TOKEN"), "Idempotency-Key": id}, true)
		}},
	}
	results := []Document{}
	states := map[string]bool{}
	for _, channel := range channels {
		if !channel.configured {
			continue
		}
		state := "accepted"
		var code any
		err := channel.send()
		if err != nil {
			state, code = "unknown", "notification_outcome_unknown"
			if errors.Is(err, errRejected) {
				state, code = "failed", "notification_rejected"
			} else if errors.Is(err, errUnconfirmed) {
				code = "provider_acceptance_unconfirmed"
			}
		}
		results = append(results, Document{"channel": channel.name, "state": state, "error_code": code})
		states[state] = true
	}
	state := "unknown"
	if len(results) == 0 {
		state = "not_configured"
	} else if len(states) == 1 && states["accepted"] {
		state = "accepted"
	} else if states["accepted"] {
		state = "partial"
	} else if len(states) == 1 && states["failed"] {
		state = "failed"
	}
	return Document{"state": state, "channels": results, "device_delivery": "unconfirmed"}
}

func Fy1PushEndpoint(server string) (string, error) {
	bad := errors.New("invalid Fy1Push endpoint")
	server = strings.TrimSpace(server)
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") || (strings.TrimRight(u.Path, "/") != "" && strings.TrimRight(u.Path, "/") != "/v1/push") || strings.Contains(server, `\`) || strings.HasSuffix(u.Host, ":") {
		return "", bad
	}
	for _, r := range server {
		if unicode.IsSpace(r) || r < 32 || r == 127 {
			return "", bad
		}
	}
	if u.Scheme == "http" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" && u.Hostname() != "::1" {
		return "", bad
	}
	if port := u.Port(); port != "" {
		p, e := strconv.Atoi(port)
		if e != nil || p < 1 || p > 65535 {
			return "", bad
		}
	}
	u.Path = "/v1/push"
	u.RawPath = ""
	return u.String(), nil
}
func Fy1PushChannel(channel string) (string, error) {
	if channel == "" {
		channel = "签到"
	}
	if count := utf8.RuneCountInString(channel); count < 1 || count > 24 {
		return "", errors.New("invalid Fy1Push channel")
	}
	for _, r := range channel {
		if !unicode.IsLetter(r) && !unicode.IsNumber(r) && r != '-' && r != '_' && r != '.' {
			return "", errors.New("invalid Fy1Push channel")
		}
	}
	return channel, nil
}
func ValidateFy1PushToken(token string) error {
	for _, r := range token {
		if r < 33 || r > 126 {
			return errors.New("invalid Fy1Push token")
		}
	}
	return nil
}
func Fy1PushSummary(value string, limit int) (string, error) {
	if strings.TrimSpace(value) == "" || !utf8.ValidString(value) || limit < 3 {
		return "", errors.New("invalid Fy1Push text")
	}
	for _, r := range value {
		if r < 32 && r != '\n' && r != '\r' && r != '\t' {
			return "", errors.New("invalid Fy1Push text")
		}
	}
	runes := []rune(value)
	if len(runes) > limit {
		return string(runes[:limit-3]) + "...", nil
	}
	return value, nil
}

func sendEmail(ctx context.Context, cfg Document, title, content string) error {
	user, password, recipient := text(cfg["EMAIL_USER"]), text(cfg["EMAIL_PASS"]), text(cfg["EMAIL_TO"])
	sender := text(cfg["EMAIL_SENDER"])
	if sender == "" {
		sender = user
	}
	if strings.ContainsAny(sender+recipient+title, "\r\n") {
		return errUnconfirmed
	}
	from, err := mail.ParseAddress(sender)
	if err != nil {
		return errUnconfirmed
	}
	recipients, err := mail.ParseAddressList(recipient)
	if err != nil {
		return errUnconfirmed
	}
	host := text(cfg["CUSTOM_SMTP_SERVER"])
	if host == "" {
		at := strings.LastIndex(user, "@")
		if at < 1 {
			return errUnconfirmed
		}
		host = "smtp." + user[at+1:]
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	conn, err := (&tls.Dialer{NetDialer: dialer, Config: &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}}).DialContext(ctx, "tcp", net.JoinHostPort(host, "465"))
	if err != nil {
		return errUnconfirmed
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return notificationSMTPError(err)
	}
	defer client.Close()
	if err = client.Auth(smtp.PlainAuth("", user, password, host)); err != nil {
		return notificationSMTPError(err)
	}
	if err = client.Mail(from.Address); err != nil {
		return notificationSMTPError(err)
	}
	for _, to := range recipients {
		if err = client.Rcpt(to.Address); err != nil {
			return notificationSMTPError(err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return notificationSMTPError(err)
	}
	var body bytes.Buffer
	fmt.Fprintf(&body, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n%s", (&mail.Address{Name: "AnyRouter Assistant", Address: from.Address}).String(), recipient, mime.QEncoding.Encode("UTF-8", title), content)
	if _, err = writer.Write(body.Bytes()); err != nil {
		return errUnconfirmed
	}
	if err = writer.Close(); err != nil {
		return notificationSMTPError(err)
	}
	_ = client.Quit()
	return nil
}
func notificationSMTPError(err error) error {
	var provider *textproto.Error
	if errors.As(err, &provider) {
		return errRejected
	}
	return errUnconfirmed
}
