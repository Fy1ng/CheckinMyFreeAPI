package checkin

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func notificationConfig() Document {
	return Document{"EMAIL_USER": "", "PUSHPLUS_TOKEN": "synthetic-pushplus", "SERVERPUSHKEY": "synthetic-serverkey", "DINGDING_WEBHOOK": "https://oapi.dingtalk.com/robot/send?access_token=synthetic", "FEISHU_WEBHOOK": "https://open.feishu.cn/open-apis/bot/v2/hook/synthetic", "WEIXIN_WEBHOOK": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=synthetic", "GOTIFY_URL": "https://gotify.example.com/message", "GOTIFY_TOKEN": "synthetic-gotify", "GOTIFY_PRIORITY": "8", "TELEGRAM_BOT_TOKEN": "synthetic-telegram", "TELEGRAM_CHAT_ID": "42", "BARK_KEY": "synthetic-bark", "FY1PUSH_SERVER": "https://push.example.com", "FY1PUSH_TOKEN": "synthetic-fy1push", "FY1PUSH_CHANNEL": "签到"}
}
func TestNotificationsEveryChannelAcceptedOnce(t *testing.T) {
	requests := []*http.Request{}
	n := &notifier{transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		requests = append(requests, req)
		data, _ := io.ReadAll(req.Body)
		var payload Document
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		switch req.URL.Host {
		case "push.example.com":
			if req.URL.Path != "/v1/push" || req.Header.Get("Authorization") != "Bearer synthetic-fy1push" || len(req.Header.Get("Idempotency-Key")) != 36 || payload["channel"] != "签到" {
				t.Fatal("Fy1Push contract")
			}
			if len([]rune(text(payload["body"]))) > 100 {
				t.Fatal("Fy1Push body limit")
			}
			return response(200, `{"ok":true,"accepted":true}`), nil
		case "api.telegram.org":
			if payload["parse_mode"] != "HTML" || payload["chat_id"] != "42" {
				t.Fatal("Telegram contract")
			}
		case "gotify.example.com":
			if req.URL.Query().Get("token") != "synthetic-gotify" || payload["priority"] != float64(8) {
				t.Fatal("Gotify contract")
			}
		case "api.day.app":
			if payload["device_key"] != "synthetic-bark" {
				t.Fatal("Bark contract")
			}
		}
		return response(200, `{"code":200}`), nil
	})}
	result := n.deliver(context.Background(), notificationConfig(), "签到结果", strings.Repeat("结果", 80))
	if result["state"] != "accepted" || result["device_delivery"] != "unconfirmed" || len(requests) != 9 {
		t.Fatalf("%#v requests %d", result, len(requests))
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "synthetic") {
		t.Fatal("notification secret leaked")
	}
}

func TestNotificationAcceptanceEvidenceAndNoRetries(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		body, state string
	}{{"accepted", 200, `{"ok":true,"accepted":true}`, "accepted"}, {"false", 200, `{"ok":true,"accepted":false}`, "unknown"}, {"missing", 200, `{"ok":true}`, "unknown"}, {"nonbool", 200, `{"ok":1,"accepted":1}`, "unknown"}, {"invalid", 200, `oops`, "unknown"}, {"rejected", 401, `{}`, "failed"}, {"rate", 429, `{}`, "failed"}, {"redirect", 302, `{}`, "failed"}, {"alternate2xx", 202, `{"ok":true,"accepted":true}`, "failed"}, {"network", 0, ``, "unknown"}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			n := &notifier{transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				if tc.status == 0 {
					return nil, context.DeadlineExceeded
				}
				return response(tc.status, tc.body), nil
			})}
			result := n.deliver(context.Background(), Document{"FY1PUSH_SERVER": "https://push.example.com", "FY1PUSH_TOKEN": "secret-token"}, "title", "content")
			if result["state"] != tc.state || calls != 1 {
				t.Fatalf("%#v calls %d", result, calls)
			}
		})
	}
}

func TestNotificationsProviderRejectionsAndPartial(t *testing.T) {
	for _, payload := range []string{`{"ok":false}`, `{"errcode":1}`, `{"StatusCode":2}`, `{"code":401}`, `{"ret":3}`, `{"code":"0"}`} {
		n := &notifier{transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, payload), nil })}
		result := n.deliver(context.Background(), Document{"PUSHPLUS_TOKEN": "synthetic"}, "title", "content")
		if result["state"] != "failed" {
			t.Fatal("provider rejection accepted")
		}
	}
	n := &notifier{transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "www.pushplus.plus" {
			return response(200, `{"code":200}`), nil
		}
		return response(400, `{}`), nil
	})}
	result := n.deliver(context.Background(), Document{"PUSHPLUS_TOKEN": "synthetic", "BARK_KEY": "synthetic"}, "title", "content")
	if result["state"] != "partial" {
		t.Fatal("mixed state lost")
	}
	if Deliver(context.Background(), Document{}, "title", "content")["state"] != "not_configured" {
		t.Fatal("no channels")
	}
}

func TestFy1PushValidationAndUnicodeBudgets(t *testing.T) {
	for input, want := range map[string]string{"https://push.example.com": "https://push.example.com/v1/push", "https://push.example.com/v1/push/": "https://push.example.com/v1/push", "http://127.0.0.1:123": "http://127.0.0.1:123/v1/push", "http://[::1]:123/": "http://[::1]:123/v1/push"} {
		got, err := Fy1PushEndpoint(input)
		if err != nil || got != want {
			t.Fatal("endpoint normalization", got, err)
		}
	}
	for _, input := range []string{"http://public.example", "https://user:pass@push.example", "https://push.example/api", "https://push.example?token=secret", "https://push.example#frag", "https://push.example:0", "https://push.example:", "https://push.example\\x", "https://push.example/ x", "https://push.example:99999"} {
		if _, err := Fy1PushEndpoint(input); err == nil {
			t.Fatal("invalid endpoint accepted")
		}
	}
	for _, input := range []string{"test token", "秘密", "token\r\n"} {
		if ValidateFy1PushToken(input) == nil {
			t.Fatal("invalid token accepted")
		}
	}
	channel, err := Fy1PushChannel("")
	if err != nil || channel != "签到" {
		t.Fatal("default channel")
	}
	for _, input := range []string{"has space", "/slash", strings.Repeat("a", 25)} {
		if _, err := Fy1PushChannel(input); err == nil {
			t.Fatal("invalid channel accepted")
		}
	}
	value, err := Fy1PushSummary(strings.Repeat("中文😀", 20), 40)
	if err != nil || len([]rune(value)) != 40 || !strings.HasSuffix(value, "...") {
		t.Fatal("rune truncation")
	}
	for _, input := range []string{" ", "bad\x00value"} {
		if _, err := Fy1PushSummary(input, 40); err == nil {
			t.Fatal("bad text accepted")
		}
	}
}

func TestFy1PushTitleBudgetAccountsForChannel(t *testing.T) {
	channel := strings.Repeat("组", 24)
	var title string
	n := &notifier{transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		data, _ := io.ReadAll(req.Body)
		var p Document
		_ = json.Unmarshal(data, &p)
		title = text(p["title"])
		return response(200, `{"ok":true,"accepted":true}`), nil
	})}
	result := n.deliver(context.Background(), Document{"FY1PUSH_SERVER": "https://push.example.com", "FY1PUSH_TOKEN": "synthetic", "FY1PUSH_CHANNEL": channel}, strings.Repeat("标题", 40), "body")
	if result["state"] != "accepted" || len([]rune(title)) != 11 {
		t.Fatal("channel title bound")
	}
}

func TestNotifyProviderPayloads(t *testing.T) {
	payloads := map[string]Document{}
	n := &notifier{transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		var p Document
		_ = json.Unmarshal(b, &p)
		payloads[req.URL.Host] = p
		return response(200, `{"code":200}`), nil
	})}
	cfg := Document{"DINGDING_WEBHOOK": "https://ding.example/send", "WEIXIN_WEBHOOK": "https://wecom.example/send", "FEISHU_WEBHOOK": "https://feishu.example/send"}
	n.deliver(context.Background(), cfg, "title", "body")
	if !reflect.DeepEqual(payloads["ding.example"], Document{"msgtype": "text", "text": Document{"content": "title\nbody"}}) || payloads["wecom.example"]["msgtype"] != "text" || payloads["feishu.example"]["msg_type"] != "interactive" {
		t.Fatal("provider payload mismatch")
	}
}
