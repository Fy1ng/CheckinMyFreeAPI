package checkin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type memorySessions struct {
	data             map[string]Document
	loads, saves     int
	loadErr, saveErr error
}

func (s *memorySessions) LoadSession(id, binding string) (Document, error) {
	s.loads++
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	return s.data[id+binding], nil
}
func (s *memorySessions) SaveSession(id, binding string, state Document) error {
	s.saves++
	if s.saveErr != nil {
		return s.saveErr
	}
	if s.data == nil {
		s.data = map[string]Document{}
	}
	s.data[id+binding] = state
	return nil
}
func testAccount() Document {
	return Document{"id": "a", "name": "Account", "provider": "anyrouter", "auth_type": "cookie", "enabled": true, "cookies": "session=synthetic-cookie", "api_user": "42", "expected_username": "alice", "proxy": "direct"}
}
func testPassword() Document {
	a := testAccount()
	a["auth_type"], a["cookies"], a["username"], a["password"] = "password", "", "alice", "synthetic-password"
	return a
}
func testAgent() Document { a := testPassword(); a["provider"] = "agentrouter"; return a }
func response(status int, body string, headers ...string) *http.Response {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	for i := 0; i+1 < len(headers); i += 2 {
		h.Add(headers[i], headers[i+1])
	}
	return &http.Response{StatusCode: status, Header: h, Body: io.NopCloser(strings.NewReader(body))}
}
func user(extra string) *http.Response {
	if extra != "" {
		extra = "," + extra
	}
	return response(200, `{"success":true,"data":{"id":42,"username":"alice","quota":500000,"used_quota":100000`+extra+`}}`)
}
func testRuntime(handler func(*http.Request) (*http.Response, error)) (*Runtime, *memorySessions, *[]*http.Request) {
	s := &memorySessions{data: map[string]Document{}}
	r := New(Document{"http": Document{"timeout_seconds": 30}}, s)
	requests := []*http.Request{}
	r.transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests = append(requests, request)
		return handler(request)
	})
	return r, s, &requests
}
func runTest(r *Runtime, a Document) Document { return r.Execute(context.Background(), a, nil) }
func assertReason(t *testing.T, result Document, outcome, reason string) {
	t.Helper()
	if result["outcome"] != outcome || result["reason"] != reason {
		t.Fatalf("got result %#v, want %s/%s", result, outcome, reason)
	}
}
func acwFixture(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "anyrouter_acw_challenge.html"))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAnyCookieIdentityAndSuccessfulSessionOnly(t *testing.T) {
	gets := 0
	r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "anyrouter.top" || req.Header.Get("new-api-user") != "42" || !strings.Contains(req.Header.Get("Cookie"), "session=synthetic-cookie") || req.Header.Get("Authorization") != "" {
			t.Fatalf("wrong account route or identity")
		}
		if req.Method == "GET" {
			gets++
			if gets == 2 {
				return response(200, `{"success":true,"data":{"id":42,"username":"alice","quota":1000000,"used_quota":100000}}`), nil
			}
			return user(""), nil
		}
		return response(200, `{"success":true}`, "Set-Cookie", "refreshed=fresh; Path=/; HttpOnly; Secure"), nil
	})
	events := []Document{}
	result := r.Execute(context.Background(), testAccount(), func(d Document) { events = append(events, d) })
	assertReason(t, result, "success", "checkin_verified")
	if result["success"] != true || len(*requests) != 3 || s.saves != 1 || result["reward"] != float64(1) {
		t.Fatalf("unexpected execution %#v", result)
	}
	stages := []string{}
	for _, step := range result["steps"].([]Document) {
		stages = append(stages, text(step["stage"]))
	}
	if !reflect.DeepEqual(stages, []string{"prepare", "load_session", "verify_identity", "checkin", "verify_result", "save_session", "finished"}) {
		t.Fatalf("stages %v", stages)
	}
	encoded, _ := json.Marshal([]any{result, events})
	if strings.Contains(string(encoded), "synthetic-cookie") || strings.Contains(string(encoded), "fresh") {
		t.Fatal("credentials leaked into result")
	}
}

func TestAnyPasswordSessionReuseAndExpiredLoginOnce(t *testing.T) {
	logins := 0
	r, s, _ := testRuntime(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/user/login" {
			logins++
			return response(200, `{"success":true,"data":{"id":42}}`, "Set-Cookie", "session=new-session; Path=/; Secure; HttpOnly"), nil
		}
		if req.Method == "GET" {
			return user(""), nil
		}
		return response(200, `{"success":true}`), nil
	})
	a := testPassword()
	if runTest(r, a)["success"] != true || runTest(r, a)["success"] != true || logins != 1 || s.saves != 2 {
		t.Fatal("session not reused")
	}
	reads := 0
	r.transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/user/login" {
			logins++
			return response(200, `{"success":true,"data":{"id":42}}`, "Set-Cookie", "session=renewed; Path=/; Secure"), nil
		}
		if req.Method == "GET" {
			reads++
			if reads == 1 {
				return response(401, `{"success":false}`), nil
			}
			return user(""), nil
		}
		return response(200, `{"success":true}`), nil
	})
	if runTest(r, a)["success"] != true || logins != 2 {
		t.Fatal("expired session did not login exactly once")
	}
}

func TestAnyIdentityMismatchNeverChecksIn(t *testing.T) {
	r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
		return response(200, `{"success":true,"data":{"id":99,"username":"alice"}}`), nil
	})
	result := runTest(r, testAccount())
	assertReason(t, result, "needs_credentials", "account_identity_mismatch")
	if len(*requests) != 1 || s.saves != 0 {
		t.Fatal("identity mismatch wrote")
	}
}

func TestIdentityRequiresStrictIntegerOrString(t *testing.T) {
	for _, id := range []string{`42.0`, `42e0`, `true`, `null`, `0`, `-1`, `"042"`} {
		t.Run(id, func(t *testing.T) {
			r, s, requests := testRuntime(func(*http.Request) (*http.Response, error) {
				return response(200, `{"success":true,"data":{"id":`+id+`,"username":"alice"}}`), nil
			})
			assertReason(t, runTest(r, testAccount()), "failed", "invalid_user_info")
			if len(*requests) != 1 || s.saves != 0 {
				t.Fatal("invalid identity wrote")
			}
		})
	}
}

func TestAnyAlreadyAndLegacySuccess(t *testing.T) {
	for _, payload := range []string{`{"success":false,"message":"已经签到"}`, `{"ret":1}`, `{"code":0}`, `{"success":true}`} {
		t.Run(payload, func(t *testing.T) {
			r, _, _ := testRuntime(func(req *http.Request) (*http.Response, error) {
				if req.Method == "GET" {
					return user(""), nil
				}
				return response(200, payload), nil
			})
			result := runTest(r, testAccount())
			if result["success"] != true {
				t.Fatalf("%#v", result)
			}
		})
	}
	for _, payload := range []string{`{"success":false,"code":0}`, `{"success":1}`, `{"ret":true}`, `{"code":false}`, `{"ret":1.0}`, `{"code":0e0}`} {
		t.Run(payload, func(t *testing.T) {
			r, s, _ := testRuntime(func(req *http.Request) (*http.Response, error) {
				if req.Method == "GET" {
					return user(""), nil
				}
				return response(200, payload), nil
			})
			assertReason(t, runTest(r, testAccount()), "failed", "checkin_rejected")
			if s.saves != 0 {
				t.Fatal("failed response saved")
			}
		})
	}
}

func TestAnyPostVerificationFailureIsUncertain(t *testing.T) {
	reads := 0
	r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
		if req.Method == "POST" {
			return response(200, `{"success":true}`), nil
		}
		reads++
		if reads == 2 {
			return response(401, `{}`), nil
		}
		return user(""), nil
	})
	result := runTest(r, testAccount())
	assertReason(t, result, "uncertain", "checkin_verification_failed")
	if result["verification_reason"] != "credentials_rejected" || s.saves != 0 || len(*requests) != 3 {
		t.Fatal("verification semantics")
	}
}

func TestAgentFreshLoginAndStrictCheckedIn(t *testing.T) {
	for _, scenario := range []struct{ field, outcome, reason string }{{`true`, "success", "agent_checkin_verified"}, {`false`, "failed", "agent_checkin_not_confirmed"}, {`1`, "uncertain", "agent_checkin_result_unknown"}, {`"true"`, "uncertain", "agent_checkin_result_unknown"}, {`null`, "uncertain", "agent_checkin_result_unknown"}} {
		t.Run(scenario.field, func(t *testing.T) {
			r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
				if req.Method != "POST" || req.URL.Host != "agentrouter.org" || req.URL.Path != "/api/user/login" || req.URL.RawQuery != "turnstile=" || req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != "" {
					t.Fatal("agent must freshly login once")
				}
				return user(`"checked_in":` + scenario.field), nil
			})
			result := runTest(r, testAgent())
			assertReason(t, result, scenario.outcome, scenario.reason)
			if len(*requests) != 1 || s.loads != 0 || s.saves != 0 {
				t.Fatal("unexpected session action")
			}
			if _, ok := result["balance_after"]; ok {
				t.Fatal("login placeholder exposed")
			}
		})
	}
}

func TestAgentAuxiliaryBalanceFailurePreservesCheckin(t *testing.T) {
	r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
		if req.Method == "POST" {
			return response(200, `{"success":true,"data":{"id":42,"username":"alice","checked_in":true,"quota":0}}`, "Set-Cookie", "session=agent; Path=/; Secure"), nil
		}
		return response(429, `{}`, "Retry-After", "60"), nil
	})
	r.Config["monitoring"] = Document{"enabled": true}
	result := runTest(r, testAgent())
	assertReason(t, result, "success", "agent_checkin_verified")
	if r.BalanceError["reason"] != "rate_limited" || s.saves != 1 || len(*requests) != 2 || len(r.BalanceObservations) != 0 {
		t.Fatal("auxiliary failure changed confirmed result")
	}
}

func TestBalanceNeverLogsInOrSignsIn(t *testing.T) {
	for _, a := range []Document{testPassword(), testAgent()} {
		r, _, requests := testRuntime(func(req *http.Request) (*http.Response, error) { t.Fatal("must not request"); return nil, nil })
		result := r.Balance(context.Background(), a, nil)
		assertReason(t, result, "needs_credentials", "balance_session_required")
		if len(*requests) != 0 {
			t.Fatal("requests sent")
		}
	}
	r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
		if req.Method != "GET" || req.URL.Path != "/api/user/self" {
			t.Fatal("balance mutation")
		}
		return user(""), nil
	})
	result := r.Balance(context.Background(), testAccount(), nil)
	assertReason(t, result, "success", "balance_refreshed")
	if s.saves != 0 || len(*requests) != 1 || len(r.BalanceObservations) != 1 {
		t.Fatal("balance observation missing")
	}
}

func TestAgentReadOnlyUsesPersistedSession(t *testing.T) {
	a := testAgent()
	r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
		if req.Method != "GET" || req.Header.Get("Cookie") != "session=saved-agent" {
			t.Fatal("wrong readonly session")
		}
		return response(401, `{}`), nil
	})
	s.data[a["id"].(string)+AccountBinding(a, r.Config)] = Document{"api_user": "42", "cookies": []Document{{"name": "session", "value": "saved-agent", "domain": "agentrouter.org", "path": "/", "expires": nil}}}
	assertReason(t, r.Balance(context.Background(), a, nil), "needs_credentials", "credentials_rejected")
	if len(*requests) != 1 || s.saves != 0 {
		t.Fatal("readonly retried")
	}
}

func TestNetworkErrorsAndChallengeClassification(t *testing.T) {
	scenarios := []struct {
		name                                 string
		status                               int
		body, header, value, outcome, reason string
	}{{"429", 429, `{}`, "Retry-After", "60", "rate_limited", "rate_limited"}, {"redirect", 302, `{}`, "Location", "https://unrelated.test", "blocked", "response_redirected"}, {"server", 503, `{}`, "", "", "uncertain", "request_result_unknown"}, {"cloudflare", 200, `<html>cloudflare</html>`, "Content-Type", "text/html", "blocked", "interactive_verification_required"}, {"header", 200, `{}`, "cf-mitigated", "challenge", "blocked", "interactive_verification_required"}, {"html", 200, `<html>Login</html>`, "Content-Type", "text/html", "blocked", "html_response_received"}, {"badjson", 200, `no`, "", "", "uncertain", "invalid_json_response"}, {"array", 200, `[]`, "", "", "uncertain", "invalid_json_response"}, {"trailing", 200, `{} {}`, "", "", "uncertain", "invalid_json_response"}, {"401", 401, `oops`, "", "", "needs_credentials", "credentials_rejected"}, {"403", 403, `oops`, "", "", "blocked", "access_blocked"}, {"auth", 200, `{"message":"invalid token"}`, "", "", "needs_credentials", "credentials_rejected"}, {"timeout", 0, "", "", "", "uncertain", "request_result_unknown"}}
	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
				if scenario.status == 0 {
					return nil, context.DeadlineExceeded
				}
				return response(scenario.status, scenario.body, scenario.header, scenario.value), nil
			})
			result := runTest(r, testAgent())
			assertReason(t, result, scenario.outcome, scenario.reason)
			if len(*requests) != 1 || s.saves != 0 {
				t.Fatal("failure retried or stored")
			}
			if scenario.status == 429 && result["retry_after_seconds"] != 60 {
				t.Fatal("retry-after")
			}
		})
	}
}

func TestACWNegotiationUsesSameCookiesAndNeverLeaks(t *testing.T) {
	html := acwFixture(t)
	logins := 0
	r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/user/login" {
			logins++
			if logins == 1 {
				return response(200, html, "Content-Type", "text/html", "Set-Cookie", "cdn_sec_tc=synthetic-seed; Path=/; Secure; HttpOnly"), nil
			}
			cookie := req.Header.Get("Cookie")
			if !strings.Contains(cookie, "cdn_sec_tc=synthetic-seed") || !strings.Contains(cookie, "acw_sc__v2=699dbedad126579b6bc0ebb91eaae8d7af3548b5") {
				t.Fatal("ACW cookie context lost")
			}
			return response(200, `{"success":true,"data":{"id":42}}`, "Set-Cookie", "session=fresh-session; Path=/; Secure; HttpOnly"), nil
		}
		if req.Method == "GET" {
			return user(""), nil
		}
		return response(200, `{"success":true}`), nil
	})
	events := []Document{}
	result := r.Execute(context.Background(), testPassword(), func(d Document) { events = append(events, d) })
	assertReason(t, result, "success", "checkin_verified")
	if len(*requests) != 5 || s.saves != 1 || logins != 2 {
		t.Fatal("wrong attempt counts")
	}
	states := []string{}
	for _, step := range result["steps"].([]Document) {
		if step["stage"] == "password_login" {
			states = append(states, text(step["state"]))
		}
		if step["state"] == "failed" {
			t.Fatal("ACW challenge shown as failure")
		}
	}
	if !reflect.DeepEqual(states, []string{"verification_required", "completed"}) {
		t.Fatalf("states %v", states)
	}
	encoded, _ := json.Marshal([]any{result, events})
	for _, secret := range []string{"synthetic-password", "fresh-session", "synthetic-seed", "699dbedad126579b6bc0ebb91eaae8d7af3548b5"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("secret leaked")
		}
	}
}

func TestACWBoundAndNoUnsupportedRetry(t *testing.T) {
	html := acwFixture(t)
	for _, scenario := range []struct {
		name, page, cookie, reason string
		attempts                   int
	}{{"limit", html, "seed=x; Path=/; Secure", "acw_challenge_limit", 3}, {"missing", html, "", "acw_cookie_context_missing", 1}, {"domain", html, "seed=x; Domain=elsewhere.test; Path=/; Secure", "acw_cookie_context_missing", 1}, {"template", strings.Replace(html, "function a0i()", "function unknown()", 1), "seed=x; Path=/", "acw_challenge_unsupported", 1}, {"script", html + "<script>alert(1)</script>", "seed=x; Path=/", "acw_challenge_unsupported", 1}} {
		t.Run(scenario.name, func(t *testing.T) {
			r, s, requests := testRuntime(func(*http.Request) (*http.Response, error) {
				return response(200, scenario.page, "Content-Type", "text/html", "Set-Cookie", scenario.cookie), nil
			})
			result := runTest(r, testPassword())
			assertReason(t, result, "blocked", scenario.reason)
			if len(*requests) != scenario.attempts || s.saves != 0 {
				t.Fatal("ACW bound violated")
			}
		})
	}
}

func TestACWMutationsNeverRepeated(t *testing.T) {
	html := acwFixture(t)
	for _, a := range []Document{testAccount(), testAgent()} {
		r, s, requests := testRuntime(func(req *http.Request) (*http.Response, error) {
			if req.Method == "GET" {
				return user(""), nil
			}
			return response(200, html, "Content-Type", "text/html", "Set-Cookie", "seed=x; Path=/; Secure"), nil
		})
		result := runTest(r, a)
		assertReason(t, result, "uncertain", "acw_challenge_requires_confirmation")
		want := 2
		if a["provider"] == "agentrouter" {
			want = 1
		}
		if len(*requests) != want || s.saves != 0 {
			t.Fatal("mutation repeated")
		}
	}
}

func TestCookieAndSavedStateValidation(t *testing.T) {
	for _, cookie := range []any{"", "not-a-pair", "session=x\r\nInjected=x", "session=x; missing", Document{"session": true}, "session=非ASCII"} {
		t.Run(fmt.Sprint(cookie), func(t *testing.T) {
			r, _, requests := testRuntime(func(*http.Request) (*http.Response, error) { t.Fatal("invalid cookie requested"); return nil, nil })
			a := testAccount()
			a["cookies"] = cookie
			assertReason(t, runTest(r, a), "needs_credentials", "invalid_cookie_configuration")
			if len(*requests) != 0 {
				t.Fatal("request")
			}
		})
	}
	r, s, _ := testRuntime(func(*http.Request) (*http.Response, error) { return nil, errors.New("secret cookie raw network error") })
	s.loadErr = errors.New("sensitive database information")
	assertReason(t, runTest(r, testAccount()), "failed", "session_load_failed")
}

func TestAccountBindingMatchesPython(t *testing.T) {
	python := ""
	for _, candidate := range []string{filepath.Join("..", "..", ".venv", "Scripts", "python.exe"), "python3", "python"} {
		if filepath.IsAbs(candidate) || strings.Contains(candidate, string(filepath.Separator)) {
			if _, err := os.Stat(candidate); err == nil {
				python = candidate
				break
			}
		} else if p, err := exec.LookPath(candidate); err == nil {
			python = p
			break
		}
	}
	if python == "" {
		t.Skip("Python unavailable for cross-language compatibility test")
	}
	a := testPassword()
	a["username"], a["password"], a["proxy"] = "张三😀", "<>&密码", nil
	cfg := Document{"proxy_url": "socks5://u:p@localhost:1080"}
	payload, _ := json.Marshal(Document{"account": a, "config": cfg})
	code := `import sys,json,hashlib; d=json.loads(sys.stdin.buffer.read().decode("utf-8")); a=d['account']; c=d['config']; fields=('id','provider','auth_type','cookies','username','password','system_access_token','api_user','expected_username','proxy'); b={k:a.get(k) for k in fields}; b.update({'proxy_url':c.get('proxy_url')} if a.get('proxy') in (None,'','default') else {}); raw=json.dumps(b,sort_keys=True,separators=(',',':')); print(hashlib.sha256(raw.encode()).hexdigest());print(raw)`
	cmd := exec.Command(python, "-c", code)
	cmd.Stdin = strings.NewReader(string(payload))
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)
	if got := AccountBinding(a, cfg); got != strings.TrimSpace(want[0]) {
		bound := Document{}
		for _, key := range []string{"id", "provider", "auth_type", "cookies", "username", "password", "system_access_token", "api_user", "expected_username", "proxy"} {
			bound[key] = a[key]
		}
		bound["proxy_url"] = cfg["proxy_url"]
		left, right := PythonJSON(bound), []byte(strings.TrimSpace(want[1]))
		for i := 0; i < len(left) && i < len(right); i++ {
			if left[i] != right[i] {
				t.Fatalf("binding mismatch at byte %d: %d != %d", i, left[i], right[i])
			}
		}
		t.Fatalf("binding mismatch length %d != %d", len(left), len(right))
	}
}

func TestRetryAfterBounds(t *testing.T) {
	for _, tc := range []struct {
		value   string
		seconds int
		ok      bool
	}{{"60", 60, true}, {"-2", 0, true}, {"999999999", 31536000, true}, {"junk", 0, false}} {
		v, ok := retryAfter(tc.value)
		if ok != tc.ok || v != tc.seconds {
			t.Fatalf("retry after %s: %d/%v", tc.value, v, ok)
		}
	}
	v, ok := retryAfter(time.Now().Add(60 * time.Second).UTC().Format(http.TimeFormat))
	if !ok || v < 59 || v > 60 {
		t.Fatal("HTTP date retry-after")
	}
}
