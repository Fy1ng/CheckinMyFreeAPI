package storage

import (
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	s, e := Open(filepath.Join(t.TempDir(), "webui.sqlite3"), make([]byte, 32))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	return s
}
func testConfig() Document {
	d := DefaultConfig()
	d["accounts"] = []any{Document{"id": "test", "name": "测试", "provider": "anyrouter", "auth_type": "password", "enabled": true, "username": "测试<&>", "password": "test-only"}}
	return d
}
func TestConfigRoundTripAndSecrets(t *testing.T) {
	s := testStore(t)
	d, r, e := s.Load()
	if e != nil || r != 0 || len(Array(d["accounts"])) != 0 {
		t.Fatal(d, r, e)
	}
	config := testConfig()
	config["proxy_url"] = "socks5://test-user:test-value@proxy.example:1080"
	Object(config["backups"])["password"] = "test recovery password"
	Object(config["notifications"])["FY1PUSH_TOKEN"] = "test-only-token"
	public, r, e := s.Save(config, 0)
	if e != nil || r != 1 {
		t.Fatal(r, e)
	}
	if public["proxy_url"] != SecretKeep || Object(Array(public["accounts"])[0])["password"] != SecretKeep || Object(public["notifications"])["FY1PUSH_TOKEN"] != SecretKeep {
		t.Fatal("secrets were not redacted")
	}
	Object(Array(public["accounts"])[0])["name"] = "changed"
	_, r, e = s.Save(public, 1)
	if e != nil || r != 2 {
		t.Fatal(r, e)
	}
	loaded, _, e := s.Load()
	if e != nil || Object(Array(loaded["accounts"])[0])["password"] != "test-only" {
		t.Fatal("saved credential lost", e)
	}
	if _, _, e = s.Save(config, 1); !errors.Is(e, ErrConflict) {
		t.Fatal("stale revision accepted", e)
	}
	b, e := os.ReadFile(s.Path)
	if e != nil {
		t.Fatal(e)
	}
	if string(b) == "test-only" {
		t.Fatal("plaintext database")
	}
}
func TestConfigValidationRejectsUntrustedValues(t *testing.T) {
	tests := []struct {
		name   string
		change func(Document)
	}{{"nan", func(d Document) { Object(Object(d["automation"])["low_balance"])["threshold"] = math.NaN() }}, {"unknown", func(d Document) { d["other"] = true }}, {"missing credential", func(d Document) { Object(Array(d["accounts"])[0])["password"] = "" }}, {"mix credentials", func(d Document) { Object(Array(d["accounts"])[0])["cookies"] = "session=test" }}, {"unsupported provider", func(d Document) { Object(Array(d["accounts"])[0])["provider"] = "custom" }}, {"credential default", func(d Document) { Object(Array(d["accounts"])[0])["proxy"] = "default" }}, {"invalid socks", func(d Document) { d["proxy_url"] = "socks5://user@proxy.example:1080" }}, {"remote http url", func(d Document) { d["webui_url"] = "http://checkin.example" }}, {"cron too frequent", func(d Document) { Object(d["schedule"])["cron"] = "*/5 * * * *" }}, {"invalid cron", func(d Document) { Object(d["schedule"])["cron"] = "* * * * JAN" }}, {"bad cookie", func(d Document) {
		a := Object(Array(d["accounts"])[0])
		a["enabled"] = false
		a["password"] = ""
		a["username"] = ""
		a["auth_type"] = "cookie"
		a["cookies"] = "bad"
	}}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := testConfig()
			tt.change(d)
			if _, e := Validate(d); e == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
}
func TestSecretMarkerCannotCrossCredentialIdentity(t *testing.T) {
	d := testConfig()
	old, _ := Validate(d)
	public := Redact(old)
	a := Object(Array(public["accounts"])[0])
	a["auth_type"] = "cookie"
	a["username"] = ""
	if _, e := RestoreSecrets(public, old); e == nil {
		t.Fatal("reused password marker across auth mode")
	}
}
func TestPythonBindingAndSessionEncryption(t *testing.T) {
	d := testConfig()
	a := Object(Array(d["accounts"])[0])
	binding := AccountBinding(a, d)
	if binding != "3f3d83431eec5ed48b2b574b0268c5d1f97e25270ad4304f01a2c61de93e10f8" {
		t.Fatal("Python fingerprint mismatch", binding)
	}
	s := testStore(t)
	state := Document{"api_user": "123", "cookies": []any{Document{"name": "session", "value": "local-test-only", "domain": "anyrouter.top", "path": "/", "expires": nil}}}
	if e := s.SaveSession("test", binding, state); e != nil {
		t.Fatal(e)
	}
	saved, e := s.LoadSession("test", binding)
	if e != nil || saved["api_user"] != "123" {
		t.Fatal(saved, e)
	}
	if mismatch, e := s.LoadSession("test", "different binding"); e != nil || mismatch != nil {
		t.Fatal("mismatched session leaked", e)
	}
	var blob []byte
	if e = s.DB.QueryRow("SELECT document FROM http_sessions").Scan(&blob); e != nil {
		t.Fatal(e)
	}
	blob[len(blob)-1] ^= 1
	if _, e = s.DB.Exec("UPDATE http_sessions SET document=?", blob); e != nil {
		t.Fatal(e)
	}
	if _, e = s.LoadSession("test", binding); e == nil {
		t.Fatal("tampered session accepted")
	}
}
func TestAgentMigrationArchivesCiphertext(t *testing.T) {
	s := testStore(t)
	d := DefaultConfig()
	d["accounts"] = []any{Document{"id": "agent", "name": "agent", "provider": "agentrouter", "auth_type": "system_token", "system_access_token": "local-test-only", "enabled": true}}
	plain, _ := json.Marshal(d)
	blob, e := Encrypt(s.Key, plain, []byte(ConfigAAD+"1"))
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("INSERT INTO config VALUES(1,1,?)", blob); e != nil {
		t.Fatal(e)
	}
	loaded, r, e := s.Load()
	if e != nil || r != 2 {
		t.Fatal(r, e)
	}
	a := Object(Array(loaded["accounts"])[0])
	if a["auth_type"] != "password" || Bool(a["enabled"]) || a["system_access_token"] != nil {
		t.Fatal("migration unsafe")
	}
	m, e := s.MigrationInfo()
	if e != nil || Int(m["source_revision"]) != 1 {
		t.Fatal(m, e)
	}
	var archived []byte
	if e = s.DB.QueryRow("SELECT document FROM config_archive").Scan(&archived); e != nil || string(archived) != string(blob) {
		t.Fatal("archive changed", e)
	}
}
func TestAttentionUnknownSurvivesCredentialChanges(t *testing.T) {
	s := testStore(t)
	if e := s.RecordAttention("test", "old", Document{"success": false, "outcome": "uncertain", "reason": "request_timeout"}); e != nil {
		t.Fatal(e)
	}
	a, e := s.Attention("test", "new")
	if e != nil || a["outcome"] != "uncertain" {
		t.Fatal(a, e)
	}
	if e = s.RecordAttention("test", "old", Document{"success": false, "outcome": "needs_credentials", "reason": "invalid_session"}); e != nil {
		t.Fatal(e)
	}
	a, e = s.Attention("test", "new")
	if e != nil || a != nil {
		t.Fatal("old credential pause should be scoped", e)
	}
	if e = s.RecordAttention("test", "new", Document{"success": false, "outcome": "rate_limited", "reason": "rate_limited", "retry_after_seconds": 20}); e != nil {
		t.Fatal(e)
	}
	a, e = s.Attention("test", "new")
	at, _ := Number(a["retry_at"])
	if e != nil || at < Now()+18 || at > Now()+21 {
		t.Fatal(a, e)
	}
}
func TestBalanceObservationIncomeAndIdentity(t *testing.T) {
	s := testStore(t)
	d := testConfig()
	a := Object(Array(d["accounts"])[0])
	now := float64(time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).Unix())
	if now > Now() {
		now = Now() - 300
	}
	one := Document{"id": json.Number("123"), "quota": json.Number("1000000"), "used_quota": json.Number("500000"), "observed_at": now}
	if ok, e := s.BalanceRecord(a, d, one); e != nil || !ok {
		t.Fatal(ok, e)
	}
	snapshot, e := s.BalanceSnapshot(d, now)
	if e != nil {
		t.Fatal(e)
	}
	summary := Object(snapshot["summary"])
	if summary["balance"] != float64(2) || summary["today_income"] != nil {
		t.Fatal("first observation invented income", summary)
	}
	two := Document{"id": json.Number("123"), "quota": json.Number("1250000"), "used_quota": json.Number("750000"), "observed_at": now + 1}
	if ok, e := s.BalanceRecord(a, d, two); e != nil || !ok {
		t.Fatal(ok, e)
	}
	snapshot, e = s.BalanceSnapshot(d, now+1)
	if e != nil {
		t.Fatal(e)
	}
	summary = Object(snapshot["summary"])
	if summary["today_income"] != float64(1) || summary["today_net_change"] != float64(.5) {
		t.Fatal(summary)
	}
	three := Clone(two)
	three["id"] = json.Number("124")
	three["observed_at"] = now + 2
	if ok, e := s.BalanceRecord(a, d, three); e != nil || ok {
		t.Fatal("identity mismatch accepted", ok, e)
	}
	snapshot, e = s.BalanceSnapshot(d, now+2)
	if e != nil {
		t.Fatal(e)
	}
	entry := Object(Array(snapshot["accounts"])[0])
	if entry["balance"] != float64(2.5) || entry["state"] != "needs_credentials" || !Bool(entry["stale"]) {
		t.Fatal(entry)
	}
}
func TestAutomationRecoveryAndLowBalanceDedup(t *testing.T) {
	s := testStore(t)
	d := testConfig()
	a := Object(Array(d["accounts"])[0])
	Object(Object(d["automation"])["recovery"])["enabled"] = true
	Object(Object(d["automation"])["low_balance"])["enabled"] = true
	now := Now()
	ids, e := s.RecordHealth(a, d, "checkin", Document{"success": true, "outcome": "completed"}, 1, now)
	if e != nil || len(ids) != 0 {
		t.Fatal("first success is not recovery", ids, e)
	}
	if _, e = s.RecordHealth(a, d, "checkin", Document{"success": false, "outcome": "uncertain", "reason": "request_timeout"}, 1, now+1); e != nil {
		t.Fatal(e)
	}
	ids, e = s.RecordHealth(a, d, "balance", Document{"success": true, "outcome": "completed"}, 1, now+2)
	if e != nil || len(ids) != 0 {
		t.Fatal("balance cannot recover checkin", ids, e)
	}
	ids, e = s.RecordHealth(a, d, "checkin", Document{"success": true, "outcome": "completed"}, 1, now+3)
	if e != nil || len(ids) != 1 {
		t.Fatal(ids, e)
	}
	low := Document{"balance": float64(.5), "stale": false, "state": "ok"}
	ids, e = s.CheckLowBalance(a, d, low, 1, now)
	if e != nil || len(ids) != 1 {
		t.Fatal(ids, e)
	}
	again, e := s.CheckLowBalance(a, d, low, 1, now+40000)
	if e != nil || len(again) != 0 {
		t.Fatal("unconfirmed notification was resent", again, e)
	}
	if e = s.FinishNotification(ids[0], Document{"state": "accepted", "channels": []any{Document{"channel": "Fy1Push", "state": "accepted"}}}); e != nil {
		t.Fatal(e)
	}
	again, e = s.CheckLowBalance(a, d, low, 1, now+40001)
	if e != nil || len(again) != 1 {
		t.Fatal("accepted notification did not honor later cooldown", again, e)
	}
}

func TestPythonPendingLowBalanceWithUnicodeAccountID(t *testing.T) {
	s := testStore(t)
	d := testConfig()
	a := Object(Array(d["accounts"])[0])
	a["id"] = "测试账号"
	Object(Object(d["automation"])["low_balance"])["enabled"] = true
	binding := AccountBinding(a, d)
	episode := float64(1790000000)
	now := episode + 40000
	if _, e := s.DB.Exec("INSERT INTO automation_low_balance VALUES (?,?,1,1,?,?)", a["id"], binding, episode, episode); e != nil {
		t.Fatal(e)
	}
	key := "low:" + String(a["id"]) + ":" + binding + ":1790000000.0:1790000000.0"
	if _, e := s.ClaimNotification(key, "low_balance", "test", "test", a["id"], 1); e != nil {
		t.Fatal(e)
	}
	ids, e := s.CheckLowBalance(a, d, Document{"balance": .5, "stale": false, "state": "ok"}, 1, now)
	if e != nil || len(ids) != 0 {
		t.Fatal("Python pending event was not recognized", ids, e)
	}
}
