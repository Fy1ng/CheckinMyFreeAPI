package storage

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strconv"
	"time"
)

var StatisticsZone = time.FixedZone("Asia/Singapore", 8*3600)

func Day(at float64) string {
	return time.Unix(0, int64(at*1e9)).In(StatisticsZone).Format("2006-01-02")
}
func rowsDocuments(rows *sql.Rows) ([]Document, error) {
	defer rows.Close()
	columns, e := rows.Columns()
	if e != nil {
		return nil, e
	}
	out := []Document{}
	for rows.Next() {
		values := make([]any, len(columns))
		refs := make([]any, len(columns))
		for i := range values {
			refs[i] = &values[i]
		}
		if e = rows.Scan(refs...); e != nil {
			return nil, e
		}
		d := Document{}
		for i, k := range columns {
			d[k] = values[i]
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
func (s *Store) Query(query string, args ...any) ([]Document, error) {
	r, e := s.DB.Query(query, args...)
	if e != nil {
		return nil, e
	}
	return rowsDocuments(r)
}
func (s *Store) one(query string, args ...any) (Document, error) {
	r, e := s.Query(query, args...)
	if e != nil {
		return nil, e
	}
	if len(r) == 0 {
		return nil, nil
	}
	return r[0], nil
}
func (s *Store) Attention(id, binding string) (Document, error) {
	d, e := s.one("SELECT outcome,reason,retry_at,updated_at,binding FROM account_attention WHERE account_id=?", id)
	if e != nil || d == nil {
		return nil, e
	}
	if d["binding"] != binding && d["outcome"] != "uncertain" {
		return nil, nil
	}
	delete(d, "binding")
	return d, nil
}
func (s *Store) ClearAttention(id string) error {
	_, e := s.DB.Exec("DELETE FROM account_attention WHERE account_id=?", id)
	return e
}
func (s *Store) RecordAttention(id, binding string, result Document) error {
	outcome := String(result["outcome"])
	if outcome != "needs_credentials" && outcome != "blocked" && outcome != "rate_limited" && outcome != "uncertain" {
		if Bool(result["success"]) {
			return s.ClearAttention(id)
		}
		return nil
	}
	var retry any
	if outcome == "rate_limited" {
		delay, ok := Number(result["retry_after_seconds"])
		if !ok || math.IsNaN(delay) || math.IsInf(delay, 0) {
			delay = 3600
		}
		retry = Now() + math.Max(1, math.Min(86400, delay))
	}
	_, e := s.DB.Exec("INSERT OR REPLACE INTO account_attention VALUES (?,?,?,?,?,?)", id, binding, outcome, safeCode(result["reason"]), retry, Now())
	return e
}
func rat(v any) *big.Rat {
	var str string
	switch x := v.(type) {
	case string:
		str = x
	case json.Number:
		str = x.String()
	default:
		n, ok := Number(v)
		if !ok || math.IsInf(n, 0) || math.IsNaN(n) {
			return nil
		}
		str = strconv.FormatFloat(n, 'g', -1, 64)
	}
	r, ok := new(big.Rat).SetString(str)
	if !ok {
		return nil
	}
	return r
}
func quota(v any) *big.Rat {
	if _, ok := Number(v); !ok {
		return nil
	}
	r := rat(v)
	if r == nil || r.Sign() < 0 || r.Cmp(new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(24), nil))) > 0 {
		return nil
	}
	return r.Quo(r, big.NewRat(500000, 1))
}
func rationalText(r *big.Rat) any {
	if r == nil {
		return nil
	}
	return r.FloatString(10)
}
func rationalNumber(v any) any {
	r := rat(v)
	if r == nil {
		return nil
	}
	n, _ := r.Float64()
	return math.Round(n*1e10) / 1e10
}
func (s *Store) BalanceRecord(account, config, observation Document) (bool, error) {
	q, u, income := quota(observation["quota"]), quota(observation["used_quota"]), quota(observation["today_income"])
	at := Now()
	if v, ok := observation["observed_at"]; ok {
		at, _ = Number(v)
	}
	if q == nil || !isFinite(at) || at <= 0 || at > Now()+300 {
		return false, s.BalanceFailure(account, config, "failed", "invalid_balance_data")
	}
	identity, e := apiUser(observation["id"])
	if e != nil || identity == "" {
		return false, s.BalanceFailure(account, config, "failed", "invalid_balance_identity")
	}
	hash := sha256.Sum256([]byte(identity))
	identity = hex.EncodeToString(hash[:])
	id := String(account["id"])
	binding := AccountBinding(account, config)
	current, e := s.one("SELECT * FROM balance_accounts WHERE account_id=?", id)
	if e != nil {
		return false, e
	}
	if current != nil && current["binding"] == binding {
		if current["identity"] != nil && current["identity"] != identity {
			return false, s.BalanceFailure(account, config, "needs_credentials", "account_identity_mismatch")
		}
		oldAt, ok := Number(current["observed_at"])
		if ok && oldAt > at {
			return false, nil
		}
	}
	var total *big.Rat
	if u != nil {
		total = new(big.Rat).Add(q, u)
	}
	day := Day(at)
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.Begin()
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	var opening, closing, credits string
	var oldTotal, siteIncome sql.NullString
	var samples, reset int
	var first, last float64
	e = tx.QueryRow("SELECT opening,closing,total,credits,site_income,samples,first_at,last_at,reset FROM balance_days WHERE account_id=? AND binding=? AND day=?", id, binding, day).Scan(&opening, &closing, &oldTotal, &credits, &siteIncome, &samples, &first, &last, &reset)
	if errors.Is(e, sql.ErrNoRows) {
		_, e = tx.Exec("INSERT INTO balance_days VALUES (?,?,?,?,?,?,?,?,?,?,?,0)", id, binding, day, rationalText(q), rationalText(q), rationalText(total), "0", rationalText(income), 1, at, at)
	} else if e == nil {
		c := rat(credits)
		if c == nil {
			return false, ErrInvalid
		}
		if total != nil && oldTotal.Valid {
			previousTotal := rat(oldTotal.String)
			if previousTotal == nil {
				return false, ErrInvalid
			}
			delta := new(big.Rat).Sub(total, previousTotal)
			if delta.Sign() >= 0 {
				c.Add(c, delta)
			} else {
				reset = 1
			}
		} else {
			reset = 1
		}
		_, e = tx.Exec("UPDATE balance_days SET closing=?,total=?,credits=?,site_income=?,samples=samples+1,last_at=?,reset=? WHERE account_id=? AND binding=? AND day=?", rationalText(q), rationalText(total), rationalText(c), rationalText(income), at, reset, id, binding, day)
	}
	if e != nil {
		return false, e
	}
	if _, e = tx.Exec("INSERT OR REPLACE INTO balance_accounts VALUES (?,?,?,?,?,?,?,?,?,?)", id, binding, identity, rationalText(q), rationalText(u), rationalText(total), at, "ok", nil, at); e != nil {
		return false, e
	}
	if _, e = tx.Exec("DELETE FROM balance_retry WHERE account_id=?", id); e != nil {
		return false, e
	}
	cutoff := time.Unix(0, int64(at*1e9)).In(StatisticsZone).AddDate(0, 0, -400).Format("2006-01-02")
	if _, e = tx.Exec("DELETE FROM balance_days WHERE day<?", cutoff); e != nil {
		return false, e
	}
	return true, tx.Commit()
}
func isFinite(n float64) bool { return !math.IsNaN(n) && !math.IsInf(n, 0) }
func safeCode(v any) string {
	s := String(v)
	if len(s) == 0 || len(s) > 128 {
		return "operation_failed"
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return "operation_failed"
		}
	}
	return s
}
func (s *Store) BalanceFailure(account, config Document, state, reason string) error {
	switch state {
	case "unknown", "needs_credentials", "blocked", "rate_limited", "failed":
	default:
		state = "failed"
	}
	_, e := s.DB.Exec(`INSERT INTO balance_accounts(account_id,binding,state,reason,attempted_at) VALUES (?,?,?,?,?) ON CONFLICT(account_id) DO UPDATE SET identity=CASE WHEN binding=excluded.binding THEN identity ELSE NULL END,balance=CASE WHEN binding=excluded.binding THEN balance ELSE NULL END,used=CASE WHEN binding=excluded.binding THEN used ELSE NULL END,total=CASE WHEN binding=excluded.binding THEN total ELSE NULL END,observed_at=CASE WHEN binding=excluded.binding THEN observed_at ELSE NULL END,binding=excluded.binding,state=excluded.state,reason=excluded.reason,attempted_at=excluded.attempted_at`, account["id"], AccountBinding(account, config), state, safeCode(reason), Now())
	return e
}
func (s *Store) BalanceRateLimit(account, config Document, delay any) error {
	n, ok := Number(delay)
	if !ok || !isFinite(n) {
		n = 3600
	}
	_, e := s.DB.Exec("INSERT OR REPLACE INTO balance_retry VALUES (?,?,?)", account["id"], AccountBinding(account, config), Now()+math.Max(1, math.Min(n, 86400)))
	return e
}
func (s *Store) BalanceRetryAt(account, config Document) (any, error) {
	var at float64
	e := s.DB.QueryRow("SELECT retry_at FROM balance_retry WHERE account_id=? AND binding=?", account["id"], AccountBinding(account, config)).Scan(&at)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	return at, e
}
func daily(row Document) Document {
	d := Document{"today_income": nil, "today_net_change": nil, "income_source": nil, "partial": true, "income_partial": true, "net_change_partial": true, "observed_since": nil}
	if row == nil {
		return d
	}
	d["observed_since"] = Stamp(row["first_at"])
	var income any
	var source any
	if row["site_income"] != nil {
		income = row["site_income"]
		source = "site"
	} else if Int(row["samples"]) > 1 && Int(row["reset"]) == 0 && row["total"] != nil {
		income = row["credits"]
		source = "observed"
	}
	d["today_income"] = rationalNumber(income)
	d["income_source"] = source
	d["income_partial"] = source != "site"
	if Int(row["samples"]) > 1 {
		close, open := rat(row["closing"]), rat(row["opening"])
		if close != nil && open != nil {
			d["today_net_change"] = rationalNumber(rationalText(new(big.Rat).Sub(close, open)))
		}
	}
	return d
}
func combine(items []any, key string) any {
	sum := new(big.Rat)
	count := 0
	for _, v := range items {
		d := Object(v)
		if r := rat(d[key]); r != nil {
			sum.Add(sum, r)
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return rationalNumber(rationalText(sum))
}
func countKnown(items []any, key string) int {
	n := 0
	for _, v := range items {
		if Object(v)[key] != nil {
			n++
		}
	}
	return n
}
func (s *Store) BalanceSnapshot(config Document, now ...float64) (Document, error) {
	at := Now()
	if len(now) > 0 {
		at = now[0]
	}
	day := Day(at)
	accounts := []any{}
	active := []any{}
	byDay := map[string][]any{}
	freshFor := float64(Int(Object(config["monitoring"])["interval_minutes"])*60 + 300)
	cutoff := time.Unix(0, int64(at*1e9)).In(StatisticsZone).AddDate(0, 0, -29).Format("2006-01-02")
	for _, v := range Array(config["accounts"]) {
		account := Object(v)
		binding := AccountBinding(account, config)
		row, e := s.one("SELECT * FROM balance_accounts WHERE account_id=? AND binding=?", account["id"], binding)
		if e != nil {
			return nil, e
		}
		today, e := s.one("SELECT * FROM balance_days WHERE account_id=? AND binding=? AND day=?", account["id"], binding, day)
		if e != nil {
			return nil, e
		}
		enabled := Bool(account["enabled"])
		observed, observedOK := Number(row["observed_at"])
		stale := row == nil || row["state"] != "ok" || !observedOK || at-observed > freshFor
		state := "unknown"
		var reason any = "balance_not_collected"
		if row != nil {
			state = String(row["state"])
			reason = row["reason"]
		}
		if !enabled {
			state = "disabled"
		}
		entry := Document{"id": account["id"], "name": account["name"], "provider": account["provider"], "enabled": enabled, "balance": rationalNumber(row["balance"]), "used": rationalNumber(row["used"]), "updated_at": Stamp(row["observed_at"]), "stale": stale, "state": state, "reason": reason}
		for k, v := range daily(today) {
			entry[k] = v
		}
		accounts = append(accounts, entry)
		if enabled {
			active = append(active, entry)
			history, e := s.Query("SELECT * FROM balance_days WHERE account_id=? AND binding=? AND day>=? AND day<=?", account["id"], binding, cutoff, day)
			if e != nil {
				return nil, e
			}
			for _, r := range history {
				d := daily(r)
				d["balance"] = rationalNumber(r["closing"])
				k := String(r["day"])
				byDay[k] = append(byDay[k], d)
			}
		}
	}
	summary := Document{"balance": combine(active, "balance"), "today_income": combine(active, "today_income"), "today_net_change": combine(active, "today_net_change"), "account_count": len(active), "balance_count": countKnown(active, "balance"), "income_count": countKnown(active, "today_income"), "net_change_count": countKnown(active, "today_net_change")}
	fresh := 0
	for _, v := range active {
		if !Bool(Object(v)["stale"]) {
			fresh++
		}
	}
	summary["fresh_count"] = fresh
	history := []any{}
	for d := time.Unix(0, int64(at*1e9)).In(StatisticsZone).AddDate(0, 0, -29); Day(float64(d.Unix())) <= day; d = d.AddDate(0, 0, 1) {
		key := d.Format("2006-01-02")
		items := byDay[key]
		if len(items) == 0 {
			continue
		}
		history = append(history, Document{"day": key, "balance": combine(items, "balance"), "today_income": combine(items, "today_income"), "today_net_change": combine(items, "today_net_change"), "balance_count": len(items), "income_count": countKnown(items, "today_income"), "net_change_count": countKnown(items, "today_net_change")})
	}
	return Document{"timezone": "Asia/Singapore", "day": day, "summary": summary, "accounts": accounts, "history": history}, nil
}
