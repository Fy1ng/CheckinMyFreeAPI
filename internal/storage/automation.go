package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

func claimTx(tx *sql.Tx, eventKey, kind, title, message string, accountID any, runID any) (int64, error) {
	result, e := tx.Exec("INSERT OR IGNORE INTO automation_notifications(event_key,kind,account_id,state,created_at,title,message,run_id) VALUES (?,?,?,'pending',?,?,?,?)", eventKey, kind, accountID, Now(), truncate(title, 256), truncate(message, 32768), runID)
	if e != nil {
		return 0, e
	}
	affected, e := result.RowsAffected()
	if e != nil || affected == 0 {
		return 0, e
	}
	return result.LastInsertId()
}
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}

// Event keys are shared with Python. Unix timestamps in Python f-strings use
// decimal notation and retain .0 for an integral floating-point timestamp.
func eventTimestamp(v any) string {
	n, ok := Number(v)
	if !ok {
		return "None"
	}
	s := strconv.FormatFloat(n, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}
func (s *Store) ClaimNotification(eventKey, kind, title, message string, accountID any, runID any) (int64, error) {
	tx, e := s.DB.Begin()
	if e != nil {
		return 0, e
	}
	defer tx.Rollback()
	id, e := claimTx(tx, eventKey, kind, title, message, accountID, runID)
	if e != nil {
		return 0, e
	}
	return id, tx.Commit()
}
func (s *Store) PendingNotification(id int64) (Document, error) {
	return s.one("SELECT id,title,message FROM automation_notifications WHERE id=? AND state='pending'", id)
}
func deliveryState(value any) string {
	switch String(value) {
	case "accepted", "partial", "failed", "unknown", "not_configured":
		return String(value)
	}
	return "unknown"
}
func (s *Store) FinishNotification(id int64, delivery Document) error {
	channels := []any{}
	allowed := map[string]bool{}
	for _, n := range []string{"Email", "PushPlus", "Server Push", "DingTalk", "Feishu", "WeChat Work", "Gotify", "Telegram", "Bark", "Fy1Push"} {
		allowed[n] = true
	}
	for _, v := range Array(delivery["channels"]) {
		d := Object(v)
		if !allowed[String(d["channel"])] {
			continue
		}
		var code any
		if d["error_code"] != nil {
			code = safeCode(d["error_code"])
		}
		channels = append(channels, Document{"channel": d["channel"], "state": deliveryState(d["state"]), "error_code": code})
	}
	b, _ := json.Marshal(Document{"channels": channels, "device_delivery": "unconfirmed"})
	_, e := s.DB.Exec("UPDATE automation_notifications SET state=?,finished_at=?,delivery=? WHERE id=? AND state='pending'", deliveryState(delivery["state"]), Now(), string(b), id)
	return e
}
func (s *Store) InterruptPending(runID ...int64) error {
	q := "UPDATE automation_notifications SET state='unknown',finished_at=? WHERE state='pending'"
	a := []any{Now()}
	if len(runID) > 0 {
		q += " AND run_id=?"
		a = append(a, runID[0])
	}
	_, e := s.DB.Exec(q, a...)
	return e
}
func (s *Store) RecordHealth(account, config Document, scope string, result Document, runID any, now ...float64) ([]int64, error) {
	empty := []int64{}
	outcome := String(result["outcome"])
	if scope != "checkin" && scope != "balance" || !Bool(account["enabled"]) || outcome == "skipped" {
		return empty, nil
	}
	failure := outcome == "failed" || outcome == "needs_credentials" || outcome == "blocked" || outcome == "rate_limited" || outcome == "uncertain"
	if !Bool(result["success"]) && !failure {
		return empty, nil
	}
	at := Now()
	if len(now) > 0 {
		at = now[0]
	}
	binding := AccountBinding(account, config)
	id := String(account["id"])
	old, e := s.one("SELECT * FROM automation_health WHERE account_id=? AND binding=? AND scope=?", id, binding, scope)
	if e != nil {
		return nil, e
	}
	failureSince, lastFailure, lastSuccess, recovered, notified := old["failure_since"], old["last_failure_at"], old["last_success_at"], old["recovered_at"], old["recovery_notified_at"]
	consecutive := Int(old["consecutive_failures"])
	state := outcome
	var reason any = safeCode(result["reason"])
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	claimed := []int64{}
	if Bool(result["success"]) {
		settings := Object(Object(config["automation"])["recovery"])
		if since, ok := Number(failureSince); ok {
			recovered = at
			n, notifiedOK := Number(notified)
			if Bool(settings["enabled"]) && (!notifiedOK || at-n >= float64(Int(settings["cooldown_minutes"])*60)) {
				label := "签到"
				if scope == "balance" {
					label = "余额查询"
				}
				message := fmt.Sprintf("%s: %s已恢复. 异常持续 %d 秒. 请在管理面板查看详情.", String(account["name"]), label, int(math.Max(0, at-since)))
				key := fmt.Sprintf("recovery:%s:%s:%s:%s", id, binding, scope, eventTimestamp(since))
				n, e := claimTx(tx, key, "recovery", "账户故障恢复", message, id, runID)
				if e != nil {
					return nil, e
				}
				if n > 0 {
					claimed = append(claimed, n)
					notified = at
				}
			}
		}
		failureSince = nil
		consecutive = 0
		lastSuccess = at
		state = "healthy"
		reason = nil
	} else {
		if failureSince == nil {
			failureSince = at
		}
		lastFailure = at
		consecutive++
	}
	if _, e = tx.Exec("INSERT OR REPLACE INTO automation_health VALUES (?,?,?,?,?,?,?,?,?,?,?)", id, binding, scope, state, reason, failureSince, lastFailure, lastSuccess, recovered, consecutive, notified); e != nil {
		return nil, e
	}
	return claimed, tx.Commit()
}
func (s *Store) CheckLowBalance(account, config, observation Document, runID any, now ...float64) ([]int64, error) {
	settings := Object(Object(config["automation"])["low_balance"])
	empty := []int64{}
	if !Bool(settings["enabled"]) || !Bool(account["enabled"]) || Bool(observation["stale"]) || observation["state"] != "ok" {
		return empty, nil
	}
	balance, ok := Number(observation["balance"])
	if !ok || !isFinite(balance) {
		return empty, nil
	}
	at := Now()
	if len(now) > 0 {
		at = now[0]
	}
	id := String(account["id"])
	binding := AccountBinding(account, config)
	limit := account["low_balance_threshold"]
	if limit == nil {
		limit = settings["threshold"]
	}
	threshold, _ := Number(limit)
	old, e := s.one("SELECT * FROM automation_low_balance WHERE account_id=? AND binding=?", id, binding)
	if e != nil {
		return nil, e
	}
	oldThreshold, _ := Number(old["threshold"])
	below := balance < threshold
	episode, notified := old["episode"], old["notified_at"]
	if old == nil || Int(old["below"]) == 0 || oldThreshold != threshold {
		episode = at
		notified = nil
	}
	unconfirmed := false
	if notified != nil {
		prefix := fmt.Sprintf("low:%s:%s:%s:", id, binding, eventTimestamp(episode))
		previous, e := s.one("SELECT state FROM automation_notifications WHERE kind='low_balance' AND substr(event_key,1,?)=? ORDER BY id DESC LIMIT 1", utf8.RuneCountInString(prefix), prefix)
		if e != nil {
			return nil, e
		}
		unconfirmed = previous["state"] == "pending" || previous["state"] == "unknown" || previous["state"] == "partial"
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.Begin()
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	claimed := []int64{}
	n, notifiedOK := Number(notified)
	if below && !unconfirmed && (!notifiedOK || at-n >= float64(Int(settings["cooldown_minutes"])*60)) {
		message := fmt.Sprintf("%s: 当前站内额度 $%.4f, 低于阈值 $%.4f. 请在 Status 查看余额.", String(account["name"]), balance, threshold)
		key := fmt.Sprintf("low:%s:%s:%s:%s", id, binding, eventTimestamp(episode), eventTimestamp(at))
		notification, e := claimTx(tx, key, "low_balance", "账户低余额提醒", message, id, runID)
		if e != nil {
			return nil, e
		}
		if notification > 0 {
			claimed = append(claimed, notification)
			notified = at
		}
	}
	b := 0
	if below {
		b = 1
	} else {
		episode = nil
		notified = nil
	}
	if _, e = tx.Exec("INSERT OR REPLACE INTO automation_low_balance VALUES (?,?,?,?,?,?)", id, binding, threshold, b, episode, notified); e != nil {
		return nil, e
	}
	return claimed, tx.Commit()
}
func (s *Store) AutomationSnapshot(config Document, now ...float64) (Document, error) {
	at := Now()
	if len(now) > 0 {
		at = now[0]
	}
	health := []any{}
	for _, v := range Array(config["accounts"]) {
		a := Object(v)
		rows, e := s.Query("SELECT * FROM automation_health WHERE account_id=? AND binding=?", a["id"], AccountBinding(a, config))
		if e != nil {
			return nil, e
		}
		for _, r := range rows {
			d := Document{}
			for _, k := range []string{"account_id", "scope", "state", "reason", "consecutive_failures"} {
				d[k] = r[k]
			}
			for _, k := range []string{"failure_since", "last_failure_at", "last_success_at", "recovered_at"} {
				d[k] = Stamp(r[k])
			}
			health = append(health, d)
		}
	}
	notifications := []any{}
	rows, e := s.Query("SELECT * FROM automation_notifications ORDER BY id DESC LIMIT 30")
	if e != nil {
		return nil, e
	}
	for _, r := range rows {
		d := Document{}
		for _, k := range []string{"id", "kind", "account_id", "state", "title"} {
			d[k] = r[k]
		}
		d["created_at"] = Stamp(r["created_at"])
		d["finished_at"] = Stamp(r["finished_at"])
		d["delivery"] = nil
		if raw := String(r["delivery"]); raw != "" {
			var delivery any
			if json.Unmarshal([]byte(raw), &delivery) == nil {
				d["delivery"] = delivery
			}
		}
		notifications = append(notifications, d)
	}
	last, e := s.one("SELECT event_key,state FROM automation_notifications WHERE kind='daily_summary' ORDER BY id DESC LIMIT 1")
	if e != nil {
		return nil, e
	}
	schedule, e := s.one("SELECT next_at FROM automation_scheduler WHERE id=1")
	if e != nil {
		return nil, e
	}
	var lastDay any
	if last != nil {
		lastDay = strings.TrimPrefix(String(last["event_key"]), "summary:")
	}
	return Document{"timezone": "Asia/Singapore", "day": Day(at), "health": health, "notifications": notifications, "daily_summary": Document{"last_day": lastDay, "last_state": last["state"], "next_at": Stamp(schedule["next_at"])}}, nil
}
func money(v any) string {
	n, ok := Number(v)
	if !ok {
		return "未知"
	}
	return fmt.Sprintf("$%.4f", n)
}
func (s *Store) BuildDailySummary(config Document, day string, now ...float64) (string, string, error) {
	at := Now()
	if len(now) > 0 {
		at = now[0]
	}
	current := Day(at)
	if day == "" {
		day = current
	}
	local, e := time.ParseInLocation("2006-01-02", day, StatisticsZone)
	if e != nil || day > current {
		return "", "", fmt.Errorf("Invalid summary day")
	}
	if day != current {
		at = float64(local.Add(24*time.Hour - time.Second).Unix())
	}
	snapshot, e := s.BalanceSnapshot(config, at)
	if e != nil {
		return "", "", e
	}
	active := map[string]bool{}
	for _, v := range Array(config["accounts"]) {
		a := Object(v)
		if Bool(a["enabled"]) {
			active[String(a["id"])] = true
		}
	}
	counts := map[string]int{"success": 0, "failed": 0, "skipped": 0}
	rows, e := s.Query("SELECT summary FROM runs WHERE kind='checkin' AND COALESCE(finished_at,started_at)>=? AND COALESCE(finished_at,started_at)<? AND state NOT IN ('running','stopping')", local.Unix(), local.AddDate(0, 0, 1).Unix())
	if e != nil {
		return "", "", e
	}
	for _, r := range rows {
		var d Document
		if json.Unmarshal([]byte(String(r["summary"])), &d) != nil {
			continue
		}
		for _, v := range Array(d["accounts"]) {
			a := Object(v)
			if !active[String(a["id"])] {
				continue
			}
			key := "failed"
			if a["outcome"] == "skipped" {
				key = "skipped"
			} else if Bool(a["success"]) {
				key = "success"
			}
			counts[key]++
		}
	}
	summary := Object(snapshot["summary"])
	if day != current {
		summary["balance"] = nil
		summary["balance_count"] = 0
		summary["fresh_count"] = 0
		for _, v := range Array(snapshot["history"]) {
			h := Object(v)
			if h["day"] == day {
				summary["balance"] = h["balance"]
				summary["balance_count"] = h["balance_count"]
			}
		}
	}
	partial := false
	for _, v := range Array(snapshot["accounts"]) {
		a := Object(v)
		if Bool(a["enabled"]) && Bool(a["income_partial"]) {
			partial = true
		}
	}
	part := ""
	if partial {
		part = ", 含部分采集时段"
	}
	lines := []string{fmt.Sprintf("日期: %s, UTC+8", day), fmt.Sprintf("总余额: %s. 已知 %d/%d, 新鲜 %d/%d.", money(summary["balance"]), Int(summary["balance_count"]), len(active), Int(summary["fresh_count"]), len(active)), fmt.Sprintf("今日新增: %s. 覆盖 %d/%d%s.", money(summary["today_income"]), Int(summary["income_count"]), len(active), part), fmt.Sprintf("采集期净变化: %s. 覆盖 %d/%d.", money(summary["today_net_change"]), Int(summary["net_change_count"]), len(active)), fmt.Sprintf("签到记录: 成功 %d, 失败或待处理 %d, 跳过 %d.", counts["success"], counts["failed"], counts["skipped"]), "站内额度统计, 未知或过期数据不代表余额为 0. 接收确认不代表设备送达."}
	if url := String(config["webui_url"]); url != "" {
		lines = append(lines, strings.TrimRight(url, "/")+"/status")
	}
	return "每日摘要 " + day, strings.Join(lines, "\n"), nil
}
