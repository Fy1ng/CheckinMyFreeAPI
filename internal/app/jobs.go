package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/checkin"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/storage"
)

type Jobs struct {
	mu                                                   sync.Mutex
	store                                                *storage.Store
	active                                               int64
	cancel                                               context.CancelFunc
	done                                                 chan struct{}
	root                                                 context.Context
	changed                                              chan struct{}
	executeAccount                                       func(context.Context, Document, Document, string, func(Document)) (Document, []Document, Document)
	startupNetwork                                       func(context.Context, Document, Document) bool
	checkinSignature, balanceSignature, summarySignature string
}

func NewJobs(ctx context.Context, s *storage.Store) (*Jobs, error) {
	j := &Jobs{store: s, root: ctx, changed: make(chan struct{}, 1), startupNetwork: waitStartupNetwork}
	j.executeAccount = func(ctx context.Context, account, config Document, kind string, report func(Document)) (Document, []Document, Document) {
		runtime := checkin.New(config, s)
		var result Document
		if kind == "balance" {
			result = runtime.Balance(ctx, account, report)
		} else {
			result = runtime.Execute(ctx, account, report)
		}
		return result, runtime.BalanceObservations, runtime.BalanceError
	}
	_, e := s.DB.Exec(`CREATE TABLE IF NOT EXISTS runs(id INTEGER PRIMARY KEY,state TEXT NOT NULL,started_at REAL NOT NULL,finished_at REAL,error TEXT,summary TEXT,revision INTEGER NOT NULL,kind TEXT NOT NULL DEFAULT 'checkin',identity TEXT);
CREATE TABLE IF NOT EXISTS scheduler(id INTEGER PRIMARY KEY CHECK(id=1),next_at REAL);
INSERT OR IGNORE INTO scheduler VALUES(1,NULL);
CREATE TABLE IF NOT EXISTS balance_scheduler(id INTEGER PRIMARY KEY CHECK(id=1),next_at REAL);
INSERT OR IGNORE INTO balance_scheduler VALUES(1,NULL);
CREATE TABLE IF NOT EXISTS backup_scheduler(id INTEGER PRIMARY KEY CHECK(id=1),next_at REAL,last_attempt_at REAL,last_state TEXT,error TEXT);
INSERT OR IGNORE INTO backup_scheduler VALUES(1,NULL,NULL,NULL,NULL);`)
	if e != nil {
		return nil, e
	}
	// Python versions predating balance collection have no kind/identity columns.
	cols, e := s.DB.Query("PRAGMA table_info(runs)")
	if e != nil {
		return nil, e
	}
	names := map[string]bool{}
	for cols.Next() {
		var cid, notnull, pk int
		var name, typ string
		var value any
		if e = cols.Scan(&cid, &name, &typ, &notnull, &value, &pk); e != nil {
			cols.Close()
			return nil, e
		}
		names[name] = true
	}
	cols.Close()
	if !names["kind"] {
		if _, e = s.DB.Exec("ALTER TABLE runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'checkin'"); e != nil {
			return nil, e
		}
	}
	if !names["identity"] {
		if _, e = s.DB.Exec("ALTER TABLE runs ADD COLUMN identity TEXT"); e != nil {
			return nil, e
		}
	}
	config, _, e := s.Load()
	if e != nil {
		return nil, e
	}
	rows, e := s.DB.Query("SELECT summary FROM runs WHERE state IN ('running','awaiting_login','stopping') AND kind='checkin'")
	if e != nil {
		return nil, e
	}
	summaries := []string{}
	for rows.Next() {
		var raw sql.NullString
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return nil, e
		}
		if raw.Valid {
			summaries = append(summaries, raw.String)
		}
	}
	rows.Close()
	for _, raw := range summaries {
		var summary Document
		if json.Unmarshal([]byte(raw), &summary) != nil {
			continue
		}
		active := object(object(summary["progress"])["active_account"])
		id := text(active["id"])
		for _, a := range list(config["accounts"]) {
			if text(a["id"]) == id {
				_, e = s.DB.Exec("INSERT OR REPLACE INTO account_attention VALUES(?,?,?,?,NULL,?)", id, checkin.AccountBinding(a, config), "uncertain", "REQUEST_CANCELLED_RESULT_UNKNOWN", float64(time.Now().UnixNano())/1e9)
				if e != nil {
					return nil, e
				}
			}
		}
	}
	_, e = s.DB.Exec("UPDATE runs SET state='interrupted',finished_at=?,error='服务重启, 请核对任务结果后再运行' WHERE state IN ('running','awaiting_login','stopping')", float64(time.Now().UnixNano())/1e9)
	if e != nil {
		return nil, e
	}
	return j, nil
}

func (j *Jobs) Running() bool { j.mu.Lock(); defer j.mu.Unlock(); return j.active != 0 }
func (j *Jobs) Notify() {
	select {
	case j.changed <- struct{}{}:
	default:
	}
}
func (j *Jobs) Stop() bool {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.active == 0 {
		return false
	}
	_, _ = j.store.DB.Exec("UPDATE runs SET state='stopping' WHERE id=?", j.active)
	j.cancel()
	return true
}
func (j *Jobs) Close() {
	j.mu.Lock()
	if j.active == 0 {
		j.mu.Unlock()
		return
	}
	j.cancel()
	done := j.done
	j.mu.Unlock()
	<-done
}

func (j *Jobs) History() ([]Document, error) {
	rows, e := j.store.DB.Query("SELECT id,state,started_at,finished_at,error,summary,revision,kind,identity FROM runs ORDER BY id DESC LIMIT 50")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Document{}
	for rows.Next() {
		var id int64
		var state, kind string
		var started float64
		var finished sql.NullFloat64
		var errText, summary, identity sql.NullString
		var revision int
		if e = rows.Scan(&id, &state, &started, &finished, &errText, &summary, &revision, &kind, &identity); e != nil {
			return nil, e
		}
		var parsed any
		if summary.Valid {
			_ = json.Unmarshal([]byte(summary.String), &parsed)
		}
		var end, errorValue, identityValue any
		if finished.Valid {
			end = nullableTime(finished.Float64)
		}
		if errText.Valid {
			errorValue = errText.String
		}
		if identity.Valid {
			identityValue = identity.String
		}
		out = append(out, Document{"id": id, "state": state, "kind": kind, "revision": revision, "started_at": nullableTime(started), "finished_at": end, "error": errorValue, "summary": parsed, "identity": identityValue})
	}
	return out, rows.Err()
}

func (j *Jobs) attention(id, binding string) (Document, error) {
	var outcome, reason, stored string
	var retry sql.NullFloat64
	var updated float64
	e := j.store.DB.QueryRow("SELECT outcome,reason,retry_at,updated_at,binding FROM account_attention WHERE account_id=?", id).Scan(&outcome, &reason, &retry, &updated, &stored)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if stored != binding && outcome != "uncertain" {
		return nil, nil
	}
	var at any
	if retry.Valid {
		at = retry.Float64
	}
	return Document{"outcome": outcome, "reason": reason, "retry_at": at, "updated_at": updated}, nil
}
func (j *Jobs) recordAttention(account, config, result Document) error {
	outcome := text(result["outcome"])
	id := text(account["id"])
	if outcome != "needs_credentials" && outcome != "blocked" && outcome != "rate_limited" && outcome != "uncertain" {
		if yes(result["success"]) {
			_, e := j.store.DB.Exec("DELETE FROM account_attention WHERE account_id=?", id)
			return e
		}
		return nil
	}
	var retry any
	if outcome == "rate_limited" {
		delay := number(result["retry_after_seconds"])
		if delay < 1 {
			delay = 3600
		}
		if delay > 86400 {
			delay = 86400
		}
		retry = float64(time.Now().UnixNano())/1e9 + delay
	}
	_, e := j.store.DB.Exec("INSERT OR REPLACE INTO account_attention VALUES(?,?,?,?,?,?)", id, checkin.AccountBinding(account, config), outcome, text(result["reason"]), retry, float64(time.Now().UnixNano())/1e9)
	return e
}
func (j *Jobs) Status() (Document, error) {
	history, e := j.History()
	if e != nil {
		return nil, e
	}
	var run any
	if len(history) > 0 {
		run = history[0]
	}
	config, _, e := j.store.Load()
	if e != nil {
		return nil, e
	}
	attention := Document{}
	for _, a := range list(config["accounts"]) {
		pending, e := j.attention(text(a["id"]), checkin.AccountBinding(a, config))
		if e != nil {
			return nil, e
		}
		if pending != nil {
			attention[text(a["id"])] = pending
		}
	}
	var next sql.NullFloat64
	if e = j.store.DB.QueryRow("SELECT next_at FROM scheduler WHERE id=1").Scan(&next); e != nil {
		return nil, e
	}
	var nextAt any
	if next.Valid {
		nextAt = nullableTime(next.Float64)
	}
	return Document{"running": j.Running(), "run": run, "attention": attention, "next_run_at": nextAt}, nil
}

func (j *Jobs) Start(revision int, kind, trigger, accountID string) (Document, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.root.Err() != nil {
		return nil, errors.New("服务正在退出")
	}
	if j.active != 0 {
		return nil, errors.New("已有任务运行, 请等待完成或先停止")
	}
	if kind != "checkin" && kind != "balance" && kind != "summary" {
		return nil, errors.New("任务类型无效")
	}
	if trigger != "manual" && trigger != "scheduled" && trigger != "startup" {
		return nil, errors.New("任务来源无效")
	}
	config, current, e := j.store.Load()
	if e != nil {
		return nil, e
	}
	if current != revision {
		return nil, errors.New("配置已更新, 请重新读取后运行")
	}
	accounts := list(config["accounts"])
	if accountID != "" {
		selected := []any{}
		for _, a := range accounts {
			if text(a["id"]) == accountID && yes(a["enabled"]) {
				selected = append(selected, a)
			}
		}
		if len(selected) != 1 || trigger != "manual" || kind == "summary" {
			return nil, errors.New("请选择已保存且已启用的账号")
		}
		config["accounts"] = selected
		accounts = list(selected)
	}
	total := 0
	for _, a := range accounts {
		if yes(a["enabled"]) {
			total++
		}
	}
	if total == 0 && kind != "summary" {
		return nil, errors.New("请先保存至少一个已启用账号")
	}
	summary := Document{"account_id": nil, "accounts": []any{}, "progress": Document{"total": total, "completed": 0, "active_account": nil}, "trigger": trigger}
	if accountID != "" {
		summary["account_id"] = accountID
	}
	raw, _ := json.Marshal(summary)
	now := float64(time.Now().UnixNano()) / 1e9
	result, e := j.store.DB.Exec("INSERT INTO runs(state,started_at,revision,kind,summary) VALUES('running',?,?,?,?)", now, revision, kind, string(raw))
	if e != nil {
		return nil, e
	}
	id, e := result.LastInsertId()
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(j.root)
	j.active = id
	j.cancel = cancel
	j.done = make(chan struct{})
	go j.execute(ctx, id, revision, config, kind, trigger, accountID, total)
	return Document{"id": id, "state": "running", "started_at": nullableTime(now), "finished_at": nil, "error": nil, "summary": summary, "revision": revision, "kind": kind, "identity": nil}, nil
}

func (j *Jobs) alreadySucceeded(account, config Document, revision int) (bool, error) {
	now := time.Now().In(zone)
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, zone)
	rows, e := j.store.DB.Query("SELECT summary,revision,started_at,finished_at FROM runs WHERE (started_at>=? OR finished_at>=?) AND kind='checkin' AND summary IS NOT NULL ORDER BY id DESC", midnight.Unix(), midnight.Unix())
	if e != nil {
		return false, e
	}
	defer rows.Close()
	binding := checkin.AccountBinding(account, config)
	for rows.Next() {
		var raw string
		var savedRevision int
		var started float64
		var finished sql.NullFloat64
		if e = rows.Scan(&raw, &savedRevision, &started, &finished); e != nil {
			return false, e
		}
		var summary Document
		if json.Unmarshal([]byte(raw), &summary) != nil {
			continue
		}
		for _, r := range list(summary["accounts"]) {
			if text(r["id"]) == text(account["id"]) && yes(r["success"]) && text(r["reason"]) != "startup_already_checked_in" {
				when := time.Unix(0, int64(started*1e9))
				if finished.Valid {
					when = time.Unix(0, int64(finished.Float64*1e9))
				}
				if completed, e := time.Parse(time.RFC3339Nano, text(r["completed_at"])); e == nil {
					when = completed
				} else {
					steps := list(r["steps"])
					for i := len(steps) - 1; i >= 0; i-- {
						if at, e := time.Parse(time.RFC3339Nano, text(steps[i]["at"])); e == nil {
							when = at
							break
						}
					}
				}
				if dayAt(when) != dayAt(now) {
					continue
				}
				savedBinding := text(r["binding"])
				if savedBinding == binding || (savedBinding == "" && savedRevision == revision) {
					return true, nil
				}
			}
		}
	}
	return false, rows.Err()
}

func waitStartupNetwork(ctx context.Context, account, config Document) bool {
	proxyURL, err := checkin.ResolveProxy(account, config)
	if err != nil {
		return false
	}
	host := "anyrouter.top:443"
	if text(account["provider"]) == "agentrouter" {
		host = "agentrouter.org:443"
	}
	if proxyURL != "" {
		p, e := url.Parse(proxyURL)
		if e != nil {
			return false
		}
		host = p.Host
		if p.Port() == "" {
			port := "1080"
			if p.Scheme == "http" {
				port = "80"
			}
			if p.Scheme == "https" {
				port = "443"
			}
			host = net.JoinHostPort(p.Hostname(), port)
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(time.Duration(attempt*5) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return false
			case <-timer.C:
			}
		}
		conn, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", host)
		if e == nil {
			conn.Close()
			return true
		}
		if ctx.Err() != nil {
			return false
		}
	}
	return false
}

func (j *Jobs) execute(ctx context.Context, id int64, revision int, config Document, kind, trigger, accountID string, total int) {
	results := []Document{}
	state := "failed"
	var taskError any = "任务未正常完成, 请查看执行记录"
	var active, activeAccount Document
	notificationIDs := []int64{}
	summaryExtras := Document{}
	summary := func() Document {
		completed, success := 0, 0
		for _, r := range results {
			if text(r["reason"]) != "ACCOUNT_DISABLED" {
				completed++
			}
			if yes(r["success"]) {
				success++
			}
		}
		var a any
		if active != nil {
			a = active
		}
		var selected any
		if accountID != "" {
			selected = accountID
		}
		s := Document{"accounts": results, "account_id": selected, "success_count": success, "total_count": total, "trigger": trigger, "progress": Document{"total": total, "completed": completed, "active_account": a}}
		for k, v := range summaryExtras {
			s[k] = v
		}
		return s
	}
	publish := func() {
		raw, _ := json.Marshal(summary())
		_, _ = j.store.DB.Exec("UPDATE runs SET summary=? WHERE id=?", string(raw), id)
	}
	defer func() {
		if recover() != nil {
			state = "failed"
			taskError = "执行器出现异常, 请核对任务结果"
			if activeAccount != nil && kind == "checkin" {
				_ = j.recordAttention(activeAccount, config, Document{"outcome": "uncertain", "reason": "HTTP_EXECUTION_FAILED_RESULT_UNKNOWN"})
			}
		}
		if ctx.Err() != nil {
			state = "cancelled"
			taskError = "任务已停止, 请核对执行记录"
			if activeAccount != nil && kind == "checkin" {
				_ = j.recordAttention(activeAccount, config, Document{"outcome": "uncertain", "reason": "REQUEST_CANCELLED_RESULT_UNKNOWN"})
			}
		}
		active = nil
		_ = j.store.InterruptPending(id)
		raw, _ := json.Marshal(summary())
		_, _ = j.store.DB.Exec("UPDATE runs SET state=?,finished_at=?,error=?,summary=? WHERE id=?", state, float64(time.Now().UnixNano())/1e9, taskError, string(raw), id)
		j.mu.Lock()
		j.active = 0
		j.cancel = nil
		close(j.done)
		j.mu.Unlock()
		j.Notify()
	}()
	if kind == "summary" {
		summaryExtras, state, taskError = j.executeSummary(ctx, id, config)
		return
	}
	for _, account := range list(config["accounts"]) {
		if ctx.Err() != nil {
			return
		}
		base := Document{"id": account["id"], "name": account["name"], "provider": account["provider"], "binding": checkin.AccountBinding(account, config)}
		if !yes(account["enabled"]) {
			base["success"] = false
			base["outcome"] = "skipped"
			base["reason"] = "ACCOUNT_DISABLED"
			results = append(results, base)
			publish()
			continue
		}
		pending, e := j.attention(text(account["id"]), text(base["binding"]))
		if e != nil {
			taskError = "账号暂停状态无法读取, 已停止任务"
			return
		}
		limited := text(pending["outcome"]) == "rate_limited" && number(pending["retry_at"]) > float64(time.Now().Unix())
		paused := pending != nil && ((kind == "checkin" && text(pending["outcome"]) == "uncertain") || (trigger != "manual" && text(pending["outcome"]) != "rate_limited" && text(pending["outcome"]) != "uncertain"))
		balanceRetry := j.balanceRetry(account, config)
		if balanceRetry > float64(time.Now().Unix()) {
			limited = true
			pending = Document{"outcome": "rate_limited", "reason": "rate_limited", "retry_at": balanceRetry}
		}
		if limited || paused {
			base["success"] = false
			base["outcome"] = "skipped"
			base["reason"] = "ACCOUNT_PAUSED"
			base["pending_outcome"] = pending["outcome"]
			base["pending_reason"] = pending["reason"]
			if limited {
				base["retry_after_seconds"] = max(1, int(number(pending["retry_at"])-float64(time.Now().Unix())))
			}
			results = append(results, base)
			publish()
			continue
		}
		checked := false
		if trigger == "startup" {
			checked, e = j.alreadySucceeded(account, config, revision)
			if e != nil {
				base["success"] = false
				base["outcome"] = "failed"
				base["reason"] = "startup_history_unavailable"
				results = append(results, base)
				publish()
				continue
			}
		}
		if checked {
			base["success"] = true
			base["outcome"] = "already_checked_in"
			base["reason"] = "startup_already_checked_in"
			results = append(results, base)
			publish()
			continue
		}
		active = clone(base)
		active["stage"] = "prepare"
		publish()
		if trigger == "startup" && !j.startupNetwork(ctx, account, config) {
			base["success"] = false
			base["outcome"] = "failed"
			base["reason"] = "startup_network_unavailable"
			results = append(results, base)
			active = nil
			publish()
			continue
		}
		activeAccount = account
		report := func(event Document) {
			active = clone(base)
			for _, k := range []string{"stage", "state", "at", "step", "method", "path", "http_status", "timeout_seconds", "attempt", "max_attempts", "acw_challenges", "error_type"} {
				if v, ok := event[k]; ok {
					active[k] = v
				}
			}
			publish()
		}
		result, observations, metricError := j.executeAccount(ctx, account, config, kind, report)
		result["completed_at"] = stamp(time.Now())
		result["binding"] = base["binding"]
		if kind == "checkin" {
			if e = j.recordAttention(account, config, result); e != nil {
				result["attention_warning"] = "attention_storage_failed"
			}
		}
		activeAccount = nil
		if ctx.Err() != nil {
			results = append(results, result)
			publish()
			return
		}
		balanceResult := j.recordBalances(account, config, result, observations, metricError, kind)
		notificationIDs = append(notificationIDs, j.recordAutomation(id, account, config, result, balanceResult, kind)...)
		results = append(results, result)
		active = nil
		activeAccount = nil
		publish()
	}
	j.deliverAutomation(ctx, config, notificationIDs)
	all := len(results) > 0
	hasUncertain, needsAttention := false, false
	for _, r := range results {
		if text(r["reason"]) == "ACCOUNT_DISABLED" {
			continue
		}
		outcome := text(r["outcome"])
		if text(r["pending_outcome"]) != "" {
			outcome = text(r["pending_outcome"])
		}
		if outcome != "success" && outcome != "already_checked_in" {
			all = false
		}
		if outcome == "uncertain" {
			hasUncertain = true
		}
		if outcome == "needs_credentials" || outcome == "blocked" || outcome == "rate_limited" {
			needsAttention = true
		}
	}
	if all {
		state = "succeeded"
		taskError = nil
	} else if hasUncertain {
		state = "uncertain"
		taskError = "有请求结果不确定, 请核对后解除暂停"
	} else if needsAttention {
		state = "needs_attention"
		taskError = "请查看账号结果并更新凭据或人工处理"
	}
	if kind == "checkin" {
		j.notifyResult(ctx, config, results, accountID, total)
	}
}

func (j *Jobs) notifyResult(ctx context.Context, config Document, results []Document, accountID string, total int) {
	clean := []Document{}
	success := 0
	for _, r := range results {
		v := clone(r)
		for _, key := range []string{"steps", "diagnostic", "retry_after_seconds", "binding", "completed_at"} {
			delete(v, key)
		}
		if text(v["pending_outcome"]) != "" {
			v["outcome"] = v["pending_outcome"]
			v["reason"] = v["pending_reason"]
		}
		delete(v, "pending_outcome")
		delete(v, "pending_reason")
		clean = append(clean, v)
		if yes(r["success"]) {
			success++
		}
	}
	raw, _ := json.Marshal(clean)
	sum := sha256.Sum256(raw)
	fingerprint := hex.EncodeToString(sum[:])
	scope := "result:" + accountID
	scopeHash := sha256.Sum256([]byte(scope))
	path := filepath.Join(j.store.DataDir, "go-http-result-"+hex.EncodeToString(scopeHash[:8])+".txt")
	if platform.PrivateFile(path) != nil {
		return
	}
	old, _ := os.ReadFile(path)
	if string(old) == fingerprint {
		return
	}
	lines := []string{fmt.Sprintf("成功 %d/%d. 请在 WebUI 查看执行记录.", success, total)}
	for _, r := range results {
		if !yes(r["success"]) && text(r["reason"]) != "ACCOUNT_DISABLED" {
			name := text(r["name"])
			if name == "" {
				name = text(r["id"])
			}
			lines = append(lines, name+": "+text(r["reason"]))
			if address := text(config["webui_url"]); address != "" {
				lines = append(lines, strings.TrimRight(address, "/")+"/?account="+url.QueryEscape(text(r["id"])))
			}
		}
	}
	delivery := checkin.Deliver(ctx, object(config["notifications"]), "签到执行结果", strings.Join(lines, "\n"))
	if text(delivery["state"]) == "accepted" || text(delivery["state"]) == "no_channels" {
		_ = os.WriteFile(path, []byte(fingerprint), 0600)
	}
}
