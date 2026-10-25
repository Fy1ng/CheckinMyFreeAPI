package app

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/checkin"
)

func (j *Jobs) balanceRetry(account, config Document) float64 {
	value, e := j.store.BalanceRetryAt(account, config)
	if e != nil {
		return float64(time.Now().Add(time.Hour).Unix())
	}
	return number(value)
}

func (j *Jobs) recordBalances(account, config, result Document, observations []Document, metricError Document, kind string) Document {
	if kind != "balance" && !yes(object(config["monitoring"])["enabled"]) {
		return nil
	}
	var metric Document
	for _, observation := range observations {
		ok, e := j.store.BalanceRecord(account, config, observation)
		metric = Document{"success": ok && e == nil, "outcome": "success", "reason": "balance_refreshed"}
		if e != nil || !ok {
			metric["outcome"] = "failed"
			metric["reason"] = "balance_storage_failed"
			if kind == "balance" {
				result["success"] = false
				result["outcome"] = "failed"
				result["reason"] = "balance_storage_failed"
			} else {
				result["balance_warning"] = "balance_storage_failed"
			}
		}
	}
	failure := metricError
	if failure == nil && kind == "balance" && !yes(result["success"]) {
		failure = result
	}
	if failure != nil {
		metric = failure
		_ = j.store.BalanceFailure(account, config, text(failure["outcome"]), text(failure["reason"]))
		if text(failure["outcome"]) == "rate_limited" {
			delay := failure["retry_after_seconds"]
			if delay == nil {
				delay = 3600
			}
			_ = j.store.BalanceRateLimit(account, config, delay)
		}
	}
	return metric
}

func (j *Jobs) recordAutomation(runID int64, account, config, result, balanceResult Document, kind string) []int64 {
	ids := []int64{}
	if kind == "checkin" {
		items, e := j.store.RecordHealth(account, config, "checkin", result, runID)
		if e != nil {
			result["automation_warning"] = "automation_state_unavailable"
		} else {
			ids = append(ids, items...)
		}
	}
	if kind == "balance" {
		balanceResult = result
	}
	if balanceResult != nil {
		items, e := j.store.RecordHealth(account, config, "balance", balanceResult, runID)
		if e == nil {
			ids = append(ids, items...)
		} else {
			result["automation_warning"] = "automation_state_unavailable"
		}
		if yes(balanceResult["success"]) {
			snapshot, e := j.store.BalanceSnapshot(config)
			if e == nil {
				for _, row := range list(snapshot["accounts"]) {
					if text(row["id"]) == text(account["id"]) {
						items, e = j.store.CheckLowBalance(account, config, row, runID)
						if e == nil {
							ids = append(ids, items...)
						}
						break
					}
				}
			}
		}
	}
	return ids
}

func (j *Jobs) deliverAutomation(ctx context.Context, config Document, ids []int64) []Document {
	groups := map[string][]Document{}
	order := []string{}
	for _, id := range ids {
		pending, e := j.store.PendingNotification(id)
		if e != nil || pending == nil {
			continue
		}
		title := text(pending["title"])
		if _, ok := groups[title]; !ok {
			order = append(order, title)
		}
		groups[title] = append(groups[title], pending)
	}
	results := []Document{}
	for _, title := range order {
		group := groups[title]
		messages := []string{}
		for _, p := range group {
			messages = append(messages, text(p["message"]))
		}
		content := strings.Join(messages, "\n\n")
		if len(group) > 1 {
			content = fmt.Sprintf("本次共 %d 个账户事件. 请在管理面板查看各账户详情.\n\n", len(group)) + content
		}
		delivery := checkin.Deliver(ctx, object(config["notifications"]), title, content)
		for _, p := range group {
			id := int64(number(p["id"]))
			_ = j.store.FinishNotification(id, delivery)
			results = append(results, Document{"id": id, "state": delivery["state"]})
		}
	}
	return results
}

func (j *Jobs) executeSummary(ctx context.Context, id int64, config Document) (Document, string, any) {
	day := dayAt(time.Now())
	title, message, e := j.store.BuildDailySummary(config, day)
	if e != nil {
		return nil, "failed", "日报数据无法读取"
	}
	claim, e := j.store.ClaimNotification("summary:"+day, "daily_summary", title, message, nil, id)
	if e != nil {
		return nil, "failed", "日报去重状态无法保存"
	}
	ids := []int64{}
	if claim != 0 {
		ids = append(ids, claim)
	}
	deliveries := j.deliverAutomation(ctx, config, ids)
	state := "already_recorded"
	success := claim == 0
	if len(deliveries) > 0 {
		state = text(deliveries[0]["state"])
		success = state == "accepted"
	}
	summary := Document{"accounts": []Document{}, "day": day, "notification_state": state, "notifications": deliveries, "total_count": 0, "success_count": 0}
	if claim != 0 {
		summary["total_count"] = 1
		if success {
			summary["success_count"] = 1
		}
	}
	if success {
		return summary, "succeeded", nil
	}
	return summary, "needs_attention", "日报通知未全部确认接收, 请查看自动化通知记录"
}

func (j *Jobs) BalanceSnapshot() (Document, error) {
	config, _, e := j.store.Load()
	if e != nil {
		return nil, e
	}
	snapshot, e := j.store.BalanceSnapshot(config)
	if e != nil {
		return nil, e
	}
	automation, e := j.store.AutomationSnapshot(config)
	if e != nil {
		return nil, e
	}
	for _, account := range list(snapshot["accounts"]) {
		health := Document{}
		for _, item := range list(automation["health"]) {
			if text(item["account_id"]) == text(account["id"]) {
				health[text(item["scope"])] = item
			}
		}
		account["health"] = health
	}
	var at sql.NullFloat64
	e = j.store.DB.QueryRow("SELECT next_at FROM balance_scheduler WHERE id=1").Scan(&at)
	if e != nil {
		return nil, e
	}
	var next any
	if at.Valid {
		next = nullableTime(at.Float64)
	}
	snapshot["refreshing"] = j.Running()
	snapshot["next_refresh_at"] = next
	return snapshot, nil
}
