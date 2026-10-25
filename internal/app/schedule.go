package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/checkin"
)

func signature(v any) string { raw, _ := json.Marshal(v); return string(raw) }
func enabledAccounts(config Document) bool {
	for _, account := range list(config["accounts"]) {
		if yes(account["enabled"]) {
			return true
		}
	}
	return false
}

func nextSchedule(settings Document, now time.Time) any {
	if !yes(settings["enabled"]) {
		return nil
	}
	if text(settings["mode"]) == "cron" {
		cron, e := checkin.ParseCron(text(settings["cron"]))
		if e != nil {
			return nil
		}
		next, e := cron.NextAfter(now)
		if e != nil {
			return nil
		}
		return float64(next.Unix())
	}
	return float64(now.Unix()) + number(settings["interval_minutes"])*60
}
func nextDaily(settings Document, now time.Time) any {
	if !yes(settings["enabled"]) {
		return nil
	}
	next, e := checkin.NextDailyTime(text(settings["time"]), now)
	if e != nil {
		return nil
	}
	return float64(next.Unix())
}

func (j *Jobs) reschedule(config Document, initial bool) error {
	now := time.Now()
	schedule := object(config["schedule"])
	monitoring := object(config["monitoring"])
	summary := object(object(config["automation"])["daily_summary"])
	for _, entry := range []struct {
		table   string
		sig     string
		old     *string
		next    any
		enabled bool
	}{
		{"scheduler", signature(schedule), &j.checkinSignature, nextSchedule(schedule, now), yes(schedule["enabled"])},
		{"balance_scheduler", signature([]any{monitoring, enabledAccounts(config)}), &j.balanceSignature, func() any {
			if yes(monitoring["enabled"]) && enabledAccounts(config) {
				return float64(now.Unix()) + number(monitoring["interval_minutes"])*60
			}
			return nil
		}(), yes(monitoring["enabled"]) && enabledAccounts(config)},
		{"automation_scheduler", signature(summary), &j.summarySignature, nextDaily(summary, now), yes(summary["enabled"])},
	} {
		var saved sql.NullFloat64
		if e := j.store.DB.QueryRow("SELECT next_at FROM " + entry.table + " WHERE id=1").Scan(&saved); e != nil {
			return e
		}
		change := (!initial && *entry.old != entry.sig) || !entry.enabled || !saved.Valid || (initial && saved.Float64 <= float64(now.Unix()))
		if change {
			if _, e := j.store.DB.Exec("UPDATE "+entry.table+" SET next_at=? WHERE id=1", entry.next); e != nil {
				return e
			}
		}
		*entry.old = entry.sig
	}
	return nil
}

func (j *Jobs) Scheduler(ctx context.Context, backup func(int) error) {
	backupSignature := ""
	_, _, _ = j.takeDue(true, &backupSignature)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-j.changed:
		case <-ticker.C:
		}
		kind, revision, e := j.takeDue(false, &backupSignature)
		if e != nil || kind == "" {
			continue
		}
		if kind == "backup" {
			if backup != nil {
				_ = backup(revision)
			}
		} else {
			_, _ = j.Start(revision, kind, "scheduled", "")
		}
	}
}

// Schedule reads and advances share the job lock with restore and task starts.
func (j *Jobs) takeDue(initial bool, backupSignature *string) (string, int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	config, revision, e := j.store.Load()
	if e != nil {
		return "", 0, e
	}
	if e = j.reschedule(config, initial); e != nil {
		return "", 0, e
	}
	settings := object(config["backups"])
	sig := signature(settings)
	var next sql.NullFloat64
	if e = j.store.DB.QueryRow("SELECT next_at FROM backup_scheduler WHERE id=1").Scan(&next); e != nil {
		return "", 0, e
	}
	enabled := yes(settings["enabled"]) && text(settings["password"]) != ""
	if !enabled || !next.Valid || (*backupSignature != "" && sig != *backupSignature) || (initial && next.Float64 <= float64(time.Now().Unix())) {
		var following any
		if enabled {
			following = nextDaily(settings, time.Now())
		}
		if _, e = j.store.DB.Exec("UPDATE backup_scheduler SET next_at=? WHERE id=1", following); e != nil {
			return "", 0, e
		}
	}
	*backupSignature = sig
	if initial || j.active != 0 {
		return "", revision, nil
	}
	for _, entry := range []struct{ table, kind string }{{"scheduler", "checkin"}, {"balance_scheduler", "balance"}, {"automation_scheduler", "summary"}, {"backup_scheduler", "backup"}} {
		var next sql.NullFloat64
		if e = j.store.DB.QueryRow("SELECT next_at FROM " + entry.table + " WHERE id=1").Scan(&next); e != nil {
			return "", 0, e
		}
		if !next.Valid || next.Float64 > float64(time.Now().Unix()) {
			continue
		}
		var following any
		switch entry.kind {
		case "checkin":
			following = nextSchedule(object(config["schedule"]), time.Now())
		case "balance":
			following = float64(time.Now().Unix()) + number(object(config["monitoring"])["interval_minutes"])*60
		case "summary":
			following = nextDaily(object(object(config["automation"])["daily_summary"]), time.Now())
		case "backup":
			following = nextDaily(settings, time.Now())
		}
		if _, e = j.store.DB.Exec("UPDATE "+entry.table+" SET next_at=? WHERE id=1", following); e != nil {
			return "", 0, e
		}
		return entry.kind, revision, nil
	}
	return "", revision, nil
}

// Startup is called once per process. Ordinary interval/cron tasks keep their schedules.
func (j *Jobs) Startup(ctx context.Context, settings *RuntimeConfig, ready func() bool) {
	initial := settings.Get()
	if !initial.RunOnStartup {
		return
	}
	// A new/unconfigured instance must not start a task merely because the user
	// saves the first account while the startup delay is still counting down.
	config, _, err := j.store.Load()
	if err != nil || !enabledAccounts(config) || !ready() || ctx.Err() != nil {
		return
	}
	timer := time.NewTimer(time.Duration(initial.StartupDelaySeconds) * time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return
	case <-timer.C:
	}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		if !settings.Get().RunOnStartup {
			return
		}
		if ready() && !j.Running() {
			config, revision, e := j.store.Load()
			if e == nil && enabledAccounts(config) {
				_, e = j.Start(revision, "checkin", "startup", "")
				if e == nil {
					return
				}
			} else if e == nil {
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
