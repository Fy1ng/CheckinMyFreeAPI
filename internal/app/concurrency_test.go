package app

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/checkin"
)

func TestRestoreDrainsReadersBeforeTakingJobLock(t *testing.T) {
	a, _ := fixture(t, true)
	cookies, csrf := login(t, a)
	_, revision, e := a.Store.Load()
	if e != nil {
		t.Fatal(e)
	}
	a.httpGate.RLock()
	released := false
	release := func() {
		if !released {
			a.httpGate.RUnlock()
			released = true
		}
	}
	defer release()
	finished := make(chan int, 1)
	go func() {
		code, _, _ := request(t, a, "POST", "/api/backups/restore", Document{"revision": revision, "ticket": "missing-test-ticket", "admin_password": testPassword}, cookies, csrf)
		finished <- code
	}()
	deadline := time.Now().Add(time.Second)
	for !a.backupBusy.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !a.backupBusy.Load() {
		release()
		t.Fatal("restore not started")
	}
	status := make(chan bool, 1)
	go func() { status <- a.Jobs.Running() }()
	select {
	case <-status:
	case <-time.After(time.Second):
		release()
		<-finished
		t.Fatal("restore held job lock while waiting for an HTTP reader")
	}
	release()
	select {
	case code := <-finished:
		if code != 400 {
			t.Fatal(code)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("restore did not finish")
	}
}

func TestStartupDedupUsesAccountCompletionDayAcrossMidnight(t *testing.T) {
	a, _ := fixture(t, true)
	config, revision := accountConfig(t, a)
	account := list(config["accounts"])[0]
	now := time.Now().In(zone)
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, zone)
	result := success(account)
	result["binding"] = checkin.AccountBinding(account, config)
	result["completed_at"] = stamp(midnight.Add(time.Second))
	raw, _ := json.Marshal(Document{"accounts": []Document{result}})
	row, e := a.Store.DB.Exec("INSERT INTO runs(state,started_at,finished_at,summary,revision,kind) VALUES('succeeded',?,?,?,?, 'checkin')", midnight.Add(-5*time.Second).Unix(), midnight.Add(5*time.Second).Unix(), string(raw), revision)
	if e != nil {
		t.Fatal(e)
	}
	id, _ := row.LastInsertId()
	checked, e := a.Jobs.alreadySucceeded(account, config, revision)
	if e != nil || !checked {
		t.Fatal("cross-midnight success would be duplicated", checked, e)
	}
	result["completed_at"] = stamp(midnight.Add(-time.Second))
	raw, _ = json.Marshal(Document{"accounts": []Document{result}})
	_, e = a.Store.DB.Exec("UPDATE runs SET summary=? WHERE id=?", string(raw), id)
	if e != nil {
		t.Fatal(e)
	}
	checked, e = a.Jobs.alreadySucceeded(account, config, revision)
	if e != nil || checked {
		t.Fatal("previous-day success skipped today's account", checked, e)
	}
}
