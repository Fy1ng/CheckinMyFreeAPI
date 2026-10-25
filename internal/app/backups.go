package app

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/auth"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/backup"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/storage"
)

func (a *App) backupStatus(w http.ResponseWriter, r *http.Request) error {
	if a.backupBusy.Load() {
		return busy("备份操作正在处理中, 请稍后重新读取")
	}
	var next, attempt sql.NullFloat64
	var state, errText sql.NullString
	e := a.Store.DB.QueryRow("SELECT next_at,last_attempt_at,last_state,error FROM backup_scheduler WHERE id=1").Scan(&next, &attempt, &state, &errText)
	if e != nil {
		return errors.New("备份状态无法读取")
	}
	files, e := a.Backups.List()
	if e != nil {
		return errors.New("备份列表无法读取")
	}
	var n, t, s, msg any
	if next.Valid {
		n = nullableTime(next.Float64)
	}
	if attempt.Valid {
		t = nullableTime(attempt.Float64)
	}
	if state.Valid {
		s = state.String
	}
	if errText.Valid {
		msg = errText.String
	}
	writeJSON(w, 200, Document{"busy": false, "next_at": n, "last_attempt_at": t, "last_state": s, "error": msg, "backups": files})
	return nil
}

func (a *App) createBackup(revision int) (Document, error) {
	if !a.operation.TryLock() {
		return nil, busy("已有备份操作正在处理")
	}
	defer a.operation.Unlock()
	a.Jobs.mu.Lock()
	defer a.Jobs.mu.Unlock()
	if a.Jobs.active != 0 {
		return nil, busy("请等待当前任务结束后再备份")
	}
	a.backupBusy.Store(true)
	defer a.backupBusy.Store(false)
	config, current, e := a.Store.Load()
	if e != nil {
		return nil, errors.New("配置无法读取")
	}
	if revision != current {
		return nil, storage.ErrConflict
	}
	settings := object(config["backups"])
	password := text(settings["password"])
	if password == "" {
		return nil, bad("请先设置并保存备份恢复密码")
	}
	_, e = a.Store.DB.Exec("UPDATE backup_scheduler SET last_attempt_at=?,last_state='running',error=NULL WHERE id=1", float64(time.Now().UnixNano())/1e9)
	if e != nil {
		return nil, errors.New("备份状态无法保存")
	}
	result, e := a.Backups.Create(password, int(number(settings["retain_count"])))
	if e != nil {
		_, _ = a.Store.DB.Exec("UPDATE backup_scheduler SET last_state='failed',error='backup_creation_failed' WHERE id=1")
		return nil, errors.New("备份创建失败, 请检查数据目录和磁盘空间")
	}
	_, e = a.Store.DB.Exec("UPDATE backup_scheduler SET last_state='succeeded',error=NULL WHERE id=1")
	if e != nil {
		return nil, errors.New("备份已创建, 请重新读取确认")
	}
	return result, nil
}
func (a *App) backupCreate(w http.ResponseWriter, r *http.Request) error {
	_, revision, e := revisionBody(r)
	if e != nil {
		return e
	}
	result, e := a.createBackup(revision)
	if e != nil {
		return e
	}
	writeJSON(w, 201, Document{"backup": result})
	return nil
}
func (a *App) backupRead(w http.ResponseWriter, r *http.Request) error {
	if a.backupBusy.Load() {
		return busy("请等待备份操作结束")
	}
	path, e := a.Backups.Read(r.PathValue("backup_id"))
	if e != nil {
		return &auth.HTTPError{Status: 404, Message: "备份文件不存在"}
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	name := r.PathValue("backup_id")
	if !strings.HasSuffix(name, ".nab") {
		name += ".nab"
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	http.ServeFile(w, r, path)
	return nil
}
func (a *App) sessionBinding(r *http.Request) string {
	a.mu.RLock()
	s := a.security
	a.mu.RUnlock()
	session := s.Session(r)
	if session == nil {
		return ""
	}
	hash := sha256.Sum256([]byte(session.Origin + "\x00" + session.CSRF))
	return hex.EncodeToString(hash[:])
}

func (a *App) backupPreview(w http.ResponseWriter, r *http.Request) error {
	if !a.operation.TryLock() {
		return busy("已有备份操作正在处理")
	}
	defer a.operation.Unlock()
	a.Jobs.mu.Lock()
	defer a.Jobs.mu.Unlock()
	if a.Jobs.active != 0 {
		return busy("请等待当前任务结束后再预览恢复")
	}
	a.backupBusy.Store(true)
	defer a.backupBusy.Store(false)
	reader, e := r.MultipartReader()
	if e != nil {
		return bad("请提供备份文件和恢复密码")
	}
	fields := map[string][]byte{}
	for {
		part, e := reader.NextPart()
		if e == io.EOF {
			break
		}
		if e != nil {
			return bad("恢复上传字段无效")
		}
		name := part.FormName()
		if _, exists := fields[name]; exists || (name != "file" && name != "password" && name != "revision") {
			part.Close()
			return bad("恢复上传字段无效")
		}
		limit := int64(4096)
		if name == "file" {
			limit = backup.MaxBackupBytes
		}
		value, e := io.ReadAll(io.LimitReader(part, limit+1))
		part.Close()
		if e != nil || int64(len(value)) > limit {
			return bad("备份文件或字段超出大小限制")
		}
		fields[name] = value
	}
	if len(fields) != 3 {
		return bad("请提供备份文件和恢复密码")
	}
	revision, e := strconv.Atoi(string(fields["revision"]))
	if e != nil || revision < 0 {
		return bad("配置版本无效")
	}
	password := string(fields["password"])
	result, e := a.Backups.Preview(fields["file"], password, revision)
	if e != nil {
		return e
	}
	a.mu.Lock()
	for key, value := range a.previews {
		if time.Now().After(value.expires) {
			delete(a.previews, key)
		}
	}
	a.previews[text(result["ticket"])] = restoreContext{password, a.sessionBindingUnlocked(r), time.Now().Add(10 * time.Minute)}
	a.mu.Unlock()
	writeJSON(w, 200, result)
	return nil
}
func (a *App) sessionBindingUnlocked(r *http.Request) string {
	session := a.security.Session(r)
	if session == nil {
		return ""
	}
	hash := sha256.Sum256([]byte(session.Origin + "\x00" + session.CSRF))
	return hex.EncodeToString(hash[:])
}

func (a *App) backupRestore(w http.ResponseWriter, r *http.Request) error {
	body, revision, e := revisionBody(r, "ticket", "admin_password", "reauth_token")
	if e != nil {
		return e
	}
	if len(body) != 3 || text(body["ticket"]) == "" {
		return bad("恢复字段无效")
	}
	if !a.operation.TryLock() {
		return busy("已有备份操作正在处理")
	}
	defer a.operation.Unlock()
	a.backupBusy.Store(true)
	defer a.backupBusy.Store(false)
	// Drain already-running HTTP handlers before validating proof and copying data.
	a.httpGate.Lock()
	defer a.httpGate.Unlock()
	a.Jobs.mu.Lock()
	defer a.Jobs.mu.Unlock()
	if a.Jobs.active != 0 {
		return busy("请等待当前任务结束后再恢复")
	}
	a.mu.RLock()
	security := a.security
	a.mu.RUnlock()
	if security.Session(r) == nil {
		return &auth.HTTPError{Status: 401, Message: "管理会话已失效, 请重新登录"}
	}
	if proof, ok := body["reauth_token"]; ok {
		if _, e = security.ConsumeReauth(r, text(proof), security.RequirePasskeyReauth(r)); e != nil {
			return e
		}
	} else if e = security.Reauthenticate(r, text(body["admin_password"])); e != nil {
		return e
	}
	binding := a.sessionBinding(r)
	ticket := text(body["ticket"])
	a.mu.Lock()
	preview, ok := a.previews[ticket]
	delete(a.previews, ticket)
	a.mu.Unlock()
	if !ok || preview.binding != binding || time.Now().After(preview.expires) {
		return bad("恢复预览已失效, 请重新上传并预览")
	}
	config, current, e := a.Store.Load()
	if e != nil {
		return errors.New("当前配置无法读取")
	}
	if current != revision {
		return storage.ErrConflict
	}
	settings := object(config["backups"])
	password := text(settings["password"])
	if password == "" {
		password = preview.password
	}
	if _, e = a.Backups.Create(password, int(number(settings["retain_count"]))); e != nil {
		return errors.New("恢复前备份失败, 当前数据未替换")
	}
	staged, e := a.Backups.PrepareRestore(ticket, revision)
	if e != nil {
		return e
	}
	defer os.Remove(staged)
	local := a.Runtime.Get()
	local.RunOnStartup = false
	if e = a.Runtime.Save(local); e != nil {
		return errors.New("无法关闭启动签到, 当前数据未替换")
	}
	a.maintenance.Store(true)
	defer a.maintenance.Store(false)
	if e = replaceDatabase(a.Store.DB, staged); e != nil {
		return errors.New("恢复失败, 当前数据库已保留")
	}
	security.Invalidate()
	a.previews = map[string]restoreContext{}
	a.Jobs.Notify()
	writeJSON(w, 200, Document{"restored": true, "authenticated": false, "automatic_tasks_disabled": true})
	return nil
}

// Keep the live DB handle. A single transaction gives recovery atomicity on
// Windows as well as Unix and retains the original database if any copy fails.
func replaceDatabase(db *sql.DB, staged string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, e := db.Conn(ctx)
	if e != nil {
		return e
	}
	defer conn.Close()
	if _, e = conn.ExecContext(ctx, "ATTACH DATABASE ? AS restore_staged", staged); e != nil {
		return e
	}
	defer conn.ExecContext(context.Background(), "DETACH DATABASE restore_staged")
	rows, e := conn.QueryContext(ctx, "SELECT name FROM main.sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	if e != nil {
		return e
	}
	tables := []string{}
	for rows.Next() {
		var name string
		if e = rows.Scan(&name); e != nil {
			rows.Close()
			return e
		}
		tables = append(tables, name)
	}
	if e = rows.Err(); e != nil {
		rows.Close()
		return e
	}
	rows.Close()
	tx, e := conn.BeginTx(ctx, nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, name := range tables {
		quoted := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
		if _, e = tx.ExecContext(ctx, "DELETE FROM main."+quoted); e != nil {
			return e
		}
		var exists int
		if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM restore_staged.sqlite_master WHERE type='table' AND name=?", name).Scan(&exists); e != nil {
			return e
		}
		if exists == 1 {
			if _, e = tx.ExecContext(ctx, "INSERT INTO main."+quoted+" SELECT * FROM restore_staged."+quoted); e != nil {
				return e
			}
		}
	}
	return tx.Commit()
}
