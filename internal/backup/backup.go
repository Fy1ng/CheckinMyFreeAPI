// Package backup implements Python-compatible .nab encrypted snapshots.
package backup

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"github.com/Fy1ng/CheckinMyFreeAPI/internal/storage"
	"golang.org/x/crypto/scrypt"
)

type Document = map[string]any

const MaxBackupBytes = 64 * 1024 * 1024
const magic = "NEWAPI-BACKUP\x00\x01"
const envelopeAAD = "newapi.password-backup.v1"

var backupName = regexp.MustCompile(`^backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\.nab$`)
var previewName = regexp.MustCompile(`^\.restore-preview-[0-9a-f]{32}\.sqlite3$`)
var ErrInvalid = errors.New("恢复密码错误或备份文件已损坏")

type preview struct {
	Path     string
	Key      []byte
	Revision int
	Expires  time.Time
}
type Manager struct {
	Store              *storage.Store
	DataDir, Directory string
	mu                 sync.Mutex
	previews           map[string]preview
}

func New(store *storage.Store) (*Manager, error) {
	if err := storage.PrivatePath(store.DataDir); err != nil {
		return nil, err
	}
	dir := filepath.Join(store.DataDir, "backups")
	if err := storage.PrivatePath(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	m := &Manager{Store: store, DataDir: store.DataDir, Directory: dir, previews: map[string]preview{}}
	entries, _ := os.ReadDir(m.DataDir)
	for _, entry := range entries {
		if !previewName.MatchString(entry.Name()) {
			continue
		}
		p := filepath.Join(m.DataDir, entry.Name())
		info, e := os.Lstat(p)
		if e == nil && info.Mode().IsRegular() && time.Since(info.ModTime()) > 10*time.Minute {
			_ = os.Remove(p)
		}
	}
	return m, nil
}
func ValidatePassword(password string) error {
	if !utf8.ValidString(password) || utf8.RuneCountInString(password) < 16 || utf8.RuneCountInString(password) > 512 {
		return errors.New("备份恢复密码需要 16 到 512 个字符")
	}
	return nil
}
func backupCipher(password string, salt []byte) (cipher.AEAD, error) {
	if err := ValidatePassword(password); err != nil {
		return nil, err
	}
	key, e := scrypt.Key([]byte(password), salt, 16384, 8, 1, 32)
	if e != nil {
		return nil, e
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func encode(database, key []byte, password string, created float64) ([]byte, error) {
	metadata := Document{"version": 1, "created_at": created, "master_key": base64.StdEncoding.EncodeToString(key), "database_sha256": digest(database), "database_length": len(database)}
	header, e := json.Marshal(metadata)
	if e != nil {
		return nil, e
	}
	plain := make([]byte, 4, len(header)+len(database)+4)
	binary.BigEndian.PutUint32(plain, uint32(len(header)))
	plain = append(plain, header...)
	plain = append(plain, database...)
	salt, nonce := storage.Random(16), storage.Random(12)
	a, e := backupCipher(password, salt)
	if e != nil {
		return nil, e
	}
	out := append([]byte(magic), salt...)
	out = append(out, nonce...)
	out = a.Seal(out, nonce, plain, []byte(envelopeAAD))
	if len(out) > MaxBackupBytes {
		return nil, errors.New("备份文件超出 64 MiB 限制")
	}
	return out, nil
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

type envelopeMetadata struct {
	Version        int     `json:"version"`
	CreatedAt      float64 `json:"created_at"`
	MasterKey      string  `json:"master_key"`
	DatabaseSHA    string  `json:"database_sha256"`
	DatabaseLength int     `json:"database_length"`
}

func decode(data []byte, password string) (database, key []byte, info Document, err error) {
	if e := ValidatePassword(password); e != nil {
		return nil, nil, nil, e
	}
	if len(data) <= len(magic)+48 || len(data) > MaxBackupBytes || !bytes.HasPrefix(data, []byte(magic)) {
		return nil, nil, nil, errors.New("备份格式或大小无效")
	}
	pos := len(magic)
	a, e := backupCipher(password, data[pos:pos+16])
	if e != nil {
		return nil, nil, nil, ErrInvalid
	}
	plain, e := a.Open(nil, data[pos+16:pos+28], data[pos+28:], []byte(envelopeAAD))
	if e != nil || len(plain) < 4 {
		return nil, nil, nil, ErrInvalid
	}
	length := int(binary.BigEndian.Uint32(plain[:4]))
	if length <= 0 || length > 4096 || length+4 >= len(plain) {
		return nil, nil, nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(plain[4 : 4+length]))
	decoder.DisallowUnknownFields()
	var m envelopeMetadata
	if !json.Valid(plain[4:4+length]) || decoder.Decode(&m) != nil || m.Version != 1 || math.IsNaN(m.CreatedAt) || math.IsInf(m.CreatedAt, 0) || m.CreatedAt <= 0 || m.CreatedAt > storage.Now()+300 {
		return nil, nil, nil, ErrInvalid
	}
	key, e = base64.StdEncoding.Strict().DecodeString(m.MasterKey)
	database = plain[4+length:]
	if e != nil || len(key) != 32 || m.DatabaseLength != len(database) || subtle.ConstantTimeCompare([]byte(m.DatabaseSHA), []byte(digest(database))) != 1 {
		return nil, nil, nil, ErrInvalid
	}
	return database, key, Document{"created_at": storage.Stamp(m.CreatedAt), "format_version": 1}, nil
}
func regular(path string, max int64) error {
	if e := storage.PrivatePath(path); e != nil {
		return e
	}
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Size() > max {
		return errors.New("备份文件不可用")
	}
	return nil
}
func writePrivate(path string, data []byte) error {
	if e := storage.PrivatePath(path); e != nil {
		return e
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	success := false
	defer func() {
		f.Close()
		if !success {
			_ = os.Remove(path)
		}
	}()
	if e = platform.ProtectFile(path); e != nil {
		return e
	}
	if _, e = f.Write(data); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	success = true
	return nil
}
func stage(root string, database []byte) (string, error) {
	p := filepath.Join(root, ".restore-preview-"+hex.EncodeToString(storage.Random(16))+".sqlite3")
	return p, writePrivate(p, database)
}
func (m *Manager) cleanup() {
	for ticket, p := range m.previews {
		if !time.Now().Before(p.Expires) {
			_ = os.Remove(p.Path)
			delete(m.previews, ticket)
		}
	}
}
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, p := range m.previews {
		_ = os.Remove(p.Path)
	}
	m.previews = map[string]preview{}
}
func (m *Manager) List() ([]Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanup()
	if e := storage.PrivatePath(m.Directory); e != nil {
		return nil, e
	}
	entries, e := os.ReadDir(m.Directory)
	if e != nil {
		return nil, e
	}
	items := []Document{}
	for _, entry := range entries {
		name := entry.Name()
		if !backupName.MatchString(name) {
			continue
		}
		p := filepath.Join(m.Directory, name)
		if regular(p, MaxBackupBytes) != nil {
			continue
		}
		f, e := os.Open(p)
		if e != nil {
			continue
		}
		b := make([]byte, len(magic))
		_, e = io.ReadFull(f, b)
		f.Close()
		if e != nil || !bytes.Equal(b, []byte(magic)) {
			continue
		}
		t, e := time.Parse("20060102T150405Z", name[7:23])
		if e != nil {
			continue
		}
		info, e := entry.Info()
		if e != nil {
			continue
		}
		items = append(items, Document{"id": name, "created_at": t.UTC().Format(time.RFC3339), "size": info.Size()})
	}
	sort.Slice(items, func(i, j int) bool { return storage.String(items[i]["id"]) > storage.String(items[j]["id"]) })
	return items, nil
}
func (m *Manager) Read(id string) (string, error) {
	if !backupName.MatchString(id) {
		return "", errors.New("备份标识无效")
	}
	p := filepath.Join(m.Directory, id)
	if e := regular(p, MaxBackupBytes); e != nil {
		return "", e
	}
	return p, nil
}
func (m *Manager) Create(password string, retain int) (Document, error) {
	if e := ValidatePassword(password); e != nil {
		return nil, e
	}
	if retain < 1 || retain > 90 {
		return nil, errors.New("备份保留数量需要为 1 到 90")
	}
	if e := storage.PrivatePath(m.Directory); e != nil {
		return nil, e
	}
	p := filepath.Join(m.DataDir, ".backup-snapshot-"+hex.EncodeToString(storage.Random(16))+".sqlite3")
	defer os.Remove(p)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, e := m.Store.DB.ExecContext(ctx, "VACUUM INTO ?", p); e != nil {
		return nil, errors.New("备份数据库快照失败")
	}
	if e := os.Chmod(p, 0600); e != nil {
		return nil, e
	}
	_, _, counts, e := validateDatabase(p, m.Store.Key)
	if e != nil {
		return nil, e
	}
	database, e := os.ReadFile(p)
	if e != nil {
		return nil, e
	}
	created := storage.Now()
	name := "backup-" + time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(storage.Random(8)) + ".nab"
	encoded, e := encode(database, m.Store.Key, password, created)
	if e != nil {
		return nil, e
	}
	if e = writePrivate(filepath.Join(m.Directory, name), encoded); e != nil {
		return nil, e
	}
	items, e := m.List()
	if e != nil {
		return nil, e
	}
	for _, item := range items[min(retain, len(items)):] {
		p, e := m.Read(storage.String(item["id"]))
		if e != nil {
			return nil, e
		}
		if e = os.Remove(p); e != nil {
			return nil, e
		}
	}
	counts["id"] = name
	counts["created_at"] = storage.Stamp(created)
	counts["size"] = len(encoded)
	return counts, nil
}
func (m *Manager) Preview(data []byte, password string, currentRevision int) (Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanup()
	_, revision, e := m.Store.Load()
	if e != nil {
		return nil, e
	}
	if revision != currentRevision {
		return nil, storage.ErrConflict
	}
	if len(m.previews) >= 4 {
		return nil, errors.New("恢复预览过多, 请等待旧预览到期")
	}
	database, key, meta, e := decode(data, password)
	if e != nil {
		return nil, e
	}
	p, e := stage(m.DataDir, database)
	if e != nil {
		return nil, e
	}
	_, sourceRevision, counts, e := validateDatabase(p, key)
	if e != nil {
		_ = os.Remove(p)
		return nil, e
	}
	ticket := base64.RawURLEncoding.EncodeToString(storage.Random(32))
	expires := time.Now().Add(10 * time.Minute)
	m.previews[ticket] = preview{p, key, revision, expires}
	for k, v := range counts {
		meta[k] = v
	}
	meta["source_revision"] = sourceRevision
	meta["ticket"] = ticket
	meta["expires_at"] = expires.UTC().Format(time.RFC3339)
	meta["automatic_tasks_disabled"] = true
	meta["preserves_admin"] = true
	meta["preserves_public_url"] = true
	return meta, nil
}
func (m *Manager) PrepareRestore(ticket string, currentRevision int) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cleanup()
	item, ok := m.previews[ticket]
	delete(m.previews, ticket)
	if !ok {
		return "", errors.New("恢复预览已失效, 请重新上传并预览")
	}
	success := false
	defer func() {
		if !success {
			_ = os.Remove(item.Path)
		}
	}()
	config, revision, e := m.Store.Load()
	if e != nil {
		return "", e
	}
	if revision != currentRevision || revision != item.Revision {
		return "", storage.ErrConflict
	}
	if e = prepareDatabase(item.Path, item.Key, m.Store.Key, config, revision, m.Store.DB); e != nil {
		return "", e
	}
	success = true
	return item.Path, nil
}
func Inspect(data []byte, password string) (Document, error) {
	database, key, meta, e := decode(data, password)
	if e != nil {
		return nil, e
	}
	root, e := os.MkdirTemp("", "checkin-backup-inspect-")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(root)
	p, e := stage(root, database)
	if e != nil {
		return nil, e
	}
	_, revision, counts, e := validateDatabase(p, key)
	if e != nil {
		return nil, e
	}
	for k, v := range counts {
		meta[k] = v
	}
	meta["source_revision"] = revision
	return meta, nil
}
func RestoreOffline(data []byte, password, dataDir, keyFile string) (Document, error) {
	for _, p := range []string{dataDir, keyFile} {
		if e := storage.PrivatePath(p); e != nil {
			return nil, e
		}
	}
	destination := filepath.Join(dataDir, "webui.sqlite3")
	absDB, e := filepath.Abs(destination)
	if e != nil {
		return nil, e
	}
	absKey, e := filepath.Abs(keyFile)
	if e != nil {
		return nil, e
	}
	if absDB == absKey {
		return nil, errors.New("数据库与主密钥路径不可相同")
	}
	for _, p := range []string{destination, keyFile} {
		if _, e := os.Lstat(p); !os.IsNotExist(e) {
			return nil, errors.New("离线恢复只允许新的数据库和主密钥路径")
		}
	}
	database, key, meta, e := decode(data, password)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(dataDir, 0700); e != nil {
		return nil, e
	}
	if e = os.MkdirAll(filepath.Dir(keyFile), 0700); e != nil {
		return nil, e
	}
	p, e := stage(dataDir, database)
	if e != nil {
		return nil, e
	}
	defer os.Remove(p)
	_, revision, counts, e := validateDatabase(p, key)
	if e != nil {
		return nil, e
	}
	if e = prepareDatabase(p, key, key, nil, revision, nil); e != nil {
		return nil, e
	}
	if e = writePrivate(keyFile, key); e != nil {
		return nil, e
	}
	data, e = os.ReadFile(p)
	if e != nil {
		os.Remove(keyFile)
		return nil, e
	}
	if e = writePrivate(destination, data); e != nil {
		os.Remove(keyFile)
		return nil, e
	}
	for k, v := range counts {
		meta[k] = v
	}
	meta["automatic_tasks_disabled"] = true
	return meta, nil
}

func compactSQL(s string) string {
	var b strings.Builder
	quoted := rune(0)
	for _, c := range strings.ToLower(s) {
		if quoted != 0 {
			b.WriteRune(c)
			if c == quoted {
				quoted = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quoted = c
		}
		if !unicode.IsSpace(c) {
			b.WriteRune(c)
		}
	}
	return b.String()
}

const securitySchema = `
CREATE TABLE IF NOT EXISTS web_auth (id INTEGER PRIMARY KEY CHECK(id=1), salt BLOB NOT NULL, digest BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS web_security ( id INTEGER PRIMARY KEY CHECK(id=1), mode TEXT NOT NULL, revision INTEGER NOT NULL, user_handle BLOB NOT NULL );
CREATE TABLE IF NOT EXISTS web_passkeys ( id TEXT PRIMARY KEY, credential BLOB NOT NULL, origin TEXT NOT NULL, rp_id TEXT NOT NULL, label TEXT NOT NULL, counter INTEGER NOT NULL, backup_eligible INTEGER NOT NULL, backed_up INTEGER NOT NULL, verified INTEGER NOT NULL, created_at REAL NOT NULL, last_used_at REAL );
`

var schemaOnce sync.Once
var expected map[string]string
var schemaErr error

func expectedSchema() (map[string]string, error) {
	schemaOnce.Do(func() {
		db, e := sql.Open("sqlite", ":memory:")
		if e != nil {
			schemaErr = e
			return
		}
		defer db.Close()
		_, e = db.Exec(storage.Schema + "ALTER TABLE runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'checkin'; ALTER TABLE runs ADD COLUMN identity TEXT;" + securitySchema)
		if e != nil {
			schemaErr = e
			return
		}
		expected, schemaErr = databaseSchema(context.Background(), db)
	})
	return expected, schemaErr
}
func databaseSchema(ctx context.Context, db *sql.DB) (map[string]string, error) {
	rows, e := db.QueryContext(ctx, "SELECT type,name,sql FROM sqlite_master")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	m := map[string]string{}
	for rows.Next() {
		var kind, name string
		var statement sql.NullString
		if e = rows.Scan(&kind, &name, &statement); e != nil {
			return nil, e
		}
		m[kind+":"+name] = compactSQL(statement.String)
	}
	return m, rows.Err()
}
func openReadonly(path string) (*sql.DB, error) {
	if e := regular(path, MaxBackupBytes); e != nil {
		return nil, e
	}
	fi, e := os.Stat(path)
	if e != nil || fi.Size() < 100 {
		return nil, errors.New("备份数据库大小无效")
	}
	db, e := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro&immutable=1")
	if e != nil {
		return nil, e
	}
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;"); e != nil {
		db.Close()
		return nil, e
	}
	return db, nil
}
func configuration(ctx context.Context, db *sql.DB, key []byte) (Document, int, error) {
	var revision int
	var encrypted []byte
	if e := db.QueryRowContext(ctx, "SELECT revision,document FROM config WHERE id=1").Scan(&revision, &encrypted); e != nil || revision < 1 || revision >= math.MaxInt64 {
		return nil, 0, errors.New("备份需要有效的已保存配置")
	}
	plain, e := storage.Decrypt(key, encrypted, []byte(storage.ConfigAAD+strconv.Itoa(revision)))
	if e != nil {
		return nil, 0, errors.New("备份中的加密数据无法校验")
	}
	var d Document
	if json.Unmarshal(plain, &d) != nil || storage.Int(d["schema_version"]) != 2 {
		return nil, 0, errors.New("备份配置版本不受支持")
	}
	d, e = storage.Validate(d)
	if e != nil {
		return nil, 0, errors.New("备份配置校验失败")
	}
	return d, revision, nil
}
func validateDatabase(path string, key []byte) (Document, int, Document, error) {
	db, e := openReadonly(path)
	if e != nil {
		return nil, 0, nil, e
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var integrity string
	if e = db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); e != nil || integrity != "ok" {
		return nil, 0, nil, errors.New("备份数据库完整性校验失败")
	}
	var pages, size int64
	if db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages) != nil || db.QueryRowContext(ctx, "PRAGMA page_size").Scan(&size) != nil || pages > MaxBackupBytes || size > MaxBackupBytes || pages*size > MaxBackupBytes {
		return nil, 0, nil, errors.New("备份数据库超出大小限制")
	}
	trusted, e := expectedSchema()
	if e != nil {
		return nil, 0, nil, e
	}
	actual, e := databaseSchema(ctx, db)
	if e != nil {
		return nil, 0, nil, e
	}
	for identity, statement := range actual {
		want, ok := trusted[identity]
		if !ok || strings.HasPrefix(identity, "trigger:") || strings.HasPrefix(identity, "view:") || statement != want {
			return nil, 0, nil, errors.New("备份包含未知或不兼容的数据库结构")
		}
	}
	if _, ok := actual["table:config"]; !ok {
		return nil, 0, nil, errors.New("备份缺少配置表")
	}
	if _, ok := actual["table:web_auth"]; !ok {
		return nil, 0, nil, errors.New("备份缺少管理员凭据")
	}
	var authID int
	var salt, digestBytes []byte
	if db.QueryRowContext(ctx, "SELECT id,salt,digest FROM web_auth").Scan(&authID, &salt, &digestBytes) != nil || authID != 1 || len(salt) != 16 || len(digestBytes) != 64 {
		return nil, 0, nil, errors.New("备份管理员凭据无效")
	}
	var count int
	if db.QueryRowContext(ctx, "SELECT count(*) FROM web_auth").Scan(&count) != nil || count != 1 {
		return nil, 0, nil, errors.New("备份管理员凭据无效")
	}
	config, revision, e := configuration(ctx, db, key)
	if e != nil {
		return nil, 0, nil, e
	}
	if _, ok := actual["table:config_archive"]; ok {
		rows, e := db.QueryContext(ctx, "SELECT source_revision,document FROM config_archive")
		if e != nil {
			return nil, 0, nil, e
		}
		for rows.Next() {
			var r int64
			var encrypted []byte
			if e = rows.Scan(&r, &encrypted); e != nil || r < 1 {
				rows.Close()
				return nil, 0, nil, errors.New("备份配置归档无效")
			}
			plain, e := storage.Decrypt(key, encrypted, []byte(storage.ConfigAAD+strconv.FormatInt(r, 10)))
			if e != nil || !json.Valid(plain) {
				rows.Close()
				return nil, 0, nil, errors.New("备份配置归档无效")
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, 0, nil, e
		}
	}
	if _, ok := actual["table:http_sessions"]; ok {
		rows, e := db.QueryContext(ctx, "SELECT account_id,binding_hash,document FROM http_sessions")
		if e != nil {
			return nil, 0, nil, e
		}
		sessionKey := storage.SessionKey(key)
		for rows.Next() {
			var id, binding string
			var encrypted []byte
			if rows.Scan(&id, &binding, &encrypted) != nil || len(id) > 128 || len(binding) != 64 || strings.Trim(binding, "0123456789abcdef") != "" {
				rows.Close()
				return nil, 0, nil, errors.New("备份会话标识无效")
			}
			aad := append([]byte(storage.SessionAAD), storage.PythonJSON([]string{id, binding})...)
			plain, e := storage.Decrypt(sessionKey, encrypted, aad)
			var d Document
			if e != nil || json.Unmarshal(plain, &d) != nil || d == nil {
				rows.Close()
				return nil, 0, nil, errors.New("备份会话无效")
			}
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, 0, nil, e
		}
	}
	runs := 0
	if _, ok := actual["table:runs"]; ok {
		if e = db.QueryRowContext(ctx, "SELECT count(*) FROM runs").Scan(&runs); e != nil {
			return nil, 0, nil, e
		}
	}
	return config, revision, Document{"accounts": len(storage.Array(config["accounts"])), "runs": runs}, nil
}

func queryRows(db *sql.DB, query string, args ...any) ([][]any, error) {
	rows, e := db.Query(query, args...)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	columns, e := rows.Columns()
	if e != nil {
		return nil, e
	}
	out := [][]any{}
	for rows.Next() {
		values := make([]any, len(columns))
		refs := make([]any, len(columns))
		for i := range values {
			refs[i] = &values[i]
		}
		if e = rows.Scan(refs...); e != nil {
			return nil, e
		}
		out = append(out, values)
	}
	return out, rows.Err()
}
func prepareDatabase(path string, oldKey, newKey []byte, currentConfig Document, currentRevision int, currentDB *sql.DB) error {
	config, savedRevision, _, e := validateDatabase(path, oldKey)
	if e != nil {
		return e
	}
	revision := max(currentRevision, savedRevision) + 1
	if revision < 1 || revision >= math.MaxInt64 {
		return errors.New("恢复配置版本超出范围")
	}
	storage.DisableAutomatic(config)
	if currentConfig != nil {
		config["webui_url"] = currentConfig["webui_url"]
	}
	config, e = storage.Validate(config)
	if e != nil {
		return e
	}
	security := map[string][][]any{}
	if currentDB != nil {
		for _, name := range []string{"web_auth", "web_security", "web_passkeys"} {
			rows, e := queryRows(currentDB, "SELECT * FROM "+name)
			if e != nil {
				return errors.New("当前管理员认证数据不可用")
			}
			security[name] = rows
		}
		if len(security["web_auth"]) != 1 {
			return errors.New("当前管理员身份不可用")
		}
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, e = db.Exec("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE;"); e != nil {
		return e
	}
	schema, e := databaseSchema(context.Background(), db)
	if e != nil {
		return e
	}
	archives := [][]any{}
	sessions := [][]any{}
	if _, ok := schema["table:config_archive"]; ok {
		archives, e = queryRows(db, "SELECT source_revision,document FROM config_archive")
		if e != nil {
			return e
		}
	}
	if _, ok := schema["table:http_sessions"]; ok {
		sessions, e = queryRows(db, "SELECT account_id,binding_hash,document FROM http_sessions")
		if e != nil {
			return e
		}
	}
	tx, e := db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	for _, r := range archives {
		aad := []byte(storage.ConfigAAD + fmt.Sprint(r[0]))
		plain, e := storage.Decrypt(oldKey, r[1].([]byte), aad)
		if e != nil {
			return e
		}
		encrypted, e := storage.Encrypt(newKey, plain, aad)
		if e != nil {
			return e
		}
		if _, e = tx.Exec("UPDATE config_archive SET document=? WHERE source_revision=?", encrypted, r[0]); e != nil {
			return e
		}
	}
	for _, r := range sessions {
		aad := append([]byte(storage.SessionAAD), storage.PythonJSON([]any{r[0], r[1]})...)
		plain, e := storage.Decrypt(storage.SessionKey(oldKey), r[2].([]byte), aad)
		if e != nil {
			return e
		}
		encrypted, e := storage.Encrypt(storage.SessionKey(newKey), plain, aad)
		if e != nil {
			return e
		}
		if _, e = tx.Exec("UPDATE http_sessions SET document=? WHERE account_id=?", encrypted, r[0]); e != nil {
			return e
		}
	}
	plain, e := json.Marshal(config)
	if e != nil {
		return e
	}
	encrypted, e := storage.Encrypt(newKey, plain, []byte(storage.ConfigAAD+strconv.Itoa(revision)))
	if e != nil {
		return e
	}
	if _, e = tx.Exec("UPDATE config SET revision=?,document=? WHERE id=1", revision, encrypted); e != nil {
		return e
	}
	if currentDB != nil {
		if _, e = tx.Exec(securitySchema); e != nil {
			return e
		}
		for _, name := range []string{"web_auth", "web_security", "web_passkeys"} {
			if _, e = tx.Exec("DELETE FROM " + name); e != nil {
				return e
			}
			for _, r := range security[name] {
				marks := strings.TrimRight(strings.Repeat("?,", len(r)), ",")
				if _, e = tx.Exec("INSERT INTO "+name+" VALUES ("+marks+")", r...); e != nil {
					return e
				}
			}
		}
		if _, e = tx.Exec("UPDATE web_security SET revision=revision+1 WHERE id=1"); e != nil {
			return e
		}
	}
	for _, name := range []string{"scheduler", "balance_scheduler", "backup_scheduler", "automation_scheduler"} {
		if _, ok := schema["table:"+name]; ok {
			if _, e = tx.Exec("UPDATE " + name + " SET next_at=NULL"); e != nil {
				return e
			}
		}
	}
	if _, ok := schema["table:automation_notifications"]; ok {
		if _, e = tx.Exec("UPDATE automation_notifications SET state='unknown',finished_at=? WHERE state='pending'", storage.Now()); e != nil {
			return e
		}
	}
	if _, ok := schema["table:runs"]; ok {
		var inflight int
		if e = tx.QueryRow("SELECT count(*) FROM runs WHERE state IN ('running','stopping','awaiting_login') AND kind='checkin'").Scan(&inflight); e != nil {
			return e
		}
		if _, e = tx.Exec("UPDATE runs SET state='interrupted',finished_at=?,error='备份恢复, 原任务状态需人工核对' WHERE state IN ('running','stopping','awaiting_login')", storage.Now()); e != nil {
			return e
		}
		if inflight > 0 {
			if _, e = tx.Exec("CREATE TABLE IF NOT EXISTS account_attention (account_id TEXT PRIMARY KEY, binding TEXT NOT NULL, outcome TEXT NOT NULL, reason TEXT NOT NULL, retry_at REAL, updated_at REAL NOT NULL)"); e != nil {
				return e
			}
			for _, v := range storage.Array(config["accounts"]) {
				a := storage.Object(v)
				if storage.Bool(a["enabled"]) {
					if _, e = tx.Exec("INSERT OR REPLACE INTO account_attention VALUES (?,?,?,?,?,?)", a["id"], storage.AccountBinding(a, config), "uncertain", "RESTORE_RESULT_UNKNOWN", nil, storage.Now()); e != nil {
						return e
					}
				}
			}
		}
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if e = db.Close(); e != nil {
		return e
	}
	_, _, _, e = validateDatabase(path, newKey)
	return e
}
