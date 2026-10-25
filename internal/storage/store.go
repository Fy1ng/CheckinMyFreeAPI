// Package storage reads the same encrypted SQLite documents as the Python edition.
package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Document = map[string]any

var ErrConflict = errors.New("Configuration changed; reload it before saving again")
var ErrInvalid = errors.New("Stored configuration is invalid; restore a trusted backup")

const ConfigAAD = "anyrouter.server.configuration.v1:"
const SessionAAD = "anyrouter.server.http-session.v1:"
const SessionPurpose = "newapi-http-sessions-v1"

type Store struct {
	DB            *sql.DB
	Path, DataDir string
	Key           []byte
	mu            sync.Mutex
}

func Open(path string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("The encryption key must contain exactly 32 bytes")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if err = PrivatePath(absolute); err != nil {
		return nil, err
	}
	if err = os.MkdirAll(filepath.Dir(absolute), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(absolute, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	f.Close()
	if err = os.Chmod(absolute, 0600); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", absolute)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{DB: db, Path: absolute, DataDir: filepath.Dir(absolute), Key: append([]byte(nil), key...)}
	if _, err = db.Exec("PRAGMA journal_mode=DELETE; PRAGMA busy_timeout=10000; PRAGMA trusted_schema=OFF;" + Schema); err != nil {
		db.Close()
		return nil, err
	}
	// These two columns were introduced without replacing the original runs table.
	for _, column := range []struct{ name, definition string }{{"kind", "TEXT NOT NULL DEFAULT 'checkin'"}, {"identity", "TEXT"}} {
		rows, e := db.Query("PRAGMA table_info(runs)")
		if e != nil {
			db.Close()
			return nil, e
		}
		found := false
		for rows.Next() {
			var cid, notnull, pk int
			var name, typ string
			var dflt any
			if e = rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); e != nil {
				rows.Close()
				db.Close()
				return nil, e
			}
			if name == column.name {
				found = true
			}
		}
		rows.Close()
		if !found {
			if _, e = db.Exec("ALTER TABLE runs ADD COLUMN " + column.name + " " + column.definition); e != nil {
				db.Close()
				return nil, e
			}
		}
	}
	return s, nil
}

// PrivatePath rejects symlinks on every existing component, including ancestors.
func PrivatePath(path string) error {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return errors.New("Private data path is unavailable")
	}
	path = absolute
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil && !os.IsNotExist(err) {
			return errors.New("Private data path is unavailable")
		}
		if err == nil && fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("Private data path must not be a symbolic link")
		}
		next := filepath.Dir(p)
		if next == p {
			break
		}
	}
	return nil
}

func (s *Store) Close() error { return s.DB.Close() }
func Random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
func Encrypt(key, plain, aad []byte) ([]byte, error) {
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	nonce := Random(a.NonceSize())
	return a.Seal(nonce, nonce, plain, aad), nil
}
func Decrypt(key, encrypted, aad []byte) ([]byte, error) {
	if len(encrypted) < 28 || len(encrypted) > 1024*1024+28 {
		return nil, ErrInvalid
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, ErrInvalid
	}
	a, e := cipher.NewGCM(b)
	if e != nil {
		return nil, ErrInvalid
	}
	p, e := a.Open(nil, encrypted[:12], encrypted[12:], aad)
	if e != nil {
		return nil, ErrInvalid
	}
	return p, nil
}
func SessionKey(key []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(SessionPurpose))
	return m.Sum(nil)
}
func Clone(d Document) Document {
	if d == nil {
		return nil
	}
	b, _ := json.Marshal(d)
	var r Document
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.UseNumber()
	_ = decoder.Decode(&r)
	return r
}
func Object(v any) Document {
	if d, ok := v.(map[string]any); ok {
		return d
	}
	return nil
}
func Array(v any) []any {
	if a, ok := v.([]any); ok {
		return a
	}
	if a, ok := v.([]Document); ok {
		r := make([]any, len(a))
		for i := range a {
			r[i] = a[i]
		}
		return r
	}
	return nil
}
func String(v any) string { s, _ := v.(string); return s }
func Bool(v any) bool     { b, _ := v.(bool); return b }
func Number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		x, e := n.Float64()
		return x, e == nil
	}
	return 0, false
}
func Int(v any) int { n, _ := Number(v); return int(n) }
func Stamp(v any) any {
	n, ok := Number(v)
	if !ok {
		return nil
	}
	return time.Unix(0, int64(n*1e9)).UTC().Format(time.RFC3339Nano)
}
func Now() float64 { return float64(time.Now().UnixNano()) / 1e9 }

func (s *Store) loadTx(tx *sql.Tx) (Document, int, error) {
	var revision int
	var encrypted []byte
	err := tx.QueryRow("SELECT revision,document FROM config WHERE id=1").Scan(&revision, &encrypted)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultConfig(), 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	if revision < 1 {
		return nil, 0, ErrInvalid
	}
	plaintext, err := Decrypt(s.Key, encrypted, []byte(ConfigAAD+strconv.Itoa(revision)))
	if err != nil {
		return nil, 0, err
	}
	var d Document
	if json.Unmarshal(plaintext, &d) != nil || d == nil {
		return nil, 0, ErrInvalid
	}
	d, information, err := migrate(d, revision)
	if err != nil {
		return nil, 0, err
	}
	if information != nil {
		meta, _ := json.Marshal(information)
		if _, err = tx.Exec("INSERT INTO config_archive(source_revision,document,migration) VALUES (?,?,?)", revision, encrypted, string(meta)); err != nil {
			return nil, 0, err
		}
		revision++
		if err = s.writeTx(tx, d, revision); err != nil {
			return nil, 0, err
		}
	}
	d, err = Validate(d)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: invalid document", ErrInvalid)
	}
	return d, revision, nil
}
func (s *Store) writeTx(tx *sql.Tx, d Document, revision int) error {
	b, e := json.Marshal(d)
	if e != nil {
		return ErrInvalid
	}
	encrypted, e := Encrypt(s.Key, b, []byte(ConfigAAD+strconv.Itoa(revision)))
	if e != nil {
		return e
	}
	_, e = tx.Exec("INSERT INTO config(id,revision,document) VALUES (1,?,?) ON CONFLICT(id) DO UPDATE SET revision=excluded.revision,document=excluded.document", revision, encrypted)
	return e
}
func (s *Store) Load() (Document, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.Begin()
	if e != nil {
		return nil, 0, e
	}
	defer tx.Rollback()
	d, r, e := s.loadTx(tx)
	if e != nil {
		return nil, 0, e
	}
	if e = tx.Commit(); e != nil {
		return nil, 0, e
	}
	return d, r, nil
}
func (s *Store) Save(config Document, expectedRevision int) (Document, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	tx, e := s.DB.Begin()
	if e != nil {
		return nil, 0, e
	}
	defer tx.Rollback()
	old, r, e := s.loadTx(tx)
	if e != nil {
		return nil, 0, e
	}
	if r != expectedRevision {
		return nil, 0, ErrConflict
	}
	d, e := RestoreSecrets(config, old)
	if e != nil {
		return nil, 0, e
	}
	d, e = Validate(d)
	if e != nil {
		return nil, 0, e
	}
	if e = s.writeTx(tx, d, r+1); e != nil {
		return nil, 0, e
	}
	if e = tx.Commit(); e != nil {
		return nil, 0, e
	}
	return Redact(d), r + 1, nil
}
func (s *Store) Public() (Document, error) {
	d, r, e := s.Load()
	if e != nil {
		return nil, e
	}
	m, e := s.MigrationInfo()
	if e != nil {
		return nil, e
	}
	return Document{"config": Redact(d), "revision": r, "migration": m}, nil
}
func (s *Store) MigrationInfo() (Document, error) {
	var raw string
	e := s.DB.QueryRow("SELECT migration FROM config_archive ORDER BY source_revision DESC LIMIT 1").Scan(&raw)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	var d Document
	if json.Unmarshal([]byte(raw), &d) != nil {
		return nil, ErrInvalid
	}
	return d, nil
}

// Python's json.dumps(..., sort_keys=True) escapes non-ASCII characters. Bindings
// must do the same or a port would discard every saved HTTP session.
func PythonJSON(v any) []byte {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(v)
	b := bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))
	var out strings.Builder
	for _, r := range string(b) {
		if r > 127 {
			if r <= 0xffff {
				fmt.Fprintf(&out, "\\u%04x", r)
			} else {
				r -= 0x10000
				fmt.Fprintf(&out, "\\u%04x\\u%04x", 0xd800+(r>>10), 0xdc00+(r&0x3ff))
			}
		} else {
			out.WriteRune(r)
		}
	}
	return []byte(out.String())
}
func AccountBinding(account, config Document) string {
	d := Document{}
	for _, k := range []string{"id", "provider", "auth_type", "cookies", "username", "password", "system_access_token", "api_user", "expected_username", "proxy"} {
		d[k] = account[k]
	}
	p := String(account["proxy"])
	if p == "" || p == "default" {
		d["proxy_url"] = config["proxy_url"]
	}
	h := sha256.Sum256(PythonJSON(d))
	return hex.EncodeToString(h[:])
}
func sessionIdentity(id, binding string) (string, []byte, error) {
	if validText(id, 128, false) != nil || validText(binding, 8192, false) != nil {
		return "", nil, errors.New("HTTP session account or binding is invalid")
	}
	h := sha256.Sum256([]byte(binding))
	digest := hex.EncodeToString(h[:])
	aad := append([]byte(SessionAAD), PythonJSON([]string{id, digest})...)
	return digest, aad, nil
}
func (s *Store) LoadSession(id, binding string) (Document, error) {
	digest, aad, e := sessionIdentity(id, binding)
	if e != nil {
		return nil, e
	}
	var saved string
	var encrypted []byte
	e = s.DB.QueryRow("SELECT binding_hash,document FROM http_sessions WHERE account_id=?", id).Scan(&saved, &encrypted)
	if errors.Is(e, sql.ErrNoRows) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if saved != digest {
		return nil, nil
	}
	plain, e := Decrypt(SessionKey(s.Key), encrypted, aad)
	if e != nil {
		return nil, errors.New("HTTP session cannot be decrypted; verify the key or update credentials")
	}
	var d Document
	if json.Unmarshal(plain, &d) != nil || d == nil {
		return nil, ErrInvalid
	}
	return d, nil
}
func (s *Store) SaveSession(id, binding string, state Document) error {
	digest, aad, e := sessionIdentity(id, binding)
	if e != nil {
		return e
	}
	if state == nil {
		return errors.New("HTTP session state must be an object")
	}
	plain, e := json.Marshal(state)
	if e != nil || len(plain) > 1024*1024 {
		return errors.New("HTTP session has an invalid format or size")
	}
	encrypted, e := Encrypt(SessionKey(s.Key), plain, aad)
	if e != nil {
		return e
	}
	_, e = s.DB.Exec("INSERT INTO http_sessions(account_id,binding_hash,document) VALUES (?,?,?) ON CONFLICT(account_id) DO UPDATE SET binding_hash=excluded.binding_hash,document=excluded.document", id, digest, encrypted)
	return e
}
func (s *Store) DeleteSession(id string) error {
	_, e := s.DB.Exec("DELETE FROM http_sessions WHERE account_id=?", id)
	return e
}

const Schema = `
CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK (id = 1), revision INTEGER NOT NULL CHECK (revision > 0), document BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS config_archive (source_revision INTEGER PRIMARY KEY, document BLOB NOT NULL, migration TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS http_sessions (account_id TEXT PRIMARY KEY, binding_hash TEXT NOT NULL, document BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS account_attention ( account_id TEXT PRIMARY KEY, binding TEXT NOT NULL, outcome TEXT NOT NULL, reason TEXT NOT NULL, retry_at REAL, updated_at REAL NOT NULL);
CREATE TABLE IF NOT EXISTS runs ( id INTEGER PRIMARY KEY, state TEXT NOT NULL, started_at REAL NOT NULL, finished_at REAL, error TEXT, summary TEXT, revision INTEGER NOT NULL );
CREATE TABLE IF NOT EXISTS scheduler (id INTEGER PRIMARY KEY CHECK(id=1), next_at REAL);
INSERT OR IGNORE INTO scheduler VALUES (1,NULL);
CREATE TABLE IF NOT EXISTS balance_scheduler (id INTEGER PRIMARY KEY CHECK(id=1), next_at REAL);
INSERT OR IGNORE INTO balance_scheduler VALUES (1,NULL);
CREATE TABLE IF NOT EXISTS backup_scheduler (id INTEGER PRIMARY KEY CHECK(id=1),next_at REAL,last_attempt_at REAL,last_state TEXT,error TEXT);
INSERT OR IGNORE INTO backup_scheduler VALUES (1,NULL,NULL,NULL,NULL);
CREATE TABLE IF NOT EXISTS balance_accounts ( account_id TEXT PRIMARY KEY, binding TEXT NOT NULL, identity TEXT, balance TEXT, used TEXT, total TEXT, observed_at REAL, state TEXT NOT NULL, reason TEXT, attempted_at REAL NOT NULL );
CREATE TABLE IF NOT EXISTS balance_days ( account_id TEXT NOT NULL, binding TEXT NOT NULL, day TEXT NOT NULL, opening TEXT NOT NULL, closing TEXT NOT NULL, total TEXT, credits TEXT NOT NULL, site_income TEXT, samples INTEGER NOT NULL, first_at REAL NOT NULL, last_at REAL NOT NULL, reset INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (account_id, binding, day) );
CREATE TABLE IF NOT EXISTS balance_retry ( account_id TEXT PRIMARY KEY, binding TEXT NOT NULL, retry_at REAL NOT NULL );
CREATE TABLE IF NOT EXISTS automation_health ( account_id TEXT NOT NULL, binding TEXT NOT NULL, scope TEXT NOT NULL, state TEXT NOT NULL, reason TEXT, failure_since REAL, last_failure_at REAL, last_success_at REAL, recovered_at REAL, consecutive_failures INTEGER NOT NULL, recovery_notified_at REAL, PRIMARY KEY(account_id,binding,scope) );
CREATE TABLE IF NOT EXISTS automation_low_balance ( account_id TEXT NOT NULL, binding TEXT NOT NULL, threshold REAL NOT NULL, below INTEGER NOT NULL, episode REAL, notified_at REAL, PRIMARY KEY(account_id,binding) );
CREATE TABLE IF NOT EXISTS automation_notifications ( id INTEGER PRIMARY KEY, event_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, account_id TEXT, state TEXT NOT NULL, created_at REAL NOT NULL, finished_at REAL, title TEXT NOT NULL, message TEXT NOT NULL, delivery TEXT, run_id INTEGER );
CREATE TABLE IF NOT EXISTS automation_scheduler ( id INTEGER PRIMARY KEY CHECK(id=1), signature TEXT NOT NULL, next_at REAL );
INSERT OR IGNORE INTO automation_scheduler VALUES (1,'',NULL);
`
