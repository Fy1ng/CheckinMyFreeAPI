package backup

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/storage"
)

const testRecovery = "local test recovery password"

func fixture(t *testing.T) (*storage.Store, *Manager) {
	t.Helper()
	s, e := storage.Open(filepath.Join(t.TempDir(), "webui.sqlite3"), bytes.Repeat([]byte{7}, 32))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if _, e = s.DB.Exec(securitySchema); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("INSERT INTO web_auth VALUES (1,?,?); INSERT INTO web_security VALUES (1,'password',1,?)", make([]byte, 16), make([]byte, 64), make([]byte, 32)); e != nil {
		t.Fatal(e)
	}
	d := storage.DefaultConfig()
	d["accounts"] = []any{Document{"id": "test", "name": "test", "provider": "anyrouter", "auth_type": "password", "enabled": true, "username": "local-test-user", "password": "local-test-value"}}
	storage.Object(d["backups"])["password"] = testRecovery
	storage.Object(d["schedule"])["enabled"] = true
	if _, _, e = s.Save(d, 0); e != nil {
		t.Fatal(e)
	}
	a := storage.Object(storage.Array(d["accounts"])[0])
	if e = s.SaveSession("test", storage.AccountBinding(a, d), Document{"api_user": "123", "cookies": []any{Document{"name": "session", "value": "local-test-only", "domain": "anyrouter.top", "path": "/", "expires": nil}}}); e != nil {
		t.Fatal(e)
	}
	m, e := New(s)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(m.Close)
	return s, m
}
func TestEncryptedBackupRoundTripAndRestorePolicy(t *testing.T) {
	s, m := fixture(t)
	created, e := m.Create(testRecovery, 7)
	if e != nil {
		t.Fatal(e)
	}
	path, e := m.Read(storage.String(created["id"]))
	if e != nil {
		t.Fatal(e)
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(data, []byte("local-test-value")) {
		t.Fatal("plaintext backup")
	}
	meta, e := Inspect(data, testRecovery)
	if e != nil || storage.Int(meta["accounts"]) != 1 {
		t.Fatal(meta, e)
	}
	preview, e := m.Preview(data, testRecovery, 1)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB.Exec("UPDATE web_security SET mode='passkey',revision=20,user_handle=? WHERE id=1; INSERT INTO web_passkeys VALUES ('current',?,'https://checkin.example','checkin.example','current device',10,1,1,1,?,NULL)", bytes.Repeat([]byte{5}, 32), []byte("local-test-public-key"), storage.Now()); e != nil {
		t.Fatal(e)
	}
	staged, e := m.PrepareRestore(storage.String(preview["ticket"]), 1)
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(staged)
	restored, e := storage.Open(staged, s.Key)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	config, revision, e := restored.Load()
	if e != nil || revision != 2 || storage.Bool(storage.Object(config["schedule"])["enabled"]) || storage.Bool(storage.Object(config["monitoring"])["enabled"]) {
		t.Fatal(config, revision, e)
	}
	var mode string
	var securityRevision int
	if e = restored.DB.QueryRow("SELECT mode,revision FROM web_security").Scan(&mode, &securityRevision); e != nil || mode != "passkey" || securityRevision != 21 {
		t.Fatal(mode, securityRevision, e)
	}
	var keyID string
	if e = restored.DB.QueryRow("SELECT id FROM web_passkeys").Scan(&keyID); e != nil || keyID != "current" {
		t.Fatal("current passkey not preserved", keyID, e)
	}
	if _, e = m.PrepareRestore(storage.String(preview["ticket"]), 1); e == nil {
		t.Fatal("preview reused")
	}
}
func TestBackupRejectsCorruptionAndUntrustedSchema(t *testing.T) {
	s, m := fixture(t)
	created, e := m.Create(testRecovery, 7)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := m.Read(storage.String(created["id"]))
	data, _ := os.ReadFile(p)
	if _, e = Inspect(data, "wrong password value"); e == nil {
		t.Fatal("wrong password accepted")
	}
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)-1] ^= 1
	if _, e = Inspect(tampered, testRecovery); e == nil {
		t.Fatal("tampered ciphertext accepted")
	}
	database, key, _, e := decode(data, testRecovery)
	if e != nil {
		t.Fatal(e)
	}
	staged, e := stage(t.TempDir(), database)
	if e != nil {
		t.Fatal(e)
	}
	db, e := sql.Open("sqlite", staged)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("CREATE TRIGGER bad AFTER INSERT ON config_archive BEGIN DELETE FROM web_passkeys; END"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	poison, _ := os.ReadFile(staged)
	encoded, e := encode(poison, key, testRecovery, storage.Now())
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Preview(encoded, testRecovery, 1); e == nil {
		t.Fatal("trigger in backup accepted")
	}
	if _, e = m.Read("../webui.sqlite3"); e == nil {
		t.Fatal("path traversal accepted")
	}
	if _, e = m.Preview(data, testRecovery, 2); e == nil {
		t.Fatal("stale configuration accepted")
	}
	if len(s.Key) != 32 {
		t.Fatal("fixture key")
	}
}

func TestOnlineRestoreReencryptsForeignMasterKey(t *testing.T) {
	_, source := fixture(t)
	created, e := source.Create(testRecovery, 7)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := source.Read(storage.String(created["id"]))
	data, _ := os.ReadFile(p)
	target, e := storage.Open(filepath.Join(t.TempDir(), "webui.sqlite3"), bytes.Repeat([]byte{9}, 32))
	if e != nil {
		t.Fatal(e)
	}
	defer target.Close()
	if _, e = target.DB.Exec(securitySchema); e != nil {
		t.Fatal(e)
	}
	if _, e = target.DB.Exec("INSERT INTO web_auth VALUES (1,?,?); INSERT INTO web_security VALUES (1,'password',4,?)", bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 64), bytes.Repeat([]byte{4}, 32)); e != nil {
		t.Fatal(e)
	}
	current := storage.DefaultConfig()
	current["webui_url"] = "https://checkin.example"
	if _, _, e = target.Save(current, 0); e != nil {
		t.Fatal(e)
	}
	m, e := New(target)
	if e != nil {
		t.Fatal(e)
	}
	defer m.Close()
	preview, e := m.Preview(data, testRecovery, 1)
	if e != nil {
		t.Fatal(e)
	}
	staged, e := m.PrepareRestore(storage.String(preview["ticket"]), 1)
	if e != nil {
		t.Fatal(e)
	}
	defer os.Remove(staged)
	restored, e := storage.Open(staged, target.Key)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	config, _, e := restored.Load()
	if e != nil || config["webui_url"] != "https://checkin.example" {
		t.Fatal("current URL not preserved", e)
	}
	a := storage.Object(storage.Array(config["accounts"])[0])
	session, e := restored.LoadSession("test", storage.AccountBinding(a, config))
	if e != nil || session["api_user"] != "123" {
		t.Fatal("foreign session key not reencrypted", e)
	}
	var salt []byte
	if e = restored.DB.QueryRow("SELECT salt FROM web_auth").Scan(&salt); e != nil || !bytes.Equal(salt, bytes.Repeat([]byte{2}, 16)) {
		t.Fatal("current password not preserved", e)
	}
}
func TestBackupRotationAndExpiredPreviews(t *testing.T) {
	_, m := fixture(t)
	for i := 0; i < 3; i++ {
		if _, e := m.Create(testRecovery, 2); e != nil {
			t.Fatal(e)
		}
	}
	items, e := m.List()
	if e != nil || len(items) != 2 {
		t.Fatal(len(items), e)
	}
	p, _ := m.Read(storage.String(items[0]["id"]))
	data, _ := os.ReadFile(p)
	preview, e := m.Preview(data, testRecovery, 1)
	if e != nil {
		t.Fatal(e)
	}
	ticket := storage.String(preview["ticket"])
	entry := m.previews[ticket]
	entry.Expires = time.Now().Add(-time.Second)
	m.previews[ticket] = entry
	if _, e = m.PrepareRestore(ticket, 1); e == nil {
		t.Fatal("expired preview accepted")
	}
	if _, e = os.Stat(entry.Path); !os.IsNotExist(e) {
		t.Fatal("expired staging file retained")
	}
}
func TestOfflineRestoreRefusesOverwriteAndReencrypts(t *testing.T) {
	_, m := fixture(t)
	created, e := m.Create(testRecovery, 7)
	if e != nil {
		t.Fatal(e)
	}
	p, _ := m.Read(storage.String(created["id"]))
	data, _ := os.ReadFile(p)
	root := t.TempDir()
	dataDir, keyFile := filepath.Join(root, "data"), filepath.Join(root, "keys", "master.key")
	meta, e := RestoreOffline(data, testRecovery, dataDir, keyFile)
	if e != nil || !storage.Bool(meta["automatic_tasks_disabled"]) {
		t.Fatal(meta, e)
	}
	key, _ := os.ReadFile(keyFile)
	s, e := storage.Open(filepath.Join(dataDir, "webui.sqlite3"), key)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	d, r, e := s.Load()
	if e != nil || r != 2 || storage.Bool(storage.Object(d["monitoring"])["enabled"]) {
		t.Fatal(r, e)
	}
	if _, e = RestoreOffline(data, testRecovery, dataDir, keyFile); e == nil {
		t.Fatal("offline overwrite accepted")
	}
}
func pythonInterpreter(t *testing.T) string {
	t.Helper()
	if configured := os.Getenv("CHECKIN_PYTHON_EXECUTABLE"); configured != "" {
		return configured
	}
	for _, p := range []string{filepath.Join("..", "..", ".venv", "Scripts", "python.exe"), filepath.Join("..", "..", ".venv", "bin", "python")} {
		if _, e := os.Stat(p); e == nil {
			abs, _ := filepath.Abs(p)
			return abs
		}
	}
	for _, name := range []string{"python3", "python"} {
		if p, e := exec.LookPath(name); e == nil {
			return p
		}
	}
	t.Skip("Python is unavailable for optional interoperability coverage")
	return ""
}
func TestPythonBidirectionalBackupCompatibility(t *testing.T) {
	s, m := fixture(t)
	created, e := m.Create(testRecovery, 7)
	if e != nil {
		t.Fatal(e)
	}
	goBackup, _ := m.Read(storage.String(created["id"]))
	python := pythonInterpreter(t)
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	check := exec.Command(python, "-c", "import cryptography")
	check.Dir = root
	if err := check.Run(); err != nil {
		t.Skip("Python cryptography is unavailable for optional interoperability coverage")
	}
	output := filepath.Join(t.TempDir(), "python.nab")
	script := `
import sys, pathlib, sqlite3, hmac
from server.backup import inspect_backup, _encode, _expected_schema
from server.config_store import ConfigStore, default_config
from server.http_session_store import HttpSessionStore
from utils.http_checkin import account_binding
go_path, destination, password, key_hex = sys.argv[1:]
assert inspect_backup(pathlib.Path(go_path).read_bytes(), password)['accounts'] == 1
key = bytes.fromhex(key_hex)
root = pathlib.Path(destination).parent
path = root / 'python.sqlite3'
db = sqlite3.connect(path)
for (kind, name), statement in _expected_schema(root).items():
    if kind == 'table': db.execute(statement)
db.execute('INSERT INTO web_auth VALUES (1,?,?)',(bytes(16),bytes(64)))
db.execute("INSERT INTO web_security VALUES (1,'password',1,?)",(bytes(32),))
db.commit(); db.close()
store = ConfigStore(path,key)
config = default_config()
config['accounts'] = [dict(id='test',name='test',provider='anyrouter',auth_type='password',enabled=True,username='local-test-user',password='local-test-value')]
store.save(config,0); store.close()
session = HttpSessionStore(path,hmac.digest(key,b'newapi-http-sessions-v1','sha256'))
session.save('test',account_binding(config['accounts'][0],config),dict(api_user='123',cookies=[]))
session.close()
import time
pathlib.Path(destination).write_bytes(_encode(path.read_bytes(),key,password,time.time()))
print('compatible')
`
	cmd := exec.Command(python, "-c", script, goBackup, output, testRecovery, hex.EncodeToString(s.Key))
	cmd.Dir = root
	out, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("Python compatibility failed: %v: %s", e, out)
	}
	if !strings.Contains(string(out), "compatible") {
		t.Fatal("Python compatibility did not finish")
	}
	data, e := os.ReadFile(output)
	if e != nil {
		t.Fatal(e)
	}
	meta, e := Inspect(data, testRecovery)
	if e != nil || storage.Int(meta["accounts"]) != 1 {
		t.Fatal(meta, e)
	}
	dataDir, keyFile := filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "master.key")
	if _, e = RestoreOffline(data, testRecovery, dataDir, keyFile); e != nil {
		t.Fatal(e)
	}
	key, _ := os.ReadFile(keyFile)
	restored, e := storage.Open(filepath.Join(dataDir, "webui.sqlite3"), key)
	if e != nil {
		t.Fatal(e)
	}
	defer restored.Close()
	config, _, e := restored.Load()
	if e != nil {
		t.Fatal(e)
	}
	a := storage.Object(storage.Array(config["accounts"])[0])
	session, e := restored.LoadSession("test", storage.AccountBinding(a, config))
	if e != nil || session["api_user"] != "123" {
		t.Fatal("Python session incompatible", session, e)
	}
}
