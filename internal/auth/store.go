package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"golang.org/x/crypto/scrypt"
)

const schema = `CREATE TABLE IF NOT EXISTS web_auth (id INTEGER PRIMARY KEY CHECK(id=1), salt BLOB NOT NULL, digest BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS web_security ( id INTEGER PRIMARY KEY CHECK(id=1), mode TEXT NOT NULL, revision INTEGER NOT NULL, user_handle BLOB NOT NULL );
CREATE TABLE IF NOT EXISTS web_passkeys ( id TEXT PRIMARY KEY, credential BLOB NOT NULL, origin TEXT NOT NULL, rp_id TEXT NOT NULL, label TEXT NOT NULL, counter INTEGER NOT NULL, backup_eligible INTEGER NOT NULL, backed_up INTEGER NOT NULL, verified INTEGER NOT NULL, created_at REAL NOT NULL, last_used_at REAL );`

type Policy struct {
	Mode     string
	Revision int64
	Handle   []byte
}

type keyRecord struct {
	ID, Origin, RPID, Label            string
	Data                               []byte
	Counter                            uint32
	BackupEligible, BackedUp, Verified bool
	Created                            float64
	Last                               sql.NullFloat64
}

func initialize(db *sql.DB, password string) error {
	if _, err := db.Exec(schema); err != nil {
		return err
	}
	var count int
	if err := db.QueryRow("SELECT count(*) FROM web_auth WHERE id=1").Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		if len([]rune(password)) < 16 || len([]rune(password)) > 512 {
			return errors.New("首次启动需要设置 16 到 512 字符的 WebUI 密码")
		}
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return err
		}
		digest, err := scrypt.Key([]byte(password), salt, 16384, 8, 1, 64)
		if err != nil {
			return err
		}
		if _, err = db.Exec("INSERT OR IGNORE INTO web_auth VALUES (1,?,?)", salt, digest); err != nil {
			return err
		}
	}
	handle := make([]byte, 32)
	if _, err := rand.Read(handle); err != nil {
		return err
	}
	_, err := db.Exec("INSERT OR IGNORE INTO web_security VALUES (1,'password',1,?)", handle)
	return err
}

func readPolicy(db *sql.DB) (Policy, error) {
	var p Policy
	err := db.QueryRow("SELECT mode,revision,user_handle FROM web_security WHERE id=1").Scan(&p.Mode, &p.Revision, &p.Handle)
	if err != nil {
		return p, err
	}
	if (p.Mode != "password" && p.Mode != "passkey") || p.Revision < 1 || p.Revision == math.MaxInt64 || len(p.Handle) != 32 {
		return p, failure(503, "登录安全配置无效, 请通过 SSH 恢复")
	}
	return p, nil
}

func readKeys(db *sql.DB, origin string) ([]keyRecord, error) {
	rows, err := db.Query("SELECT id,credential,origin,rp_id,label,counter,backup_eligible,backed_up,verified,created_at,last_used_at FROM web_passkeys WHERE origin=? ORDER BY created_at", origin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []keyRecord{}
	for rows.Next() {
		var k keyRecord
		var counter int64
		var be, bs, v int
		if err = rows.Scan(&k.ID, &k.Data, &k.Origin, &k.RPID, &k.Label, &counter, &be, &bs, &v, &k.Created, &k.Last); err != nil {
			return nil, err
		}
		if counter < 0 || counter > math.MaxUint32 || (be != 0 && be != 1) || (bs != 0 && bs != 1) || (v != 0 && v != 1) || bs > be {
			return nil, failure(503, "Passkey 存储数据无效, 请通过 SSH 恢复")
		}
		k.Counter = uint32(counter)
		k.BackupEligible = be == 1
		k.BackedUp = bs == 1
		k.Verified = v == 1
		result = append(result, k)
	}
	return result, rows.Err()
}

// Python FIDO2 stores the W3C attested credential byte sequence. Preserve that
// format, so neither runtime rewrites public keys during migration. MDS attestation
// re-verification is deliberately not configured: old records lack that evidence.
func (k keyRecord) credential() (webauthn.Credential, error) {
	if len(k.Data) < 19 {
		return webauthn.Credential{}, failure(503, "Passkey 存储数据无效")
	}
	n := int(binary.BigEndian.Uint16(k.Data[16:18]))
	if n < 1 || n > 1024 || len(k.Data) <= 18+n {
		return webauthn.Credential{}, failure(503, "Passkey 存储数据无效")
	}
	id := k.Data[18 : 18+n]
	if base64.RawURLEncoding.EncodeToString(id) != k.ID {
		return webauthn.Credential{}, failure(503, "Passkey 标识不匹配")
	}
	flags := protocol.FlagUserPresent | protocol.FlagUserVerified
	if k.BackupEligible {
		flags |= protocol.FlagBackupEligible
	}
	if k.BackedUp {
		flags |= protocol.FlagBackupState
	}
	return webauthn.Credential{ID: id, PublicKey: k.Data[18+n:], AttestationType: "none", AttestationFormat: "none", Flags: webauthn.NewCredentialFlags(flags), Authenticator: webauthn.Authenticator{AAGUID: k.Data[:16], SignCount: k.Counter}}, nil
}

func encodeCredential(c *webauthn.Credential) ([]byte, error) {
	if len(c.Authenticator.AAGUID) != 16 || len(c.ID) < 1 || len(c.ID) > 1024 || len(c.PublicKey) == 0 {
		return nil, failure(400, "Passkey 注册结果无效")
	}
	b := make([]byte, 18, 18+len(c.ID)+len(c.PublicKey))
	copy(b, c.Authenticator.AAGUID)
	binary.BigEndian.PutUint16(b[16:18], uint16(len(c.ID)))
	b = append(b, c.ID...)
	b = append(b, c.PublicKey...)
	return b, nil
}

func addKey(db *sql.DB, origin, rpid, label string, c *webauthn.Credential) (string, error) {
	data, err := encodeCredential(c)
	if err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(c.ID)
	tx, err := db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRow("SELECT count(*) FROM web_passkeys").Scan(&count); err != nil {
		return "", err
	}
	if count >= 10 {
		return "", failure(400, "最多保存 10 个 Passkey")
	}
	if _, err = tx.Exec("INSERT INTO web_passkeys VALUES (?,?,?,?,?,?,?,?,?,?,NULL)", id, data, origin, rpid, label, c.Authenticator.SignCount, c.Flags.BackupEligible, c.Flags.BackupState, 0, float64(time.Now().UnixMilli())/1000); err != nil {
		return "", failure(400, "此 Passkey 已注册或保存失败")
	}
	if _, err = tx.Exec("UPDATE web_security SET revision=revision+1 WHERE id=1"); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func recordAssertion(db *sql.DB, origin string, c *webauthn.Credential, previous keyRecord) error {
	if c.Authenticator.CloneWarning || ((c.Authenticator.SignCount != 0 || previous.Counter != 0) && c.Authenticator.SignCount <= previous.Counter) {
		return failure(400, "Passkey 签名计数器异常, 请使用其他密钥")
	}
	if c.Flags.BackupEligible != previous.BackupEligible || (c.Flags.BackupState && !c.Flags.BackupEligible) {
		return failure(400, "Passkey 状态校验失败")
	}
	res, err := db.Exec("UPDATE web_passkeys SET counter=?,backed_up=?,verified=1,last_used_at=? WHERE id=? AND origin=? AND counter=?", c.Authenticator.SignCount, c.Flags.BackupState, float64(time.Now().UnixMilli())/1000, previous.ID, origin, previous.Counter)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return failure(409, "Passkey 状态已更新, 请重新验证")
	}
	return nil
}

func timestamp(v float64) string {
	return time.UnixMilli(int64(v * 1000)).UTC().Format(time.RFC3339Nano)
}

// Reset must be called only after the caller acquires the exclusive instance lock.
func Reset(db *sql.DB, clear bool) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("UPDATE web_security SET mode='password',revision=revision+1 WHERE id=1"); err != nil {
		return err
	}
	if clear {
		if _, err = tx.Exec("DELETE FROM web_passkeys"); err != nil {
			return err
		}
	}
	return tx.Commit()
}
