package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"

	"github.com/Fy1ng/CheckinMyFreeAPI/internal/platform"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

// This offline operator command is the explicit transition from a new local
// installation with no human password to an authenticated server deployment.
func setAdminPassword(c config) error {
	if !c.confirm {
		return errors.New("设置服务器管理密码需要先停止服务, 再使用 security set-password --confirm")
	}
	if e := platform.PrivateDir(c.launch.DataDir); e != nil {
		return e
	}
	leases := []*os.File{}
	defer func() {
		for _, lease := range leases {
			lease.Close()
		}
	}()
	for _, name := range []string{"service.lock", "execution.lock"} {
		lease, e := platform.Lock(filepath.Join(c.launch.DataDir, name))
		if e != nil {
			return e
		}
		leases = append(leases, lease)
	}
	path := filepath.Join(c.launch.DataDir, "webui.sqlite3")
	if e := platform.PrivateFile(path); e != nil {
		return e
	}
	if _, e := os.Stat(path); e != nil {
		return errors.New("数据库不存在")
	}
	password := ""
	if c.passwordFile != "" {
		value, e := readSecretFile(c.passwordFile)
		if e != nil {
			return e
		}
		password = value
	} else {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("请在交互终端输入新密码, 或使用 --password-file")
		}
		fmt.Fprint(os.Stderr, "新的服务器管理密码: ")
		first, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if e != nil {
			return e
		}
		fmt.Fprint(os.Stderr, "再次输入新密码: ")
		second, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if e != nil {
			return e
		}
		if string(first) != string(second) {
			return errors.New("两次密码不一致")
		}
		password = string(first)
	}
	if !utf8.ValidString(password) || len([]rune(password)) < 16 || len([]rune(password)) > 512 {
		return errors.New("管理密码需要16至512字符")
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return e
	}
	digest, e := scrypt.Key([]byte(password), salt, 16384, 8, 1, 64)
	if e != nil {
		return e
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return e
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	tx, e := db.Begin()
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var mode string
	var revision int64
	if e = tx.QueryRow("SELECT mode,revision FROM web_security WHERE id=1").Scan(&mode, &revision); e != nil || (mode != "password" && mode != "passkey") || revision < 1 || revision >= 9223372036854775807 {
		return errors.New("登录安全配置无效")
	}
	result, e := tx.Exec("UPDATE web_auth SET salt=?,digest=? WHERE id=1", salt, digest)
	if e != nil {
		return errors.New("无法更新管理员密码")
	}
	count, e := result.RowsAffected()
	if e != nil || count != 1 {
		return errors.New("管理员密码记录不存在")
	}
	if _, e = tx.Exec("UPDATE web_security SET revision=revision+1 WHERE id=1"); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	fmt.Println("已设置服务器管理密码, 已有认证模式与Passkey保持原值.")
	return nil
}
