package auth

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	_ "modernc.org/sqlite"
)

const testOrigin = "https://security.example.test"
const testPassword = "synthetic-Go-test-admin-password"

func newService(t *testing.T) (*Service, *sql.DB) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "test.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	s, err := New(db, Options{Password: testPassword, PublicOrigin: testOrigin, TrustedProxyIPs: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatal(err)
	}
	return s, db
}

type device struct {
	key     *ecdsa.PrivateKey
	id      []byte
	counter uint32
	flags   byte
}

func newDevice(t *testing.T) *device {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	_, _ = rand.Read(id)
	return &device{key: key, id: id, flags: 5}
}
func mapJSON(t *testing.T, v any) map[string]any {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err = json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func b64(v []byte) string { return base64.RawURLEncoding.EncodeToString(v) }
func (d *device) response(t *testing.T, options map[string]any, register bool, changes map[string]any) json.RawMessage {
	t.Helper()
	p := mapJSON(t, options["publicKey"])
	typ := "webauthn.get"
	if register {
		typ = "webauthn.create"
	}
	client := map[string]any{"type": typ, "challenge": p["challenge"], "origin": testOrigin, "crossOrigin": false}
	for k, v := range changes {
		if k != "userHandle" {
			client[k] = v
		}
	}
	clientData, err := json.Marshal(client)
	if err != nil {
		t.Fatal(err)
	}
	rp := sha256.Sum256([]byte("security.example.test"))
	authData := append([]byte{}, rp[:]...)
	flags := d.flags
	if register {
		flags |= 64
	}
	authData = append(authData, flags)
	counter := make([]byte, 4)
	binary.BigEndian.PutUint32(counter, d.counter)
	authData = append(authData, counter...)
	response := map[string]any{"clientDataJSON": b64(clientData)}
	if register {
		cose, err := cbor.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: d.key.PublicKey.X.FillBytes(make([]byte, 32)), -3: d.key.PublicKey.Y.FillBytes(make([]byte, 32))})
		if err != nil {
			t.Fatal(err)
		}
		authData = append(authData, make([]byte, 16)...)
		n := make([]byte, 2)
		binary.BigEndian.PutUint16(n, uint16(len(d.id)))
		authData = append(authData, n...)
		authData = append(authData, d.id...)
		authData = append(authData, cose...)
		att, err := cbor.Marshal(map[string]any{"fmt": "none", "authData": authData, "attStmt": map[string]any{}})
		if err != nil {
			t.Fatal(err)
		}
		response["attestationObject"] = b64(att)
		response["transports"] = []string{"internal"}
	} else {
		h := sha256.Sum256(clientData)
		signed := append(append([]byte{}, authData...), h[:]...)
		digest := sha256.Sum256(signed)
		signature, err := ecdsa.SignASN1(rand.Reader, d.key, digest[:])
		if err != nil {
			t.Fatal(err)
		}
		response["authenticatorData"], response["signature"], response["userHandle"] = b64(authData), b64(signature), nil
		if handle, ok := changes["userHandle"]; ok {
			response["userHandle"] = handle
		}
	}
	value, err := json.Marshal(map[string]any{"id": b64(d.id), "rawId": b64(d.id), "type": "public-key", "response": response, "clientExtensionResults": map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func registerDevice(t *testing.T, s *Service, d *device) string {
	t.Helper()
	options, err := s.begin("register", testOrigin, "session", "Synthetic device")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.complete("register", options["ticket"].(string), d.response(t, options, true, nil), testOrigin, "session")
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestCryptographicRegistrationAndAssertion(t *testing.T) {
	s, db := newService(t)
	d := newDevice(t)
	id := registerDevice(t, s, d)
	keys, err := readKeys(db, testOrigin)
	if err != nil || len(keys) != 1 || keys[0].Verified {
		t.Fatalf("new key must be unverified: %v", err)
	}
	p, _ := readPolicy(db)
	if p.Revision != 2 {
		t.Fatal("registration must increase security revision")
	}
	options, err := s.begin("reauth", testOrigin, "session", "")
	if err != nil {
		t.Fatal(err)
	}
	d.counter = 1
	actual, err := s.complete("reauth", options["ticket"].(string), d.response(t, options, false, map[string]any{"userHandle": b64(p.Handle)}), testOrigin, "session")
	if err != nil || actual != id {
		t.Fatalf("valid signed assertion rejected: %v", err)
	}
	keys, _ = readKeys(db, testOrigin)
	if !keys[0].Verified || keys[0].Counter != 1 {
		t.Fatal("verified assertion state not saved")
	}
	if _, err = s.complete("reauth", options["ticket"].(string), d.response(t, options, false, nil), testOrigin, "session"); err == nil {
		t.Fatal("challenge replay accepted")
	}
}

func TestRejectInvalidSignedAssertions(t *testing.T) {
	for _, name := range []string{"origin", "origin-case", "UV", "UP", "crossOrigin", "crossOrigin-null", "topOrigin", "userHandle", "emptyHandle", "counter", "signature", "backup-change", "invalid-backup", "binding", "revision", "expired", "rawID"} {
		t.Run(name, func(t *testing.T) {
			s, db := newService(t)
			d := newDevice(t)
			registerDevice(t, s, d)
			options, err := s.begin("login", testOrigin, "browser", "")
			if err != nil {
				t.Fatal(err)
			}
			d.counter = 1
			changes := map[string]any{}
			sessionBinding := "browser"
			switch name {
			case "origin":
				changes["origin"] = "https://attacker.example"
			case "origin-case":
				changes["origin"] = "https://SECURITY.example.test"
			case "UV":
				d.flags = 1
			case "UP":
				d.flags = 4
			case "crossOrigin":
				changes["crossOrigin"] = true
			case "crossOrigin-null":
				changes["crossOrigin"] = nil
			case "topOrigin":
				changes["topOrigin"] = testOrigin
			case "userHandle":
				changes["userHandle"] = b64([]byte("wrong"))
			case "emptyHandle":
				changes["userHandle"] = ""
			case "counter":
				_, _ = db.Exec("UPDATE web_passkeys SET counter=1")
			case "backup-change":
				d.flags |= 8
			case "invalid-backup":
				d.flags |= 16
			case "binding":
				sessionBinding = "other"
			case "revision":
				_, _ = db.Exec("UPDATE web_security SET revision=revision+1")
			case "expired":
				s.mu.Lock()
				pending := s.pending[options["ticket"].(string)]
				pending.Expires = time.Now().Add(-time.Second)
				s.pending[options["ticket"].(string)] = pending
				s.mu.Unlock()
			}
			response := d.response(t, options, false, changes)
			if name == "signature" || name == "rawID" {
				value := mapJSON(t, json.RawMessage(response))
				if name == "signature" {
					value["response"].(map[string]any)["signature"] = b64(make([]byte, 72))
				} else {
					value["rawId"] = b64([]byte("mismatch"))
				}
				response, _ = json.Marshal(value)
			}
			if _, err = s.complete("login", options["ticket"].(string), response, testOrigin, sessionBinding); err == nil {
				t.Fatal("invalid assertion accepted")
			}
			if _, err = s.complete("login", options["ticket"].(string), d.response(t, options, false, nil), testOrigin, "browser"); err == nil {
				t.Fatal("failed challenge was reusable")
			}
		})
	}
}

func authRequest(t *testing.T, s *Service, method, path string, value any, cookies []*http.Cookie, csrf string) *httptest.ResponseRecorder {
	t.Helper()
	data, _ := json.Marshal(value)
	r := httptest.NewRequest(method, testOrigin+path, bytes.NewReader(data))
	r.Header.Set("Origin", testOrigin)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", csrf)
	r.RemoteAddr = "127.0.0.1:54321"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	mux := http.NewServeMux()
	s.Register(mux)
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })
	w := httptest.NewRecorder()
	s.Guard(mux).ServeHTTP(w, r)
	return w
}
func decodeResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var b map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestHTTPPasswordCSRFAndModePolicy(t *testing.T) {
	s, db := newService(t)
	w := authRequest(t, s, "GET", "/api/config", nil, nil, "")
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	w = authRequest(t, s, "POST", "/api/login", map[string]any{"password": testPassword}, nil, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	result := decodeResponse(t, w)
	cookies := w.Result().Cookies()
	csrf := result["csrf"].(string)
	for _, c := range cookies {
		if c.Name == sessionCookie && (!c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/") {
			t.Fatal("unsafe session cookie")
		}
	}
	w = authRequest(t, s, "POST", "/api/security/reauth", map[string]any{"password": testPassword}, cookies, "")
	if w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	w = authRequest(t, s, "POST", "/api/security/reauth", map[string]any{"password": testPassword}, cookies, csrf)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	_, _ = db.Exec("UPDATE web_security SET mode='passkey',revision=revision+1")
	w = authRequest(t, s, "POST", "/api/login", map[string]any{"password": testPassword}, nil, "")
	if w.Code != 403 {
		t.Fatal("public password bypass", w.Code)
	}
	w = authRequest(t, s, "GET", "/api/config", nil, cookies, "")
	if w.Code != 401 {
		t.Fatal("security revision did not revoke session", w.Code)
	}
	w = authRequest(t, s, "GET", "/api/session", nil, nil, "")
	result = decodeResponse(t, w)
	if result["password_login_allowed"] != false || result["reauth_method"] != "passkey" {
		t.Fatal("unsafe advertised policy")
	}
}

func TestProofBoundSingleUseAndRevision(t *testing.T) {
	s, db := newService(t)
	login := authRequest(t, s, "POST", "/api/login", map[string]any{"password": testPassword}, nil, "")
	cookies := login.Result().Cookies()
	r := httptest.NewRequest("POST", testOrigin+"/api/security/mode", nil)
	r.RemoteAddr = "127.0.0.1:12"
	for _, c := range cookies {
		r.AddCookie(c)
	}
	token, err := s.issueProof(r, "password", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConsumeReauth(r, token, false); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConsumeReauth(r, token, false); err == nil {
		t.Fatal("proof replay")
	}
	token, _ = s.issueProof(r, "password", "")
	if _, err = s.ConsumeReauth(r, token, true); err == nil {
		t.Fatal("password proof used as passkey")
	}
	token, _ = s.issueProof(r, "password", "")
	_, _ = db.Exec("UPDATE web_security SET revision=revision+1")
	if _, err = s.ConsumeReauth(r, token, false); err == nil {
		t.Fatal("outdated proof accepted")
	}
}

func TestAccessRejectsSpoofedRecovery(t *testing.T) {
	a, err := NewAccess(testOrigin, []string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, target, peer, header, value string
		allowOrigin, allowRecovery        bool
	}{
		{"direct-public", testOrigin, "192.0.2.1:42", "", "", false, false},
		{"proxy-public", testOrigin, "127.0.0.1:42", "X-Forwarded-Proto", "https", true, false},
		{"untrusted-proxy", testOrigin, "192.0.2.1:42", "X-Forwarded-Proto", "https", false, false},
		{"local", "http://127.0.0.1:8765", "127.0.0.1:42", "", "", true, true},
		{"spoofed-local", "http://127.0.0.1:8765", "192.0.2.1:42", "", "", true, false},
		{"forwarded-local", "http://localhost:8765", "127.0.0.1:42", "X-Forwarded-Proto", "http", true, false},
		{"foreign-host", "http://attacker.example", "127.0.0.1:42", "", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tc.target, nil)
			r.TLS = nil
			r.RemoteAddr = tc.peer
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			origin, err := a.Origin(r)
			if (err == nil) != tc.allowOrigin {
				t.Fatalf("origin result: %v", err)
			}
			if a.PrivateRecovery(r, origin) != tc.allowRecovery {
				t.Fatal("recovery boundary")
			}
		})
	}
	for _, value := range []string{"http://admin.example", "https://admin.example/path", "https://user:pass@admin.example", "https://localhost", "https://admin.example:0", "https://admin.example\\evil"} {
		if _, err := NewAccess(value, nil); err == nil {
			t.Fatalf("invalid origin accepted: %s", value)
		}
	}
}

func TestPasswordRateLimit(t *testing.T) {
	s, _ := newService(t)
	for i := 0; i < 5; i++ {
		w := authRequest(t, s, "POST", "/api/login", map[string]any{"password": "wrong"}, nil, "")
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	w := authRequest(t, s, "POST", "/api/login", map[string]any{"password": testPassword}, nil, "")
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("missing login rate limit")
	}
}

func TestPythonPasswordCompatibility(t *testing.T) {
	python, err := exec.LookPath("python")
	if err != nil {
		t.Skip("Python is optional for cross-runtime fixture")
	}
	path := filepath.Join(t.TempDir(), "python.sqlite3")
	program := `import sqlite3,hashlib,sys
db=sqlite3.connect(sys.argv[1])
db.execute('CREATE TABLE web_auth(id INTEGER PRIMARY KEY CHECK(id=1),salt BLOB NOT NULL,digest BLOB NOT NULL)')
salt=bytes(range(16));db.execute('INSERT INTO web_auth VALUES(1,?,?)',(salt,hashlib.scrypt(b'synthetic-Go-test-admin-password',salt=salt,n=16384,r=8,p=1)))
db.commit();db.close()`
	if output, err := exec.Command(python, "-c", program, path).CombinedOutput(); err != nil {
		t.Fatalf("Python fixture: %v %s", err, output)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err := New(db, Options{PublicOrigin: testOrigin})
	if err != nil {
		t.Fatal(err)
	}
	w := authRequest(t, s, "POST", "/api/login", map[string]any{"password": testPassword}, nil, "")
	if w.Code != 200 {
		t.Fatal("Python scrypt digest rejected", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), testPassword) {
		t.Fatal("password leaked")
	}
}

func TestHTTPPasskeyLifecycleAndLastKeyProtection(t *testing.T) {
	s, _ := newService(t)
	d := newDevice(t)
	login := authRequest(t, s, "POST", "/api/login", map[string]any{"password": testPassword}, nil, "")
	if login.Code != 200 {
		t.Fatal(login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	csrf := decodeResponse(t, login)["csrf"].(string)
	call := func(method, path string, data any) map[string]any {
		t.Helper()
		w := authRequest(t, s, method, path, data, cookies, csrf)
		if w.Code != 200 {
			t.Fatalf("%s: HTTP %d %s", path, w.Code, w.Body.String())
		}
		result := decodeResponse(t, w)
		if token, ok := result["csrf"].(string); ok {
			csrf = token
			cookies = w.Result().Cookies()
		}
		return result
	}
	proof := call("POST", "/api/security/reauth", map[string]any{"password": testPassword})["reauth_token"]
	options := call("POST", "/api/security/register/options", map[string]any{"label": "Synthetic HTTP device", "reauth_token": proof})
	registered := call("POST", "/api/security/register/verify", map[string]any{"ticket": options["ticket"], "credential": d.response(t, options, true, nil)})
	id := registered["credential_id"].(string)
	assertionProof := func() string {
		t.Helper()
		options := call("POST", "/api/security/reauth/options", map[string]any{})
		d.counter++
		return call("POST", "/api/security/reauth/verify", map[string]any{"ticket": options["ticket"], "credential": d.response(t, options, false, nil)})["reauth_token"].(string)
	}
	info := call("GET", "/api/security", nil)
	if info["passkey_available"] != false {
		t.Fatal("unverified registration advertised as available")
	}
	proof = assertionProof()
	info = call("GET", "/api/security", nil)
	if info["passkey_available"] != true {
		t.Fatal("successful assertion did not verify registration")
	}
	call("POST", "/api/security/mode", map[string]any{"mode": "passkey", "revision": info["revision"], "reauth_token": proof})
	if w := authRequest(t, s, "POST", "/api/login", map[string]any{"password": testPassword}, nil, ""); w.Code != 403 {
		t.Fatal("Passkey mode public password bypass")
	}
	info = call("GET", "/api/security", nil)
	proof = assertionProof()
	w := authRequest(t, s, "DELETE", "/api/security/passkeys/"+id, map[string]any{"revision": info["revision"], "reauth_token": proof}, cookies, csrf)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "最后") {
		t.Fatal("last verified key deletion permitted", w.Code, w.Body.String())
	}
	proof = assertionProof()
	call("POST", "/api/security/mode", map[string]any{"mode": "password", "revision": info["revision"], "reauth_token": proof})
	info = call("GET", "/api/security", nil)
	proof = call("POST", "/api/security/reauth", map[string]any{"password": testPassword})["reauth_token"]
	call("DELETE", "/api/security/passkeys/"+id, map[string]any{"revision": info["revision"], "reauth_token": proof})
	info = call("GET", "/api/security", nil)
	if len(info["passkeys"].([]any)) != 0 {
		t.Fatal("key deletion not persisted")
	}
}

func TestGoCredentialAndAssertionReadableByPythonFIDO2(t *testing.T) {
	python := filepath.Join("..", "..", ".venv", "Scripts", "python.exe")
	if _, err := exec.LookPath(python); err != nil {
		python = filepath.Join("..", "..", ".venv", "bin", "python")
		if _, err = exec.LookPath(python); err != nil {
			t.Skip("optional Python FIDO2 environment not available")
		}
	}
	s, db := newService(t)
	d := newDevice(t)
	registerDevice(t, s, d)
	options, err := s.begin("login", testOrigin, "browser", "")
	if err != nil {
		t.Fatal(err)
	}
	d.counter = 1
	response := d.response(t, options, false, nil)
	keys, err := readKeys(db, testOrigin)
	if err != nil {
		t.Fatal(err)
	}
	input, err := json.Marshal(map[string]any{"credential": b64(keys[0].Data), "response": json.RawMessage(response), "challenge": mapJSON(t, options["publicKey"])["challenge"]})
	if err != nil {
		t.Fatal(err)
	}
	program := `import json,sys
from fido2.webauthn import AttestedCredentialData,PublicKeyCredentialRpEntity
from fido2.server import Fido2Server
from fido2.utils import websafe_decode
d=json.load(sys.stdin)
credential=AttestedCredentialData(websafe_decode(d['credential']))
server=Fido2Server(PublicKeyCredentialRpEntity(id='security.example.test',name='Test'),verify_origin=lambda origin: origin=='https://security.example.test')
matched=server.authenticate_complete({'challenge':d['challenge'],'user_verification':'required'},[credential],d['response'])
assert matched.credential_id==credential.credential_id
print('verified')`
	command := exec.Command(python, "-c", program)
	command.Stdin = bytes.NewReader(input)
	out, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(out)) != "verified" {
		t.Fatalf("Python FIDO2 interoperation failed: %v %s", err, out)
	}
}

func TestPythonFIDO2CreatedPasskeyUsableWithoutReregistration(t *testing.T) {
	python := filepath.Join("..", "..", ".venv", "Scripts", "python.exe")
	if _, err := exec.LookPath(python); err != nil {
		python = filepath.Join("..", "..", ".venv", "bin", "python")
		if _, err = exec.LookPath(python); err != nil {
			t.Skip("optional Python FIDO2 environment not available")
		}
	}
	program := `import json,secrets
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData
from fido2.utils import websafe_encode
key=ec.generate_private_key(ec.SECP256R1())
credential=AttestedCredentialData.create(bytes(16),secrets.token_bytes(32),ES256.from_cryptography_key(key.public_key()))
print(json.dumps({'credential':websafe_encode(bytes(credential)),'id':websafe_encode(credential.credential_id),'d':websafe_encode(key.private_numbers().private_value.to_bytes(32,'big'))}))`
	out, err := exec.Command(python, "-c", program).CombinedOutput()
	if err != nil {
		t.Fatal("Python synthetic key fixture failed", err)
	}
	var fixture map[string]string
	if json.Unmarshal(out, &fixture) != nil {
		t.Fatal("Python synthetic key fixture format")
	}
	decode := func(name string) []byte {
		t.Helper()
		b, err := base64.RawURLEncoding.DecodeString(fixture[name])
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	s, db := newService(t)
	_, err = db.Exec("INSERT INTO web_passkeys VALUES(?,?,?,?,?,?,?,?,?,?,NULL)", fixture["id"], decode("credential"), testOrigin, "security.example.test", "Python existing device", 7, 0, 0, 1, float64(time.Now().Unix()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("UPDATE web_security SET mode='passkey',revision=revision+1"); err != nil {
		t.Fatal(err)
	}
	// A new runtime instance must keep the existing mode, password and public key.
	s, err = New(db, Options{PublicOrigin: testOrigin})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := readPolicy(db)
	if p.Mode != "passkey" {
		t.Fatal("existing Passkey mode was changed")
	}
	scalar := decode("d")
	x, y := elliptic.P256().ScalarBaseMult(scalar)
	d := &device{key: &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: new(big.Int).SetBytes(scalar)}, id: decode("id"), counter: 8, flags: 5}
	options, err := s.begin("login", testOrigin, "browser", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.complete("login", options["ticket"].(string), d.response(t, options, false, nil), testOrigin, "browser"); err != nil {
		t.Fatal("existing Python key rejected", err)
	}
	keys, err := readKeys(db, testOrigin)
	if err != nil || len(keys) != 1 || keys[0].Counter != 8 {
		t.Fatal("existing key assertion counter not preserved")
	}
}
