"""HTTP session encryption, account binding, and fail-closed persistence tests."""

import hashlib
import json
import os
import sqlite3

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.config_store import ConfigError, ConfigStore, default_config
from server.http_session_store import HttpSessionStore


def test_sessions_share_config_database_without_plaintext_and_reopen(tmp_path):
	path, key = tmp_path / 'webui.sqlite3', os.urandom(32)
	config, sessions = ConfigStore(path, key), HttpSessionStore(path, key)
	state = {'cookies': {'session': 'synthetic-http-session'}, 'api_user': '7'}
	binding = 'synthetic-sensitive-binding'
	try:
		config.save(default_config(), 0)
		assert sessions.load('one', binding) is None
		sessions.save('one', binding, state)
		loaded = sessions.load('one', binding)
		assert loaded == state
		loaded['cookies']['session'] = 'changed-local-copy'
		assert sessions.load('one', binding) == state
		assert config.load() == (default_config(), 1)
	finally:
		sessions.close()
		config.close()
	for file in path.parent.iterdir():
		data = file.read_bytes()
		assert b'synthetic-http-session' not in data
		assert binding.encode() not in data
		assert key not in data
	reopened = HttpSessionStore(path, key)
	try:
		assert reopened.load('one', binding) == state
	finally:
		reopened.close()


def test_binding_mismatch_preserves_old_session_and_account_isolation(tmp_path):
	path, key = tmp_path / 'webui.sqlite3', os.urandom(32)
	store = HttpSessionStore(path, key)
	try:
		store.save('one', 'binding-a', {'session': 'synthetic-old'})
		with sqlite3.connect(path) as db:
			before = db.execute('SELECT * FROM http_sessions').fetchall()
		assert store.load('one', 'binding-b') is None
		assert store.load('two', 'binding-a') is None
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT * FROM http_sessions').fetchall() == before
		assert store.load('one', 'binding-a') == {'session': 'synthetic-old'}
		store.save('one', 'binding-b', {'session': 'synthetic-new'})
		assert store.load('one', 'binding-a') is None
		assert store.load('one', 'binding-b') == {'session': 'synthetic-new'}
	finally:
		store.close()


def test_wrong_key_and_tampered_ciphertext_fail_without_overwrite(tmp_path):
	path, key = tmp_path / 'webui.sqlite3', os.urandom(32)
	store = HttpSessionStore(path, key)
	store.save('one', 'binding', {'session': 'synthetic-secret'})
	wrong = HttpSessionStore(path, os.urandom(32))
	try:
		with pytest.raises(ConfigError, match='cannot be decrypted'):
			wrong.load('one', 'binding')
		assert store.load('one', 'binding') == {'session': 'synthetic-secret'}
		with sqlite3.connect(path) as db:
			blob = db.execute('SELECT document FROM http_sessions').fetchone()[0]
			corrupt = blob[:-1] + bytes([blob[-1] ^ 1])
			db.execute('UPDATE http_sessions SET document = ?', (corrupt,))
		for reader in (store, wrong):
			with pytest.raises(ConfigError, match='cannot be decrypted'):
				reader.load('one', 'binding')
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT document FROM http_sessions').fetchone()[0] == corrupt
	finally:
		wrong.close()
		store.close()


def test_ciphertext_cannot_be_copied_between_account_or_binding(tmp_path):
	path, key = tmp_path / 'webui.sqlite3', os.urandom(32)
	store = HttpSessionStore(path, key)
	try:
		store.save('one', 'binding-a', {'secret': 'synthetic-secret'})
		with sqlite3.connect(path) as db:
			blob = db.execute('SELECT document FROM http_sessions').fetchone()[0]
			db.execute(
				'INSERT INTO http_sessions VALUES (?, ?, ?)', ('two', hashlib.sha256(b'binding-a').hexdigest(), blob)
			)
		with pytest.raises(ConfigError):
			store.load('two', 'binding-a')
		with sqlite3.connect(path) as db:
			db.execute(
				'UPDATE http_sessions SET binding_hash = ? WHERE account_id = ?',
				(hashlib.sha256(b'binding-b').hexdigest(), 'one'),
			)
		with pytest.raises(ConfigError):
			store.load('one', 'binding-b')
	finally:
		store.close()


@pytest.mark.parametrize('state', [[], 'synthetic-secret', {'nan': float('nan')}, {'bad': object()}, {'bad': '\ud800'}])
def test_invalid_state_never_replaces_previous_session(tmp_path, state):
	store = HttpSessionStore(tmp_path / 'webui.sqlite3', os.urandom(32))
	try:
		store.save('one', 'binding', {'old': True})
		with pytest.raises(ConfigError):
			store.save('one', 'binding', state)
		assert store.load('one', 'binding') == {'old': True}
	finally:
		store.close()


@pytest.mark.parametrize(
	'account,binding',
	[
		('', 'binding'),
		('one', ''),
		('one\nheader', 'binding'),
		('one', 'bad\r\nheader'),
		(None, 'binding'),
		('one', None),
	],
)
def test_invalid_binding_is_rejected(tmp_path, account, binding):
	store = HttpSessionStore(tmp_path / 'webui.sqlite3', os.urandom(32))
	try:
		with pytest.raises(ConfigError):
			store.save(account, binding, {})
		with pytest.raises(ConfigError):
			store.load(account, binding)
	finally:
		store.close()


@pytest.mark.parametrize('plaintext', [b'[]', b'not json'])
def test_authenticated_but_invalid_state_fails_closed(tmp_path, plaintext):
	path, key = tmp_path / 'webui.sqlite3', os.urandom(32)
	store = HttpSessionStore(path, key)
	digest = hashlib.sha256(b'binding').hexdigest()
	aad = b'anyrouter.server.http-session.v1:' + json.dumps(['one', digest], separators=(',', ':')).encode()
	nonce = os.urandom(12)
	encrypted = nonce + AESGCM(key).encrypt(nonce, plaintext, aad)
	try:
		with sqlite3.connect(path) as db:
			db.execute('INSERT INTO http_sessions VALUES (?, ?, ?)', ('one', digest, encrypted))
		with pytest.raises(ConfigError):
			store.load('one', 'binding')
	finally:
		store.close()
