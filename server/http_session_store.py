"""Encrypted HTTP sessions, bound to an account and its current credential fingerprint."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.config_store import ConfigError

_AAD = b'anyrouter.server.http-session.v1:'
_MAX_STATE_BYTES = 1024 * 1024


def _identity(account_id: str, binding: str) -> tuple[str, bytes]:
	if any(
		not isinstance(value, str)
		or not value
		or len(value) > maximum
		or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
		for value, maximum in ((account_id, 128), (binding, 8192))
	):
		raise ConfigError('HTTP session account or binding is invalid')
	# Store only a digest of the binding, in case a caller supplies sensitive material.
	digest = hashlib.sha256(binding.encode('utf-8')).hexdigest()
	aad = _AAD + json.dumps([account_id, digest], separators=(',', ':')).encode('utf-8')
	return digest, aad


class HttpSessionStore:
	"""One authenticated-encrypted session per account; mismatches never delete old state."""

	def __init__(self, path: Path, key: bytes):
		if not isinstance(key, bytes) or len(key) != 32:
			raise ConfigError('The HTTP session encryption key must contain exactly 32 bytes')
		self.path = Path(path)
		self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
		if self.path.is_symlink():
			raise ConfigError('HTTP session database must not be a symbolic link')
		try:
			fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
		except FileExistsError:
			pass
		else:
			os.close(fd)
		os.chmod(self.path, 0o600)
		self._cipher = AESGCM(key)
		self._lock = threading.RLock()
		self._connection = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
		try:
			self._connection.execute('PRAGMA journal_mode=DELETE')
			self._connection.execute('PRAGMA busy_timeout=10000')
			self._connection.execute(
				'CREATE TABLE IF NOT EXISTS http_sessions ('
				'account_id TEXT PRIMARY KEY, binding_hash TEXT NOT NULL, document BLOB NOT NULL)'
			)
		except BaseException:
			self._connection.close()
			raise

	def load(self, account_id: str, binding: str) -> dict | None:
		digest, aad = _identity(account_id, binding)
		with self._lock:
			row = self._connection.execute(
				'SELECT binding_hash, document FROM http_sessions WHERE account_id = ?', (account_id,)
			).fetchone()
			if row is None or row[0] != digest:
				return None
			encrypted = row[1]
			if not isinstance(encrypted, bytes) or not 28 <= len(encrypted) <= _MAX_STATE_BYTES + 28:
				raise ConfigError('Stored HTTP session is invalid; update the account credentials')
			try:
				plaintext = self._cipher.decrypt(encrypted[:12], encrypted[12:], aad)
				state = json.loads(plaintext)
			except (InvalidTag, ValueError, OverflowError, RecursionError):
				raise ConfigError('HTTP session cannot be decrypted; verify the key or update credentials') from None
			if not isinstance(state, dict):
				raise ConfigError('Stored HTTP session is invalid; update the account credentials')
			return state

	def save(self, account_id: str, binding: str, state: dict) -> None:
		digest, aad = _identity(account_id, binding)
		if not isinstance(state, dict):
			raise ConfigError('HTTP session state must be an object')
		try:
			plaintext = json.dumps(state, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
		except (ValueError, TypeError, RecursionError, UnicodeError):
			raise ConfigError('HTTP session state has an invalid format') from None
		if len(plaintext) > _MAX_STATE_BYTES:
			raise ConfigError('HTTP session exceeds the maximum supported size')
		nonce = os.urandom(12)
		encrypted = nonce + self._cipher.encrypt(nonce, plaintext, aad)
		with self._lock:
			self._connection.execute('BEGIN IMMEDIATE')
			try:
				self._connection.execute(
					'INSERT INTO http_sessions (account_id, binding_hash, document) VALUES (?, ?, ?) '
					'ON CONFLICT(account_id) DO UPDATE SET binding_hash=excluded.binding_hash, document=excluded.document',
					(account_id, digest, encrypted),
				)
				self._connection.execute('COMMIT')
			except BaseException:
				self._connection.execute('ROLLBACK')
				raise

	def close(self) -> None:
		with self._lock:
			self._connection.close()
