"""Password-encrypted, self-contained SQLite backups with staged, explicit restore.

The live database and master key are never replaced here. The application owns
its maintenance lock and closes live connections before installing a prepared
database. A restore into the same instance re-encrypts secrets under its current
master key and keeps its current administrator credentials and public URL.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import stat
import struct
import tempfile
import time
from contextlib import closing
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.config_store import ConfigError, ConfigStore, validate_config
from utils.secure_state import atomic_write

MAX_BACKUP_BYTES = 64 * 1024 * 1024
MAGIC = b'NEWAPI-BACKUP\x00\x01'
_AAD = b'newapi.password-backup.v1'
_CONFIG_AAD = b'anyrouter.server.configuration.v1:'
_SESSION_AAD = b'anyrouter.server.http-session.v1:'
_SESSION_PURPOSE = b'newapi-http-sessions-v1'
_BACKUP_NAME = re.compile(r'backup-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{16}\.nab')
_STAGED_NAME = re.compile(r'\.restore-preview-[0-9a-f]{32}\.sqlite3')
_MAX_PREVIEWS = 4
_PREVIEW_SECONDS = 600


class BackupError(ConfigError):
	"""A credential-free error safe to return from the authenticated WebUI."""


def validate_recovery_password(password: object) -> str:
	if (
		not isinstance(password, str)
		or not 16 <= len(password) <= 512
		or any(0xD800 <= ord(char) <= 0xDFFF for char in password)
	):
		raise BackupError('备份恢复密码需要 16 到 512 个字符')
	return password


def _derive(password: str, salt: bytes) -> bytes:
	return hashlib.scrypt(password.encode('utf-8'), salt=salt, n=16384, r=8, p=1, dklen=32, maxmem=64 * 1024 * 1024)


def _stamp(timestamp: float) -> str:
	return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()


def _private_file(path: Path) -> None:
	if path.is_symlink() or not path.is_file():
		raise BackupError('备份文件不可用')
	if not stat.S_ISREG(path.stat().st_mode):
		raise BackupError('备份文件不可用')


def _open_readonly(path: Path) -> sqlite3.Connection:
	_private_file(path)
	if path.stat().st_size > MAX_BACKUP_BYTES or path.stat().st_size < 100:
		raise BackupError('备份数据库大小无效')
	db = sqlite3.connect(path.resolve().as_uri() + '?mode=ro&immutable=1', uri=True, timeout=2)
	db.execute('PRAGMA trusted_schema=OFF')
	db.execute('PRAGMA query_only=ON')
	deadline = time.monotonic() + 10
	db.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
	return db


def _normalized(sql: str | None) -> str | None:
	return ' '.join(sql.lower().split()) if sql else None


def _schema(db: sqlite3.Connection) -> dict[tuple[str, str], str | None]:
	return {(kind, name): _normalized(sql) for kind, name, sql in db.execute('SELECT type,name,sql FROM sqlite_master')}


@lru_cache(maxsize=4)
def _expected_schema(scratch_parent: Path) -> dict[tuple[str, str], str | None]:
	"""Build a schema from installed code, never from uploaded backup metadata."""
	from server.automation_store import AutomationStore
	from server.backup_runtime import BackupRuntime
	from server.balance_store import BalanceStore
	from server.execution_state import ExecutionState
	from server.http_session_store import HttpSessionStore
	from server.jobs import JobManager
	from server.passkeys import SecurityStore

	with tempfile.TemporaryDirectory(prefix='.backup-schema-', dir=scratch_parent) as directory:
		root, key = Path(directory), secrets.token_bytes(32)
		store = ConfigStore(root / 'webui.sqlite3', key)
		manager = JobManager(store, root, key)
		balances = BalanceStore(root / 'webui.sqlite3')
		automation = AutomationStore(root / 'webui.sqlite3')
		attention = ExecutionState(root / 'webui.sqlite3')
		sessions = HttpSessionStore(root / 'webui.sqlite3', hmac.digest(key, _SESSION_PURPOSE, 'sha256'))
		backups = BackupRuntime(store, root, key, manager)
		security = SecurityStore(root / 'webui.sqlite3')
		try:
			# New optional services create their own tables when taking a cached snapshot.
			if hasattr(manager, 'automation_snapshot'):
				manager.automation_snapshot()
			manager.db.execute(
				'CREATE TABLE IF NOT EXISTS web_auth (id INTEGER PRIMARY KEY CHECK(id=1), salt BLOB NOT NULL, digest BLOB NOT NULL)'
			)
			manager.db.commit()
			return _schema(manager.db)
		finally:
			security.close()
			backups.manager.close()
			backups.db.close()
			automation.close()
			sessions.close()
			attention.close()
			balances.close()
			manager.db.close()
			if manager._instance_lock:
				manager._instance_lock.close()
			store.close()


def _plain(cipher: AESGCM, encrypted: object, aad: bytes) -> bytes:
	if not isinstance(encrypted, bytes) or not 28 <= len(encrypted) <= 1024 * 1024 + 28:
		raise BackupError('备份中的加密数据无效')
	try:
		return cipher.decrypt(encrypted[:12], encrypted[12:], aad)
	except (InvalidTag, ValueError, OverflowError):
		raise BackupError('备份中的加密数据无法校验') from None


def _encrypted(cipher: AESGCM, plaintext: bytes, aad: bytes) -> bytes:
	nonce = secrets.token_bytes(12)
	return nonce + cipher.encrypt(nonce, plaintext, aad)


def _configuration(db: sqlite3.Connection, key: bytes) -> tuple[dict, int]:
	row = db.execute('SELECT revision,document FROM config WHERE id=1').fetchone()
	if row is None or type(row[0]) is not int or not 0 < row[0] < 2**63 - 1:
		raise BackupError('备份需要有效的已保存配置')
	try:
		config = json.loads(_plain(AESGCM(key), row[1], _CONFIG_AAD + str(row[0]).encode()))
		if not isinstance(config, dict) or config.get('schema_version') != 2:
			raise BackupError('备份配置版本不受支持')
		return validate_config(config), row[0]
	except BackupError:
		raise
	except (ValueError, TypeError, RecursionError):
		raise BackupError('备份配置校验失败') from None


def _validate_database(path: Path, key: bytes) -> tuple[dict, int, dict]:
	try:
		with closing(_open_readonly(path)) as db:
			if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
				raise BackupError('备份数据库完整性校验失败')
			if (
				db.execute('PRAGMA page_count').fetchone()[0] * db.execute('PRAGMA page_size').fetchone()[0]
				> MAX_BACKUP_BYTES
			):
				raise BackupError('备份数据库超出大小限制')
			expected = _expected_schema(path.parent)
			actual = _schema(db)
			for identity, sql in actual.items():
				if identity[0] in {'trigger', 'view'} or identity not in expected or sql != expected[identity]:
					raise BackupError('备份包含未知或不兼容的数据库结构')
			if not {('table', 'config'), ('table', 'web_auth')} <= actual.keys():
				raise BackupError('备份缺少必要的数据表')
			auth = db.execute('SELECT id,salt,digest FROM web_auth').fetchall()
			if (
				len(auth) != 1
				or auth[0][0] != 1
				or not isinstance(auth[0][1], bytes)
				or len(auth[0][1]) != 16
				or not isinstance(auth[0][2], bytes)
				or len(auth[0][2]) != 64
			):
				raise BackupError('备份管理员凭据无效')
			config, revision = _configuration(db, key)
			cipher = AESGCM(key)
			if ('table', 'config_archive') in actual:
				for source_revision, document in db.execute('SELECT source_revision,document FROM config_archive'):
					if type(source_revision) is not int or not 0 < source_revision < 2**63:
						raise BackupError('备份配置归档无效')
					json.loads(_plain(cipher, document, _CONFIG_AAD + str(source_revision).encode()))
			if ('table', 'http_sessions') in actual:
				session_cipher = AESGCM(hmac.digest(key, _SESSION_PURPOSE, 'sha256'))
				for account_id, binding_hash, document in db.execute(
					'SELECT account_id,binding_hash,document FROM http_sessions'
				):
					if (
						not isinstance(account_id, str)
						or len(account_id) > 128
						or not isinstance(binding_hash, str)
						or not re.fullmatch('[0-9a-f]{64}', binding_hash)
					):
						raise BackupError('备份会话标识无效')
					aad = _SESSION_AAD + json.dumps([account_id, binding_hash], separators=(',', ':')).encode()
					if not isinstance(json.loads(_plain(session_cipher, document, aad)), dict):
						raise BackupError('备份会话无效')
			counts = {
				'accounts': len(config['accounts']),
				'runs': db.execute('SELECT count(*) FROM runs').fetchone()[0] if ('table', 'runs') in actual else 0,
			}
			return config, revision, counts
	except BackupError:
		raise
	except (sqlite3.Error, ValueError, TypeError, RecursionError, OverflowError):
		raise BackupError('备份数据库校验失败') from None


def _encode(database: bytes, key: bytes, password: str, created_at: float) -> bytes:
	metadata = json.dumps(
		{
			'version': 1,
			'created_at': created_at,
			'master_key': base64.b64encode(key).decode(),
			'database_sha256': hashlib.sha256(database).hexdigest(),
			'database_length': len(database),
		},
		separators=(',', ':'),
		allow_nan=False,
	).encode()
	salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
	plaintext = struct.pack('>I', len(metadata)) + metadata + database
	result = MAGIC + salt + nonce + AESGCM(_derive(password, salt)).encrypt(nonce, plaintext, _AAD)
	if len(result) > MAX_BACKUP_BYTES:
		raise BackupError('备份文件超出 64 MiB 限制')
	return result


def _decode(data: bytes, password: str) -> tuple[bytes, bytes, dict]:
	validate_recovery_password(password)
	if not isinstance(data, bytes) or not len(MAGIC) + 48 < len(data) <= MAX_BACKUP_BYTES or not data.startswith(MAGIC):
		raise BackupError('备份格式或大小无效')
	position = len(MAGIC)
	salt, nonce = data[position : position + 16], data[position + 16 : position + 28]
	try:
		plaintext = AESGCM(_derive(password, salt)).decrypt(nonce, data[position + 28 :], _AAD)
		length = struct.unpack('>I', plaintext[:4])[0]
		if not 0 < length <= 4096 or length + 4 >= len(plaintext):
			raise ValueError
		metadata = json.loads(plaintext[4 : 4 + length])
		if (
			not isinstance(metadata, dict)
			or set(metadata) != {'version', 'created_at', 'master_key', 'database_sha256', 'database_length'}
			or type(metadata['version']) is not int
			or metadata['version'] != 1
		):
			raise ValueError
		created_at = metadata['created_at']
		if (
			isinstance(created_at, bool)
			or not isinstance(created_at, (int, float))
			or not 0 < created_at <= time.time() + 300
		):
			raise ValueError
		key = base64.b64decode(metadata['master_key'], validate=True)
		database = plaintext[4 + length :]
		if (
			len(key) != 32
			or type(metadata['database_length']) is not int
			or metadata['database_length'] != len(database)
			or metadata['database_sha256'] != hashlib.sha256(database).hexdigest()
		):
			raise ValueError
		return database, key, {'created_at': _stamp(created_at), 'format_version': 1}
	except (InvalidTag, ValueError, TypeError, KeyError, struct.error, OverflowError):
		raise BackupError('恢复密码错误或备份文件已损坏') from None


def _stage(root: Path, database: bytes) -> Path:
	path = root / ('.restore-preview-' + secrets.token_hex(16) + '.sqlite3')
	with path.open('xb') as stream:
		os.chmod(path, 0o600)
		stream.write(database)
		stream.flush()
		os.fsync(stream.fileno())
	return path


def _disable_automatic(config: dict) -> None:
	for name in ('schedule', 'monitoring', 'backups'):
		if isinstance(config.get(name), dict):
			config[name]['enabled'] = False
	for settings in config.get('automation', {}).values():
		if isinstance(settings, dict) and 'enabled' in settings:
			settings['enabled'] = False


def _prepare_database(
	path: Path,
	old_key: bytes,
	new_key: bytes,
	current_config: dict | None,
	current_revision: int,
	current_auth: tuple | None,
	current_security: dict[str, list[tuple]] | None = None,
) -> None:
	config, saved_revision, _ = _validate_database(path, old_key)
	revision = max(current_revision, saved_revision) + 1
	if revision >= 2**63:
		raise BackupError('恢复配置版本超出范围')
	_disable_automatic(config)
	if current_config is not None:
		config['webui_url'] = current_config.get('webui_url', '')
	config = validate_config(config)
	old_cipher, new_cipher = AESGCM(old_key), AESGCM(new_key)
	with closing(sqlite3.connect(path)) as db, db:
		db.execute('PRAGMA trusted_schema=OFF')
		db.execute('PRAGMA journal_mode=DELETE')
		tables = {item[0] for item in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
		if 'config_archive' in tables:
			for source_revision, document in db.execute(
				'SELECT source_revision,document FROM config_archive'
			).fetchall():
				aad = _CONFIG_AAD + str(source_revision).encode()
				db.execute(
					'UPDATE config_archive SET document=? WHERE source_revision=?',
					(_encrypted(new_cipher, _plain(old_cipher, document, aad), aad), source_revision),
				)
		if 'http_sessions' in tables:
			old_session = AESGCM(hmac.digest(old_key, _SESSION_PURPOSE, 'sha256'))
			new_session = AESGCM(hmac.digest(new_key, _SESSION_PURPOSE, 'sha256'))
			for account_id, binding_hash, document in db.execute(
				'SELECT account_id,binding_hash,document FROM http_sessions'
			).fetchall():
				aad = _SESSION_AAD + json.dumps([account_id, binding_hash], separators=(',', ':')).encode()
				db.execute(
					'UPDATE http_sessions SET document=? WHERE account_id=?',
					(_encrypted(new_session, _plain(old_session, document, aad), aad), account_id),
				)
		document = _encrypted(
			new_cipher,
			json.dumps(config, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode(),
			_CONFIG_AAD + str(revision).encode(),
		)
		db.execute('UPDATE config SET revision=?,document=? WHERE id=1', (revision, document))
		if current_auth is not None:
			db.execute('DELETE FROM web_auth')
			db.execute('INSERT INTO web_auth(id,salt,digest) VALUES (1,?,?)', current_auth)
		if current_security is not None:
			# Restoring account data must never downgrade the current authentication policy
			# or resurrect deleted authenticators from the uploaded backup.
			expected = _expected_schema(path.parent)
			for name in ('web_security', 'web_passkeys'):
				if name not in tables:
					definition = expected[('table', name)]
					if definition is None:
						raise BackupError('当前认证数据结构不可用')
					db.execute(definition)
				db.execute('DELETE FROM ' + name)  # nosec B608 - fixed authentication table allowlist
				rows = current_security.get(name, [])
				if rows:
					marks = ','.join('?' for _ in rows[0])
					db.executemany('INSERT INTO ' + name + ' VALUES (' + marks + ')', rows)  # nosec B608 - fixed table names, bound values
			db.execute('UPDATE web_security SET revision=revision+1 WHERE id=1')
		for name, statement in {
			'scheduler': 'UPDATE scheduler SET next_at=NULL',
			'balance_scheduler': 'UPDATE balance_scheduler SET next_at=NULL',
			'backup_scheduler': 'UPDATE backup_scheduler SET next_at=NULL',
			'automation_scheduler': 'UPDATE automation_scheduler SET next_at=NULL',
		}.items():
			if name in tables:
				db.execute(statement)
		if 'automation_notifications' in tables:
			db.execute(
				"UPDATE automation_notifications SET state='unknown',finished_at=? WHERE state='pending'",
				(time.time(),),
			)
		if 'runs' in tables:
			inflight = db.execute(
				"SELECT 1 FROM runs WHERE state IN ('running','stopping','awaiting_login') AND kind='checkin'"
			).fetchone()
			db.execute(
				"UPDATE runs SET state='interrupted',finished_at=?,error='备份恢复, 原任务状态需人工核对' WHERE state IN ('running','stopping','awaiting_login')",
				(time.time(),),
			)
			if inflight:
				from utils.http_checkin import account_binding

				db.execute("""CREATE TABLE IF NOT EXISTS account_attention (
				 account_id TEXT PRIMARY KEY, binding TEXT NOT NULL, outcome TEXT NOT NULL,
				 reason TEXT NOT NULL, retry_at REAL, updated_at REAL NOT NULL)""")
				for account in config['accounts']:
					if account.get('enabled', True):
						db.execute(
							'INSERT OR REPLACE INTO account_attention VALUES (?,?,?,?,?,?)',
							(
								account['id'],
								account_binding(account, config),
								'uncertain',
								'RESTORE_RESULT_UNKNOWN',
								None,
								time.time(),
							),
						)
	_validate_database(path, new_key)


class BackupManager:
	def __init__(self, data_dir: Path, key: bytes, config_store: ConfigStore):
		self.data_dir = Path(data_dir)
		if self.data_dir.is_symlink() or not isinstance(key, bytes) or len(key) != 32:
			raise BackupError('备份数据目录或主密钥无效')
		self.data_dir = self.data_dir.resolve()
		self.directory = self.data_dir / 'backups'
		if self.directory.is_symlink():
			raise BackupError('备份目录不能是符号链接')
		self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
		self.key, self.config_store = key, config_store
		self._previews: dict[str, dict] = {}
		for path in self.data_dir.glob('.restore-preview-*.sqlite3'):
			if (
				_STAGED_NAME.fullmatch(path.name)
				and not path.is_symlink()
				and path.is_file()
				and path.stat().st_mtime < time.time() - _PREVIEW_SECONDS
			):
				path.unlink(missing_ok=True)

	def _cleanup(self) -> None:
		for ticket, item in list(self._previews.items()):
			if item['expires'] <= time.monotonic():
				item['path'].unlink(missing_ok=True)
				del self._previews[ticket]

	def list(self) -> list[dict]:
		self._cleanup()
		if self.directory.is_symlink():
			raise BackupError('备份目录不能是符号链接')
		items = []
		for path in self.directory.glob('backup-*.nab'):
			if not _BACKUP_NAME.fullmatch(path.name) or path.is_symlink() or not path.is_file():
				continue
			with path.open('rb') as stream:
				if stream.read(len(MAGIC)) != MAGIC:
					continue
			try:
				created_at = datetime.strptime(path.name[7:23], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
			except ValueError:
				continue
			metadata = {'id': path.name, 'created_at': created_at.isoformat(), 'size': path.stat().st_size}
			items.append(((created_at.timestamp(), path.stat().st_mtime_ns, path.name), metadata))
		return [metadata for _, metadata in sorted(items, key=lambda item: item[0], reverse=True)]

	def read(self, backup_id: str) -> Path:
		if not isinstance(backup_id, str) or not _BACKUP_NAME.fullmatch(backup_id) or self.directory.is_symlink():
			raise BackupError('备份标识无效')
		path = self.directory / backup_id
		_private_file(path)
		if path.stat().st_size > MAX_BACKUP_BYTES:
			raise BackupError('备份文件超出大小限制')
		return path

	def create(self, password: str, retain_count: int = 7) -> dict:
		password = validate_recovery_password(password)
		if type(retain_count) is not int or not 1 <= retain_count <= 90:
			raise BackupError('备份保留数量需要为 1 到 90')
		self._cleanup()
		if self.directory.is_symlink():
			raise BackupError('备份目录不能是符号链接')
		descriptor, temporary = tempfile.mkstemp(prefix='.backup-snapshot-', suffix='.sqlite3', dir=self.data_dir)
		os.close(descriptor)
		path = Path(temporary)
		try:
			_private_file(self.data_dir / 'webui.sqlite3')
			with closing(sqlite3.connect((self.data_dir / 'webui.sqlite3').as_uri() + '?mode=ro', uri=True)) as source:
				with closing(sqlite3.connect(path)) as target:
					source.backup(target)
			_, _, counts = _validate_database(path, self.key)
			created = time.time()
			name = (
				'backup-'
				+ datetime.fromtimestamp(created, timezone.utc).strftime('%Y%m%dT%H%M%SZ')
				+ '-'
				+ secrets.token_hex(8)
				+ '.nab'
			)
			encoded = _encode(path.read_bytes(), self.key, password, created)
			atomic_write(self.directory / name, encoded)
			os.chmod(self.directory / name, 0o600)
			for item in self.list()[retain_count:]:
				self.read(item['id']).unlink()
			return {'id': name, 'created_at': _stamp(created), 'size': len(encoded), **counts}
		finally:
			path.unlink(missing_ok=True)

	def preview(self, encrypted_bytes: bytes, password: str, current_revision: int) -> dict:
		self._cleanup()
		if type(current_revision) is not int or current_revision != self.config_store.load()[1]:
			raise BackupError('配置已更新, 请重新读取后预览恢复')
		if len(self._previews) >= _MAX_PREVIEWS:
			raise BackupError('恢复预览过多, 请等待旧预览到期')
		database, key, metadata = _decode(encrypted_bytes, password)
		path = _stage(self.data_dir, database)
		try:
			_, revision, counts = _validate_database(path, key)
			ticket = secrets.token_urlsafe(32)
			self._previews[ticket] = {
				'path': path,
				'key': key,
				'revision': current_revision,
				'expires': time.monotonic() + _PREVIEW_SECONDS,
			}
			return {
				**metadata,
				**counts,
				'source_revision': revision,
				'ticket': ticket,
				'expires_at': _stamp(time.time() + _PREVIEW_SECONDS),
				'automatic_tasks_disabled': True,
				'preserves_admin': True,
				'preserves_public_url': True,
			}
		except BaseException:
			path.unlink(missing_ok=True)
			raise

	def prepare_restore(self, ticket: str, current_revision: int) -> Path:
		self._cleanup()
		item = self._previews.pop(ticket, None) if isinstance(ticket, str) else None
		if item is None:
			raise BackupError('恢复预览已失效, 请重新上传并预览')
		path = cast(Path, item['path'])
		try:
			config, revision = self.config_store.load()
			if type(current_revision) is not int or revision != current_revision or item['revision'] != revision:
				raise BackupError('配置已更新, 请重新预览恢复')
			with closing(sqlite3.connect(self.data_dir / 'webui.sqlite3')) as current:
				auth = current.execute('SELECT salt,digest FROM web_auth WHERE id=1').fetchone()
				tables = {row[0] for row in current.execute("SELECT name FROM sqlite_master WHERE type='table'")}
				security = {
					name: current.execute('SELECT * FROM ' + name).fetchall()  # nosec B608 - fixed table allowlist
					for name in ('web_security', 'web_passkeys')
					if name in tables
				}
			if auth is None:
				raise BackupError('当前管理员身份不可用')
			_prepare_database(path, item['key'], self.key, config, revision, auth, security or None)
			return path
		except BaseException:
			path.unlink(missing_ok=True)
			raise

	def close(self) -> None:
		for item in self._previews.values():
			item['path'].unlink(missing_ok=True)
		self._previews.clear()


def inspect_backup(data: bytes, password: str) -> dict:
	database, key, metadata = _decode(data, password)
	scratch = os.environ.get('CHECKIN_WEB_DATA_DIR')
	with tempfile.TemporaryDirectory(prefix='.backup-inspect-', dir=scratch) as directory:
		path = _stage(Path(directory), database)
		_, revision, counts = _validate_database(path, key)
		return {**metadata, **counts, 'source_revision': revision}


def restore_offline(data: bytes, password: str, data_dir: Path, key_file: Path) -> dict:
	data_dir, key_file = Path(data_dir), Path(key_file)
	if any(path.is_symlink() for target in (data_dir, key_file) for path in (target, *target.parents)):
		raise BackupError('恢复目标不能是符号链接')
	data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
	key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
	data_dir, key_file = data_dir.resolve(), key_file.resolve()
	destination = data_dir / 'webui.sqlite3'
	if destination.is_symlink() or destination.exists() or key_file.exists() or destination == key_file:
		raise BackupError('离线恢复只允许新的数据库和主密钥路径, 不覆盖已有数据')
	database, key, metadata = _decode(data, password)
	path = _stage(data_dir, database)
	created_key = False
	created_db = False
	try:
		_, revision, counts = _validate_database(path, key)
		_prepare_database(path, key, key, None, revision, None)
		with key_file.open('xb') as stream:
			created_key = True
			os.chmod(key_file, 0o600)
			stream.write(key)
			stream.flush()
			os.fsync(stream.fileno())
		# Exclusive creation avoids replacing a database created concurrently.
		with destination.open('xb') as stream:
			created_db = True
			os.chmod(destination, 0o600)
			stream.write(path.read_bytes())
			stream.flush()
			os.fsync(stream.fileno())
		return {**metadata, **counts, 'automatic_tasks_disabled': True}
	except BaseException:
		if created_db:
			destination.unlink(missing_ok=True)
		if created_key:
			key_file.unlink(missing_ok=True)
		raise
	finally:
		path.unlink(missing_ok=True)
