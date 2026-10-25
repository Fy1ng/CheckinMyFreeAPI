"""Single-administrator WebAuthn credentials and bounded, one-use ceremonies."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from fido2.server import Fido2Server
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (
	AttestationConveyancePreference,
	AttestedCredentialData,
	AuthenticationResponse,
	CredentialCreationOptions,
	CredentialRequestOptions,
	PublicKeyCredentialRpEntity,
	PublicKeyCredentialUserEntity,
	ResidentKeyRequirement,
	UserVerificationRequirement,
)

from server.config_store import ConfigError, ConflictError

TTL = 180
MAX_KEYS = 10


class SecurityError(ConfigError):
	"""Only fixed, credential-free validation messages reach the client."""


def stamp(value: float | None) -> str | None:
	return datetime.fromtimestamp(value, timezone.utc).isoformat() if value is not None else None


class SecurityStore:
	def __init__(self, path: Path):
		if Path(path).is_symlink():
			raise SecurityError('登录安全数据库不能是符号链接')
		self.db = sqlite3.connect(path, timeout=10)
		self.db.row_factory = sqlite3.Row
		self.db.executescript("""
		CREATE TABLE IF NOT EXISTS web_security (
		 id INTEGER PRIMARY KEY CHECK(id=1), mode TEXT NOT NULL,
		 revision INTEGER NOT NULL, user_handle BLOB NOT NULL
		);
		CREATE TABLE IF NOT EXISTS web_passkeys (
		 id TEXT PRIMARY KEY, credential BLOB NOT NULL, origin TEXT NOT NULL,
		 rp_id TEXT NOT NULL, label TEXT NOT NULL, counter INTEGER NOT NULL,
		 backup_eligible INTEGER NOT NULL, backed_up INTEGER NOT NULL,
		 verified INTEGER NOT NULL, created_at REAL NOT NULL, last_used_at REAL
		);
		""")
		self.db.execute('INSERT OR IGNORE INTO web_security VALUES (1,?,?,?)', ('password', 1, secrets.token_bytes(32)))
		self.db.commit()

	def policy(self) -> dict:
		row = self.db.execute('SELECT mode,revision,user_handle FROM web_security WHERE id=1').fetchone()
		if (
			row is None
			or row['mode'] not in {'password', 'passkey'}
			or type(row['revision']) is not int
			or not 1 <= row['revision'] < 2**63 - 1
			or not isinstance(row['user_handle'], bytes)
			or len(row['user_handle']) != 32
		):
			raise SecurityError('登录安全配置无效, 请通过 SSH 恢复')
		return dict(row)

	def keys(self, origin: str) -> list[dict]:
		return [
			dict(row)
			for row in self.db.execute('SELECT * FROM web_passkeys WHERE origin=? ORDER BY created_at', (origin,))
		]

	def public(self, origin: str) -> dict:
		policy = self.policy()
		keys = self.keys(origin)
		return {
			'mode': policy['mode'],
			'revision': policy['revision'],
			'passkey_available': any(row['verified'] for row in keys),
			'passkeys': [
				{
					'id': row['id'],
					'label': row['label'],
					'verified': bool(row['verified']),
					'created_at': stamp(row['created_at']),
					'last_used_at': stamp(row['last_used_at']),
				}
				for row in keys
			],
		}

	def add(self, origin: str, rp_id: str, label: str, auth_data) -> str:
		credential = auth_data.credential_data
		if credential is None or not 1 <= len(credential.credential_id) <= 1024:
			raise SecurityError('Passkey 注册结果无效')
		if auth_data.is_backed_up() and not auth_data.is_backup_eligible():
			raise SecurityError('Passkey 备份标志无效')
		if self.db.execute('SELECT count(*) FROM web_passkeys').fetchone()[0] >= MAX_KEYS:
			raise SecurityError('最多保存 10 个 Passkey, 请先删除不用的密钥')
		identifier = websafe_encode(credential.credential_id)
		try:
			with self.db:
				self.db.execute(
					'INSERT INTO web_passkeys VALUES (?,?,?,?,?,?,?,?,?, ?,NULL)',
					(
						identifier,
						bytes(credential),
						origin,
						rp_id,
						label,
						auth_data.counter,
						int(auth_data.is_backup_eligible()),
						int(auth_data.is_backed_up()),
						0,
						time.time(),
					),
				)
				self.db.execute('UPDATE web_security SET revision=revision+1 WHERE id=1')
		except sqlite3.IntegrityError:
			raise SecurityError('此 Passkey 已注册') from None
		return identifier

	def record_assertion(self, identifier: str, origin: str, auth_data) -> None:
		row = self.db.execute('SELECT * FROM web_passkeys WHERE id=? AND origin=?', (identifier, origin)).fetchone()
		if (
			row is None
			or bool(row['backup_eligible']) != auth_data.is_backup_eligible()
			or (auth_data.is_backed_up() and not auth_data.is_backup_eligible())
		):
			raise SecurityError('Passkey 状态校验失败')
		# Synced authenticators commonly use an unsupported (zero) signature counter.
		if (auth_data.counter or row['counter']) and auth_data.counter <= row['counter']:
			raise SecurityError('Passkey 签名计数器异常, 请使用其他密钥')
		with self.db:
			self.db.execute(
				'UPDATE web_passkeys SET counter=?,backed_up=?,verified=1,last_used_at=? WHERE id=?',
				(auth_data.counter, int(auth_data.is_backed_up()), time.time(), identifier),
			)

	def set_mode(self, mode: str, revision: int, origin: str, method: str) -> None:
		policy = self.policy()
		if revision != policy['revision']:
			raise ConflictError('登录安全配置已更新, 请重新读取')
		if mode not in {'password', 'passkey'}:
			raise SecurityError('登录模式无效')
		if mode == 'passkey' and (method != 'passkey' or not any(row['verified'] for row in self.keys(origin))):
			raise SecurityError('请先绑定并验证一个 Passkey, 再启用 Passkey 登录')
		with self.db:
			self.db.execute('UPDATE web_security SET mode=?,revision=revision+1 WHERE id=1', (mode,))

	def remove(self, identifier: str, revision: int, origin: str) -> None:
		policy = self.policy()
		if revision != policy['revision']:
			raise ConflictError('登录安全配置已更新, 请重新读取')
		keys = self.keys(origin)
		selected = next((row for row in keys if row['id'] == identifier), None)
		if selected is None:
			raise SecurityError('Passkey 不存在')
		if policy['mode'] == 'passkey' and selected['verified'] and sum(bool(row['verified']) for row in keys) <= 1:
			raise SecurityError('Passkey 模式不能删除最后一个已验证密钥, 请先添加其他密钥或切换模式')
		with self.db:
			self.db.execute('DELETE FROM web_passkeys WHERE id=?', (identifier,))
			self.db.execute('UPDATE web_security SET revision=revision+1 WHERE id=1')

	def reset(self, *, clear: bool = False) -> None:
		with self.db:
			self.db.execute("UPDATE web_security SET mode='password',revision=revision+1 WHERE id=1")
			if clear:
				self.db.execute('DELETE FROM web_passkeys')

	def close(self) -> None:
		self.db.close()


class PasskeyCeremonies:
	def __init__(self, store: SecurityStore):
		self.store = store
		self.pending: dict[str, dict] = {}
		self.proofs: dict[str, dict] = {}
		self.attempts: dict[str, list[float]] = {}

	def clear(self) -> None:
		self.pending.clear()
		self.proofs.clear()

	def check_limit(self, client_ip: str) -> bool:
		now = time.monotonic()
		self.attempts = {
			ip: recent
			for ip, values in self.attempts.items()
			if (recent := [value for value in values if now - value < 60])
		}
		values = self.attempts.get(client_ip, [])
		if (
			len(values) >= 30
			or sum(len(value) for value in self.attempts.values()) >= 120
			or (client_ip not in self.attempts and len(self.attempts) >= 256)
		):
			return False
		self.attempts[client_ip] = [*values, now]
		return True

	def _clean(self):
		now = time.monotonic()
		self.pending = {ticket: item for ticket, item in self.pending.items() if item['expires'] > now}
		self.proofs = {ticket: item for ticket, item in self.proofs.items() if item['expires'] > now}

	@staticmethod
	def _server(origin: str) -> Fido2Server:
		rp_id = urlsplit(origin).hostname
		if not rp_id:
			raise SecurityError('Passkey 站点配置无效')
		server = Fido2Server(
			PublicKeyCredentialRpEntity(id=rp_id, name='CheckinMyFreeAPI'),
			attestation=AttestationConveyancePreference.NONE,
			verify_origin=lambda candidate: candidate == origin,
		)
		server.timeout = TTL * 1000  # type: ignore[assignment]  # fido2 exposes this setting with a None-only annotation.
		return server

	def begin(self, kind: str, origin: str, binding: str, *, label: str = '') -> dict:
		self._clean()
		if len(self.pending) >= 128:
			raise SecurityError('验证请求过多, 请稍后重试')
		server = self._server(origin)
		keys = self.store.keys(origin)
		credentials = [AttestedCredentialData(row['credential']) for row in keys]
		options: CredentialCreationOptions | CredentialRequestOptions
		if kind == 'register':
			if not isinstance(label, str) or not 1 <= len(label.strip()) <= 80 or any(ord(c) < 32 for c in label):
				raise SecurityError('请填写 1 到 80 字符的 Passkey 名称')
			if len(keys) >= MAX_KEYS:
				raise SecurityError('最多保存 10 个 Passkey')
			options, state = server.register_begin(
				PublicKeyCredentialUserEntity(
					id=self.store.policy()['user_handle'], name='admin', display_name='Administrator'
				),
				credentials=credentials,
				resident_key_requirement=ResidentKeyRequirement.REQUIRED,
				user_verification=UserVerificationRequirement.REQUIRED,
			)
		else:
			if not credentials:
				raise SecurityError('尚未绑定此站点的 Passkey, 请先使用密码模式完成绑定')
			options, state = server.authenticate_begin(
				credentials, user_verification=UserVerificationRequirement.REQUIRED
			)
		ticket = secrets.token_urlsafe(32)
		self.pending[ticket] = {
			'kind': kind,
			'origin': origin,
			'binding': binding,
			'revision': self.store.policy()['revision'],
			'expires': time.monotonic() + TTL,
			'state': state,
			'label': label.strip(),
		}
		return {'ticket': ticket, **dict(options)}

	def complete(self, kind: str, ticket: object, credential: object, origin: str, binding: str) -> str:
		self._clean()
		item = self.pending.pop(ticket, None) if isinstance(ticket, str) else None
		if item is None or any(
			item[key] != value
			for key, value in [
				('kind', kind),
				('origin', origin),
				('binding', binding),
				('revision', self.store.policy()['revision']),
			]
		):
			raise SecurityError('Passkey 验证请求已失效, 请重新开始')
		if not isinstance(credential, dict) or len(json.dumps(credential)) > 65536:
			raise SecurityError('Passkey 响应无效')
		try:
			if (
				credential.get('id') != credential.get('rawId')
				or not isinstance(credential.get('id'), str)
				or not re.fullmatch(r'[A-Za-z0-9_-]{2,1400}', credential['id'])
			):
				raise ValueError
			client_data = json.loads(websafe_decode(credential['response']['clientDataJSON']))
			if (
				not isinstance(client_data, dict)
				or client_data.get('crossOrigin', False) is not False
				or client_data.get('topOrigin') is not None
			):
				raise ValueError
			server = self._server(origin)
			if kind == 'register':
				auth_data = server.register_complete(item['state'], credential)
				return self.store.add(origin, str(server.rp.id), item['label'], auth_data)
			response = AuthenticationResponse.from_dict(credential)
			if response.response.user_handle is not None and not hmac.compare_digest(
				response.response.user_handle, self.store.policy()['user_handle']
			):
				raise ValueError
			rows = self.store.keys(origin)
			matched = server.authenticate_complete(
				item['state'], [AttestedCredentialData(row['credential']) for row in rows], response
			)
			identifier = websafe_encode(matched.credential_id)
			self.store.record_assertion(identifier, origin, response.response.authenticator_data)
			return identifier
		except SecurityError:
			raise
		except (ValueError, TypeError, KeyError, IndexError, AssertionError, OverflowError):
			raise SecurityError('Passkey 响应校验失败, 请重新验证') from None

	def proof(self, origin: str, binding: str, method: str, credential_id: str | None = None) -> str:
		self._clean()
		if len(self.proofs) >= 128:
			raise SecurityError('验证请求过多, 请稍后重试')
		token = secrets.token_urlsafe(32)
		self.proofs[token] = {
			'origin': origin,
			'binding': binding,
			'method': method,
			'credential_id': credential_id,
			'revision': self.store.policy()['revision'],
			'expires': time.monotonic() + TTL,
		}
		return token

	def consume(self, token: object, origin: str, binding: str, *, require_passkey: bool) -> dict:
		self._clean()
		item = self.proofs.pop(token, None) if isinstance(token, str) else None
		if (
			item is None
			or item['origin'] != origin
			or not hmac.compare_digest(item['binding'], binding)
			or item['revision'] != self.store.policy()['revision']
			or (require_passkey and item['method'] != 'passkey')
		):
			raise SecurityError('请重新验证当前登录身份后操作')
		return item


def binding(value: str) -> str:
	return hashlib.sha256(value.encode()).hexdigest()
