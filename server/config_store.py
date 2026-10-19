"""Validated WebUI configuration with authenticated, encrypted SQLite storage.

This module deliberately does not use environment-based configuration loaders.
The server and its worker must not share mutable process environment settings.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import re
import sqlite3
import threading
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.fy1push import fy1push_channel, fy1push_endpoint, validate_fy1push_token

# Public UI marker; never an authentication credential.
SECRET_KEEP = '__UNCHANGED_SECRET__'  # nosec B105

# Keep this allowlist aligned with the environment variables read by NotificationKit.
NOTIFICATION_ENV_NAMES = frozenset(
	{
		'EMAIL_USER',
		'EMAIL_PASS',
		'EMAIL_TO',
		'EMAIL_SENDER',
		'CUSTOM_SMTP_SERVER',
		'PUSHPLUS_TOKEN',
		'SERVERPUSHKEY',
		'DINGDING_WEBHOOK',
		'FEISHU_WEBHOOK',
		'WEIXIN_WEBHOOK',
		'GOTIFY_URL',
		'GOTIFY_TOKEN',
		'GOTIFY_PRIORITY',
		'TELEGRAM_BOT_TOKEN',
		'TELEGRAM_CHAT_ID',
		'BARK_KEY',
		'BARK_SERVER',
		'FY1PUSH_SERVER',
		'FY1PUSH_TOKEN',
		'FY1PUSH_CHANNEL',
	}
)
SECRET_NOTIFICATION_ENV_NAMES = frozenset(
	{
		'EMAIL_PASS',
		'PUSHPLUS_TOKEN',
		'SERVERPUSHKEY',
		'DINGDING_WEBHOOK',
		'FEISHU_WEBHOOK',
		'WEIXIN_WEBHOOK',
		'GOTIFY_URL',
		'GOTIFY_TOKEN',
		'TELEGRAM_BOT_TOKEN',
		'BARK_KEY',
		'BARK_SERVER',
		'FY1PUSH_TOKEN',
	}
)
_TOP_LEVEL_FIELDS = frozenset(
	{'schema_version', 'accounts', 'proxy_url', 'notifications', 'schedule', 'http', 'webui_url'}
)
_ACCOUNT_FIELDS = frozenset(
	{
		'id',
		'name',
		'provider',
		'auth_type',
		'enabled',
		'cookies',
		'username',
		'password',
		'system_access_token',
		'api_user',
		'expected_username',
		'proxy',
	}
)
_ACCOUNT_SECRETS = ('password', 'cookies', 'system_access_token')
_AAD = b'anyrouter.server.configuration.v1:'
_MAX_CONFIG_BYTES = 1024 * 1024
_FIXED_ORIGINS = {'anyrouter': 'https://anyrouter.top', 'agentrouter': 'https://agentrouter.org'}
_COOKIE_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


class ConfigError(ValueError):
	"""A safe-to-display configuration or storage error."""


class ConflictError(ConfigError):
	"""A client tried to overwrite a newer configuration revision."""


def default_config() -> dict:
	return {
		'schema_version': 2,
		'accounts': [],
		'proxy_url': '',
		'notifications': {},
		'schedule': {'enabled': False, 'interval_minutes': 360},
		'http': {'timeout_seconds': 30},
		'webui_url': '',
	}


def _object(value, allowed: frozenset | set, label: str) -> dict:
	if not isinstance(value, dict) or any(not isinstance(key, str) or key not in allowed for key in value):
		raise ConfigError(f'{label} has an invalid format or unsupported field')
	return copy.deepcopy(value)


def _text(value, label: str, *, maximum: int = 8192, empty: bool = False, strip: bool = False) -> str:
	if not isinstance(value, str):
		raise ConfigError(f'{label} must be a string')
	result = value.strip() if strip else value
	if (
		len(result) > maximum
		or (not result and not empty)
		or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value)
	):
		raise ConfigError(f'{label} has an invalid length or contains control characters')
	if result == SECRET_KEEP:
		raise ConfigError('A secret marker has no stored value; enter a value or clear the field')
	return result


def _optional_text(value, label: str, *, maximum: int = 8192) -> str | None:
	return None if value is None else _text(value, label, maximum=maximum, empty=True)


def _boolean(value, label: str) -> bool:
	if not isinstance(value, bool):
		raise ConfigError(f'{label} must be true or false')
	return value


def _integer(value, label: str, lower: int, upper: int) -> int:
	if type(value) is not int or not lower <= value <= upper:
		raise ConfigError(f'{label} must be an integer between {lower} and {upper}')
	return value


def _alias(value, label: str) -> str:
	result = _text(value, label, maximum=128, strip=True)
	if result != value:
		raise ConfigError(f'{label} must not contain leading or trailing whitespace')
	return result


def _valid_host(hostname: str | None) -> bool:
	if not hostname:
		return False
	try:
		ipaddress.ip_address(hostname)
		return True
	except ValueError:
		try:
			hostname = hostname.encode('idna').decode('ascii').rstrip('.')
		except UnicodeError:
			return False
		return len(hostname) <= 253 and all(
			re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) is not None
			for label in hostname.split('.')
		)


def _proxy(value, label: str, *, optional: bool = True) -> str | None:
	if value is None and optional:
		return None
	server = _text(value, label, maximum=4096, strip=True)
	if optional and server in {'direct', 'default'}:
		return server
	try:
		parsed = urlsplit(server)
		valid = (
			parsed.scheme in {'http', 'https', 'socks5'}
			and _valid_host(parsed.hostname)
			and parsed.port
			and not parsed.query
			and not parsed.fragment
			and parsed.path in {'', '/'}
			and not any(char.isspace() for char in server)
			and '\\' not in server
		)
		if not valid or (parsed.scheme == 'socks5' and (parsed.username is not None or parsed.password is not None)):
			raise ValueError
	except ValueError:
		raise ConfigError(
			f'{label} must be an HTTP(S) proxy or unauthenticated SOCKS5 proxy with an explicit port'
		) from None
	return server


def _webui_origin(value) -> str:
	if value == '':
		return ''
	origin = _text(value, 'WebUI URL', maximum=2048, strip=True)
	try:
		parsed = urlsplit(origin)
		loopback = parsed.hostname == 'localhost'
		if parsed.hostname:
			try:
				loopback = ipaddress.ip_address(parsed.hostname).is_loopback
			except ValueError:
				pass
		if (
			parsed.scheme not in {'https', 'http'}
			or (parsed.scheme == 'http' and not loopback)
			or not _valid_host(parsed.hostname)
			or parsed.username is not None
			or parsed.password is not None
			or parsed.path not in {'', '/'}
			or parsed.query
			or parsed.fragment
			or any(char.isspace() for char in origin)
			or '\\' in origin
			or parsed.netloc.endswith(':')
			or parsed.port == 0
		):
			raise ValueError
	except ValueError:
		raise ConfigError('WebUI URL must be an HTTPS origin, or an HTTP loopback origin') from None
	hostname = parsed.hostname or ''
	hostname = f'[{hostname}]' if ':' in hostname else hostname.encode('idna').decode('ascii')
	port = f':{parsed.port}' if parsed.port is not None else ''
	return f'{parsed.scheme}://{hostname}{port}'


def _cookies(value) -> str:
	if isinstance(value, dict):
		if len(value) > 200:
			raise ConfigError('Account cookies have too many entries')
		parts = list(value.items())
	else:
		header = _text(value, 'Account cookies', maximum=65536, empty=True)
		if not header.strip():
			return ''
		parts = []
		for part in header.split(';'):
			if not part.strip():
				continue
			name, separator, val = part.strip().partition('=')
			if not separator:
				raise ConfigError('Account cookies must contain named cookie values')
			parts.append((name.strip(), val.strip()))
		if len(parts) > 200:
			raise ConfigError('Account cookies have too many entries')
	result = []
	seen = set()
	for name, val in parts:
		name = _text(name, 'Cookie name', maximum=256)
		val = _text(val, 'Cookie value', maximum=16384, empty=True)
		if _COOKIE_NAME.fullmatch(name) is None or name in seen:
			raise ConfigError('Cookie names must be unique valid HTTP tokens')
		if any(
			not (
				ord(char) == 33
				or 35 <= ord(char) <= 43
				or 45 <= ord(char) <= 58
				or 60 <= ord(char) <= 91
				or 93 <= ord(char) <= 126
			)
			for char in val
		):
			raise ConfigError('Cookie values contain unsupported characters')
		seen.add(name)
		result.append(f'{name}={val}')
	header = '; '.join(result)
	if len(header) > 65536:
		raise ConfigError('Account cookies exceed the maximum supported size')
	return header


def _api_user(value) -> str:
	if type(value) is int:
		value = str(value)
	user = _text(value, 'API user ID', maximum=128, empty=True, strip=True)
	if user and (not user.isascii() or not user.isdecimal() or int(user) <= 0):
		raise ConfigError('API user ID must be a positive integer')
	return str(int(user)) if user else ''


def _validate_accounts(value, proxy_url: str) -> list:
	if not isinstance(value, list) or len(value) > 100:
		raise ConfigError('Accounts must be an array with at most 100 entries')
	accounts = []
	seen = set()
	for settings in value:
		account = _object(settings, _ACCOUNT_FIELDS, 'Account')
		account_id = _alias(account.get('id'), 'Account ID')
		if account_id in seen:
			raise ConfigError('Account IDs must be unique')
		seen.add(account_id)
		account['id'] = account_id
		account['name'] = _text(account.get('name', account_id), 'Account name', maximum=256)
		provider = account.get('provider')
		if not isinstance(provider, str) or provider not in _FIXED_ORIGINS:
			raise ConfigError('Only AnyRouter and AgentRouter are supported')
		auth_type = account.get('auth_type')
		allowed = {'cookie', 'password'} if provider == 'anyrouter' else {'system_token'}
		if not isinstance(auth_type, str) or auth_type not in allowed:
			raise ConfigError('Account authentication is not supported by this provider')
		account['enabled'] = _boolean(account.get('enabled', True), 'Account enabled')
		for field in {'username', 'password', 'system_access_token', 'expected_username'} & account.keys():
			account[field] = _text(account[field], 'Account field', maximum=8192, empty=True)
		if 'api_user' in account:
			account['api_user'] = _api_user(account['api_user'])
		if 'cookies' in account:
			account['cookies'] = _cookies(account['cookies'])
		if account.get('system_access_token'):
			token = account['system_access_token']
			if not token.isascii() or any(char.isspace() for char in token):
				raise ConfigError('System access token must be an ASCII token without whitespace')
		mode_fields = {
			'cookie': {'cookies'},
			'password': {'username', 'password'},
			'system_token': {'system_access_token'},
		}
		if any(
			account.get(field)
			for field in {'cookies', 'username', 'password', 'system_access_token'} - mode_fields[auth_type]
		):
			raise ConfigError('Account cannot combine different authentication credentials')
		if 'proxy' in account:
			account['proxy'] = _proxy(account['proxy'], 'Account proxy')
		if account['enabled'] and account.get('proxy') == 'default' and not proxy_url:
			raise ConfigError('A default proxy is required by an account but no proxy URL is configured')
		if account['enabled']:
			if auth_type == 'password':
				if not account.get('username') or not account.get('password'):
					raise ConfigError('Password authentication requires username and password')
			elif not account.get('api_user') or not account.get(
				'cookies' if auth_type == 'cookie' else 'system_access_token'
			):
				raise ConfigError('Cookie and system token authentication require credentials and API user ID')
		accounts.append(account)
	return accounts


def validate_config(config: dict) -> dict:
	"""Return a normalized independent document, or a credential-free ConfigError."""
	data = default_config()
	data.update(_object(config, _TOP_LEVEL_FIELDS, 'Configuration'))
	if type(data['schema_version']) is not int or data['schema_version'] != 2:
		raise ConfigError('Only configuration schema version 2 is supported')
	data['proxy_url'] = '' if data['proxy_url'] == '' else _proxy(data['proxy_url'], 'Default proxy', optional=False)
	data['accounts'] = _validate_accounts(data['accounts'], data['proxy_url'])
	data['webui_url'] = _webui_origin(data['webui_url'])
	notifications = _object(data['notifications'], NOTIFICATION_ENV_NAMES, 'Notifications')
	for key, value in notifications.items():
		notifications[key] = _text(value, 'Notification setting', maximum=8192, empty=True)
		if key == 'GOTIFY_PRIORITY' and value:
			if not value.isascii() or not value.isdecimal() or not 1 <= int(value) <= 10:
				raise ConfigError('Gotify priority must be an integer between 1 and 10')
	try:
		if notifications.get('FY1PUSH_SERVER'):
			fy1push_endpoint(notifications['FY1PUSH_SERVER'])
		if notifications.get('FY1PUSH_CHANNEL'):
			fy1push_channel(notifications['FY1PUSH_CHANNEL'])
		validate_fy1push_token(notifications.get('FY1PUSH_TOKEN', ''))
	except ValueError as error:
		raise ConfigError(str(error)) from None
	data['notifications'] = notifications
	schedule = default_config()['schedule']
	schedule.update(_object(data['schedule'], set(schedule), 'Schedule'))
	schedule['enabled'] = _boolean(schedule['enabled'], 'Schedule enabled')
	schedule['interval_minutes'] = _integer(schedule['interval_minutes'], 'Schedule interval', 30, 10080)
	if schedule['enabled'] and not any(account['enabled'] for account in data['accounts']):
		raise ConfigError('An enabled schedule requires at least one enabled account')
	data['schedule'] = schedule
	http = default_config()['http']
	http.update(_object(data['http'], set(http), 'HTTP settings'))
	http['timeout_seconds'] = _integer(http['timeout_seconds'], 'HTTP timeout', 5, 120)
	data['http'] = http
	if len(json.dumps(data, ensure_ascii=False).encode()) > _MAX_CONFIG_BYTES:
		raise ConfigError('Configuration exceeds the maximum supported size')
	return data


def redact_config(config: dict) -> dict:
	data = copy.deepcopy(config)
	if data.get('proxy_url'):
		data['proxy_url'] = SECRET_KEEP
	for account in data.get('accounts', []):
		for name in _ACCOUNT_SECRETS:
			if account.get(name):
				account[name] = SECRET_KEEP
		if account.get('proxy') not in {None, '', 'direct', 'default'}:
			account['proxy'] = SECRET_KEEP
	for name in SECRET_NOTIFICATION_ENV_NAMES:
		if data.get('notifications', {}).get(name):
			data['notifications'][name] = SECRET_KEEP
	return data


def _restore_secret(target: dict, old: dict, name: str) -> None:
	if target.get(name) == SECRET_KEEP:
		if not old.get(name):
			raise ConfigError('A secret marker has no stored value; enter a value or clear the field')
		target[name] = copy.deepcopy(old[name])


def _restore_secrets(config: dict, old: dict) -> dict:
	data = _object(config, _TOP_LEVEL_FIELDS, 'Configuration')
	_restore_secret(data, old, 'proxy_url')
	old_accounts = {account['id']: account for account in old['accounts']}
	if isinstance(data.get('accounts'), list):
		for account in data['accounts']:
			if isinstance(account, dict):
				previous = old_accounts.get(account.get('id')) if isinstance(account.get('id'), str) else None
				_restore_secret(account, previous or {}, 'proxy')
				if previous and (account.get('provider'), account.get('auth_type')) != (
					previous.get('provider'),
					previous.get('auth_type'),
				):
					previous = None
				for name in _ACCOUNT_SECRETS:
					_restore_secret(account, previous or {}, name)
	if isinstance(data.get('notifications'), dict):
		for name in SECRET_NOTIFICATION_ENV_NAMES:
			_restore_secret(data['notifications'], old['notifications'], name)
	return data


def _migrate_legacy(document: dict, revision: int) -> tuple[dict, dict]:
	"""Convert supported accounts only; the caller archives the entire original ciphertext."""
	if not isinstance(document, dict) or 'schema_version' in document:
		raise ConfigError('Stored configuration has an unsupported schema version')
	source_accounts = document.get('accounts', [])
	if not isinstance(source_accounts, list) or len(source_accounts) > 100:
		raise ConfigError('Stored accounts have an invalid format')
	data = default_config()
	data['proxy_url'] = document.get('proxy_url', '')
	data['notifications'] = copy.deepcopy(document.get('notifications', {}))
	source_schedule = document.get('schedule', {})
	if not isinstance(source_schedule, dict):
		raise ConfigError('Stored schedule has an invalid format')
	interval = source_schedule.get('interval_minutes', 360)
	data['schedule']['interval_minutes'] = _integer(interval, 'Schedule interval', 30, 10080)
	providers = document.get('providers', {})
	if not isinstance(providers, dict):
		raise ConfigError('Stored providers have an invalid format')
	omitted = 0
	seen = set()
	for old in source_accounts:
		if not isinstance(old, dict):
			raise ConfigError('Stored account has an invalid format')
		provider = old.get('provider', 'anyrouter')
		override = providers.get(provider, {}) if isinstance(provider, str) else {}
		origin = (
			override.get('domain', _FIXED_ORIGINS.get(provider, ''))
			if isinstance(override, dict) and isinstance(provider, str)
			else None
		)
		if (
			not isinstance(provider, str)
			or provider not in _FIXED_ORIGINS
			or not isinstance(override, dict)
			or not isinstance(origin, str)
			or origin.rstrip('/') != _FIXED_ORIGINS.get(provider)
		):
			omitted += 1
			continue
		try:
			account_id = _alias(old.get('id'), 'Account ID')
			name = _text(old.get('name') or account_id, 'Account name', maximum=256)
		except ConfigError:
			omitted += 1
			continue
		if account_id in seen:
			omitted += 1
			continue
		seen.add(account_id)
		account: dict = {
			'id': account_id,
			'name': name,
			'provider': provider,
			'enabled': old.get('enabled', True) is True,
			'auth_type': 'system_token' if provider == 'agentrouter' else 'cookie',
		}
		for field in ('api_user', 'expected_username', 'proxy'):
			if old.get(field) is not None:
				account[field] = copy.deepcopy(old[field])
		if provider == 'agentrouter':
			account['system_access_token'] = old.get('system_access_token', '')
		elif old.get('auth'):
			# OAuth snapshots belong to the old browser flow and must never become HTTP cookies.
			account.update(enabled=False, cookies='')
		elif old.get('email') or old.get('username') or old.get('password'):
			account.update(
				auth_type='password',
				username=old.get('username') or old.get('email') or '',
				password=old.get('password', ''),
			)
		else:
			account['cookies'] = copy.deepcopy(old.get('cookies', ''))
		try:
			account = _validate_accounts([account], data['proxy_url'])[0]
		except ConfigError:
			# Retain the account and safe identity hints, but require setup before any request.
			account['enabled'] = False
			for field in (
				'api_user',
				'expected_username',
				'proxy',
				'username',
				'password',
				'cookies',
				'system_access_token',
			):
				if field not in account:
					continue
				try:
					if field == 'api_user':
						account[field] = _api_user(account[field])
					elif field == 'proxy':
						account[field] = _proxy(account[field], 'Account proxy')
					elif field == 'cookies':
						account[field] = _cookies(account[field])
					else:
						account[field] = _text(account[field], 'Account field', empty=True)
				except ConfigError:
					account.pop(field)
			if account.get('system_access_token') and (
				not account['system_access_token'].isascii()
				or any(char.isspace() for char in account['system_access_token'])
			):
				account.pop('system_access_token')
			account = _validate_accounts([account], data['proxy_url'])[0]
		data['accounts'].append(account)
	data = validate_config(data)
	return data, {
		'from_schema': 1,
		'source_revision': revision,
		'converted_accounts': len(data['accounts']),
		'disabled_accounts': sum(not account['enabled'] for account in data['accounts']),
		'omitted_accounts': omitted,
		'schedule_disabled': True,
	}


class ConfigStore:
	"""A singleton encrypted document with a monotonically increasing CAS revision."""

	def __init__(self, path: Path, key: bytes):
		if not isinstance(key, bytes) or len(key) != 32:
			raise ConfigError('The configuration encryption key must contain exactly 32 bytes')
		self.path = Path(path)
		self._cipher = AESGCM(key)
		self._lock = threading.RLock()
		self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
		if self.path.is_symlink():
			raise ConfigError('Configuration database must not be a symbolic link')
		try:
			fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
		except FileExistsError:
			pass
		else:
			os.close(fd)
		os.chmod(self.path, 0o600)
		self._connection = sqlite3.connect(self.path, timeout=10, isolation_level=None, check_same_thread=False)
		try:
			self._connection.execute('PRAGMA journal_mode=DELETE')
			self._connection.execute('PRAGMA busy_timeout=10000')
			self._connection.execute(
				'CREATE TABLE IF NOT EXISTS config ('
				'id INTEGER PRIMARY KEY CHECK (id = 1), '
				'revision INTEGER NOT NULL CHECK (revision > 0), document BLOB NOT NULL)'
			)
			self._connection.execute(
				'CREATE TABLE IF NOT EXISTS config_archive ('
				'source_revision INTEGER PRIMARY KEY, document BLOB NOT NULL, migration TEXT NOT NULL)'
			)
		except BaseException:
			self._connection.close()
			raise

	def _load_row(self) -> tuple[dict, int]:
		row = self._connection.execute('SELECT revision, document FROM config WHERE id = 1').fetchone()
		if row is None:
			return default_config(), 0
		revision, encrypted = row
		if (
			type(revision) is not int
			or not 1 <= revision < 2**63
			or not isinstance(encrypted, bytes)
			or not 28 <= len(encrypted) <= _MAX_CONFIG_BYTES + 28
		):
			raise ConfigError('Stored configuration is invalid; restore a trusted backup')
		try:
			plaintext = self._cipher.decrypt(encrypted[:12], encrypted[12:], _AAD + str(revision).encode('ascii'))
		except (InvalidTag, ValueError, OverflowError):
			raise ConfigError(
				'Configuration cannot be decrypted; verify the encryption key or restore a trusted backup'
			) from None
		try:
			document = json.loads(plaintext)
			if isinstance(document, dict) and 'schema_version' not in document:
				if revision >= 2**63 - 1:
					raise ConfigError('Configuration revision cannot be migrated')
				document, information = _migrate_legacy(document, revision)
				self._connection.execute(
					'INSERT INTO config_archive (source_revision, document, migration) VALUES (?, ?, ?)',
					(revision, encrypted, json.dumps(information, separators=(',', ':'))),
				)
				revision += 1
				self._write(document, revision)
			return validate_config(document), revision
		except (ValueError, TypeError, RecursionError):
			raise ConfigError('Stored configuration is invalid; restore a trusted backup') from None

	def load(self) -> tuple[dict, int]:
		with self._lock:
			self._connection.execute('BEGIN IMMEDIATE')
			try:
				result = self._load_row()
				self._connection.execute('COMMIT')
				return result
			except BaseException:
				self._connection.execute('ROLLBACK')
				raise

	def migration_info(self) -> dict | None:
		"""Return credential-free migration counts, or None for a fresh schema 2 database."""
		with self._lock:
			self.load()
			row = self._connection.execute(
				'SELECT migration FROM config_archive ORDER BY source_revision DESC LIMIT 1'
			).fetchone()
			if row is None:
				return None
			try:
				information = json.loads(row[0])
				fields = (
					'from_schema',
					'source_revision',
					'converted_accounts',
					'disabled_accounts',
					'omitted_accounts',
				)
				if (
					not isinstance(information, dict)
					or set(information) != {*fields, 'schedule_disabled'}
					or any(type(information[field]) is not int or information[field] < 0 for field in fields)
					or information['schedule_disabled'] is not True
				):
					raise ValueError
			except (TypeError, ValueError, RecursionError):
				raise ConfigError('Stored migration information is invalid') from None
			return information

	def _write(self, document: dict, revision: int) -> None:
		nonce = os.urandom(12)
		plaintext = json.dumps(document, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
		encrypted = nonce + self._cipher.encrypt(nonce, plaintext, _AAD + str(revision).encode('ascii'))
		self._connection.execute(
			'INSERT INTO config (id, revision, document) VALUES (1, ?, ?) '
			'ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, document=excluded.document',
			(revision, encrypted),
		)

	def public(self) -> dict:
		config, revision = self.load()
		return {'config': redact_config(config), 'revision': revision}

	def save(self, config: dict, expected_revision: int) -> dict:
		if type(expected_revision) is not int or not 0 <= expected_revision < 2**63 - 1:
			raise ConfigError('Expected revision must be a nonnegative integer')
		with self._lock:
			self._connection.execute('BEGIN IMMEDIATE')
			try:
				old, revision = self._load_row()
				if revision != expected_revision:
					raise ConflictError('Configuration changed; reload it before saving again')
				document = validate_config(_restore_secrets(config, old))
				next_revision = revision + 1
				self._write(document, next_revision)
				self._connection.execute('COMMIT')
			except BaseException:
				self._connection.execute('ROLLBACK')
				raise
		return {'config': redact_config(document), 'revision': next_revision}

	def close(self) -> None:
		with self._lock:
			self._connection.close()
