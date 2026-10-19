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
from dataclasses import fields
from pathlib import Path
from urllib.parse import unquote, urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from utils.config import AccountConfig, AppConfig, IdentityConfig, ProviderConfig
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
	{'accounts', 'identities', 'providers', 'proxy_url', 'notifications', 'schedule', 'browser'}
)
_ACCOUNT_FIELDS = frozenset(field.name for field in fields(AccountConfig))
_PROVIDER_FIELDS = frozenset(field.name for field in fields(ProviderConfig)) - {'name'}
_AAD = b'anyrouter.server.configuration.v1:'
_MAX_CONFIG_BYTES = 1024 * 1024


class ConfigError(ValueError):
	"""A safe-to-display configuration or storage error."""


class ConflictError(ConfigError):
	"""A client tried to overwrite a newer configuration revision."""


def default_config() -> dict:
	return {
		'accounts': [],
		'identities': {},
		'providers': {},
		'proxy_url': '',
		'notifications': {},
		'schedule': {'enabled': False, 'interval_minutes': 360},
		'browser': {
			'engine': 'cloakbrowser',
			'headless': False,
			'humanize': True,
			'wait_timeout_ms': 60000,
			'manual_timeout_seconds': 600,
			'manual_total_timeout_seconds': 1800,
		},
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
		or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in result)
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


def _origin(value) -> str:
	domain = _text(value, 'Provider domain', maximum=2048, strip=True)
	try:
		parsed = urlsplit(domain)
		valid = (
			parsed.scheme == 'https'
			and _valid_host(parsed.hostname)
			and parsed.username is None
			and parsed.password is None
			and parsed.path in {'', '/'}
			and not parsed.query
			and not parsed.fragment
			and not any(char.isspace() for char in domain)
			and '\\' not in domain
			and not parsed.netloc.endswith(':')
		)
		if not valid or parsed.port == 0:
			raise ValueError
	except ValueError:
		raise ConfigError(
			'Provider domain must be a pure HTTPS origin without credentials, paths or query parameters'
		) from None
	hostname = parsed.hostname or ''
	hostname = f'[{hostname}]' if ':' in hostname else hostname.encode('idna').decode('ascii')
	port = f':{parsed.port}' if parsed.port is not None else ''
	return f'{parsed.scheme}://{hostname}{port}'


def _path(value, *, optional: bool = False) -> str | None:
	if value is None and optional:
		return None
	path = _text(value, 'Provider path', maximum=2048)
	decoded = unquote(path)
	if (
		not path.startswith('/')
		or path.startswith('//')
		or '\\' in decoded
		or '?' in path
		or '#' in path
		or decoded.startswith('//')
		or any(part in {'.', '..'} for part in decoded.split('/'))
		or any(ord(char) < 32 or ord(char) == 127 for char in decoded)
	):
		raise ConfigError('Provider paths must be absolute paths within their configured origin')
	return path


def _default_providers() -> dict[str, ProviderConfig]:
	return {
		'anyrouter': ProviderConfig(
			name='anyrouter',
			domain='https://anyrouter.top',
			bypass_method='waf_cookies',
			waf_cookie_names=['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'],
			persist_profile=True,
		),
		'agentrouter': ProviderConfig(
			name='agentrouter',
			domain='https://agentrouter.org',
			sign_in_path=None,
			bypass_method='waf_cookies',
			waf_cookie_names=['acw_tc'],
			use_proxy=True,
		),
	}


def build_app_config(config: dict) -> AppConfig:
	"""Build runtime dataclasses from already validated configuration, without environment reads."""
	providers = _default_providers()
	for name, settings in config['providers'].items():
		providers[name] = ProviderConfig.from_dict(name, settings, defaults=providers.get(name))
	return AppConfig(
		providers=providers,
		identities={name: IdentityConfig(**settings) for name, settings in config['identities'].items()},
	)


def _validate_providers(value) -> dict:
	if not isinstance(value, dict) or len(value) > 100:
		raise ConfigError('Providers must be an object with at most 100 entries')
	providers = {}
	for name, settings in value.items():
		_alias(name, 'Provider alias')
		provider = _object(settings, _PROVIDER_FIELDS, 'Provider')
		provider['domain'] = _origin(provider.get('domain'))
		for key in {'login_path', 'sign_in_path', 'user_info_path', 'status_path', 'auth_state_path'} & provider.keys():
			provider[key] = _path(provider[key], optional=key == 'sign_in_path')
		for key in {'use_proxy', 'persist_profile'} & provider.keys():
			provider[key] = _boolean(provider[key], 'Provider flag')
		if 'api_user_key' in provider:
			header = _text(provider['api_user_key'], 'API user header', maximum=128)
			if re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", header) is None:
				raise ConfigError('API user header must be a valid HTTP header name')
		if provider.get('bypass_method') is not None and provider['bypass_method'] != 'waf_cookies':
			raise ConfigError('Provider bypass method must be waf_cookies or null')
		if provider.get('waf_cookie_names') is not None:
			cookies = provider['waf_cookie_names']
			if not isinstance(cookies, list) or len(cookies) > 100:
				raise ConfigError('WAF cookie names must be an array with at most 100 entries')
			provider['waf_cookie_names'] = list(
				dict.fromkeys(_text(name, 'WAF cookie name', maximum=256) for name in cookies)
			)
		if 'oauth_client_ids' in provider:
			clients = _object(provider['oauth_client_ids'], {'github', 'linuxdo'}, 'OAuth client IDs')
			provider['oauth_client_ids'] = {
				kind: _text(client_id, 'OAuth client ID', maximum=512) for kind, client_id in clients.items()
			}
		providers[name] = provider
	return providers


def _validate_accounts(value, identities: dict, providers: dict[str, ProviderConfig], proxy_url: str) -> list:
	if not isinstance(value, list) or len(value) > 100:
		raise ConfigError('Accounts must be an array with at most 100 entries')
	accounts = []
	seen = set()
	identity_proxies: dict[str, str | None] = {}
	for settings in value:
		account = _object(settings, _ACCOUNT_FIELDS, 'Account')
		account_id = _alias(account.get('id'), 'Account ID')
		if account_id in seen:
			raise ConfigError('Account IDs must be unique')
		seen.add(account_id)
		account['id'] = account_id
		account['provider'] = _alias(account.get('provider', 'anyrouter'), 'Account provider')
		provider = providers.get(account['provider'])
		if provider is None:
			raise ConfigError('Account refers to an unknown provider')
		for key in {'name', 'email', 'password', 'expected_username'} & account.keys():
			account[key] = _optional_text(account[key], 'Account field')
		if 'name' in account and not account['name']:
			raise ConfigError('Account name must not be empty')
		if 'api_user' in account and account['api_user'] is not None:
			if type(account['api_user']) is int:
				account['api_user'] = str(account['api_user'])
			account['api_user'] = _text(account['api_user'], 'Expected API user', maximum=256)
		cookies = account.get('cookies')
		if isinstance(cookies, dict):
			if len(cookies) > 200:
				raise ConfigError('Account cookies have too many entries')
			account['cookies'] = {
				_text(name, 'Cookie name', maximum=256): _text(val, 'Cookie value', maximum=16384, empty=True)
				for name, val in cookies.items()
			}
		elif cookies is not None:
			account['cookies'] = _text(cookies, 'Account cookies', maximum=65536, empty=True)
			if cookies and not any('=' in part and part.split('=', 1)[0].strip() for part in cookies.split(';')):
				raise ConfigError('Account cookies must contain named cookie values')
		if 'proxy' in account:
			account['proxy'] = _proxy(account['proxy'], 'Account proxy')
		proxy_setting = account.get('proxy')
		auth = account.get('auth')
		if auth is not None:
			auth = _object(auth, {'type', 'identity'}, 'Account OAuth')
			if not isinstance(auth.get('type'), str) or auth['type'] not in {'linuxdo', 'github'}:
				raise ConfigError('Account OAuth type must be linuxdo or github')
			alias = _alias(auth.get('identity'), 'OAuth identity')
			identity = identities.get(alias)
			if identity is None or identity['type'] != auth['type']:
				raise ConfigError('Account OAuth identity is missing or has a different type')
			if not account.get('api_user') and not account.get('expected_username'):
				raise ConfigError('OAuth requires api_user or expected_username for account binding')
			if account.get('email') or account.get('password') or account.get('cookies'):
				raise ConfigError('OAuth cannot be combined with cookies or password credentials')
			if identity.get('proxy') is not None:
				proxy_setting = identity['proxy']
			account['auth'] = auth
		else:
			has_login = bool(account.get('email') and account.get('password'))
			if not has_login and not account.get('cookies'):
				raise ConfigError('Account requires cookies or both email and password')
			if not has_login and not account.get('api_user'):
				raise ConfigError('Cookie authentication requires api_user for account binding')
		proxy = _resolve_proxy(proxy_setting, provider.use_proxy, proxy_url)
		if auth:
			alias = auth['identity']
			if account.get('proxy') is not None:
				if _resolve_proxy(account['proxy'], provider.use_proxy, proxy_url) != proxy:
					raise ConfigError('Account and identity proxy settings conflict')
			if alias in identity_proxies and identity_proxies[alias] != proxy:
				raise ConfigError('Accounts sharing an identity must use the same effective proxy')
			identity_proxies[alias] = proxy
		accounts.append(account)
	return accounts


def _resolve_proxy(value: str | None, use_proxy: bool, proxy_url: str) -> str | None:
	if value == 'direct' or (value is None and not use_proxy):
		return None
	if value is None or value == 'default':
		if not proxy_url:
			raise ConfigError('A default proxy is required by an account but no proxy URL is configured')
		return proxy_url
	return value


def validate_config(config: dict) -> dict:
	"""Return a normalized independent document, or a credential-free ConfigError."""
	data = default_config()
	data.update(_object(config, _TOP_LEVEL_FIELDS, 'Configuration'))
	data['providers'] = _validate_providers(data['providers'])
	if not isinstance(data['identities'], dict) or len(data['identities']) > 100:
		raise ConfigError('Identities must be an object with at most 100 entries')
	identities = {}
	for alias, settings in data['identities'].items():
		_alias(alias, 'Identity alias')
		identity = _object(settings, {'type', 'proxy'}, 'Identity')
		if not isinstance(identity.get('type'), str) or identity['type'] not in {'linuxdo', 'github'}:
			raise ConfigError('Identity type must be linuxdo or github')
		if 'proxy' in identity:
			identity['proxy'] = _proxy(identity['proxy'], 'Identity proxy')
		identities[alias] = identity
	data['identities'] = identities
	data['proxy_url'] = '' if data['proxy_url'] == '' else _proxy(data['proxy_url'], 'Default proxy', optional=False)
	app_config = build_app_config(data)
	data['accounts'] = _validate_accounts(data['accounts'], identities, app_config.providers, data['proxy_url'])
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
	if schedule['enabled'] and not data['accounts']:
		raise ConfigError('An enabled schedule requires at least one account')
	data['schedule'] = schedule
	browser = default_config()['browser']
	browser.update(_object(data['browser'], set(browser), 'Browser'))
	if not isinstance(browser['engine'], str) or browser['engine'] not in {'cloakbrowser', 'chrome'}:
		raise ConfigError('INVALID_BROWSER_ENGINE')
	for key in ('headless', 'humanize'):
		browser[key] = _boolean(browser[key], 'Browser flag')
	browser['wait_timeout_ms'] = _integer(browser['wait_timeout_ms'], 'Browser wait timeout', 1000, 120000)
	browser['manual_timeout_seconds'] = _integer(browser['manual_timeout_seconds'], 'Manual timeout', 30, 1800)
	browser['manual_total_timeout_seconds'] = _integer(
		browser['manual_total_timeout_seconds'], 'Total manual timeout', 30, 3600
	)
	data['browser'] = browser
	if len(json.dumps(data, ensure_ascii=False).encode()) > _MAX_CONFIG_BYTES:
		raise ConfigError('Configuration exceeds the maximum supported size')
	return data


def redact_config(config: dict) -> dict:
	data = copy.deepcopy(config)
	if data.get('proxy_url'):
		data['proxy_url'] = SECRET_KEEP
	for account in data.get('accounts', []):
		for name in ('password', 'cookies'):
			if account.get(name):
				account[name] = SECRET_KEEP
		if account.get('proxy') not in {None, '', 'direct', 'default'}:
			account['proxy'] = SECRET_KEEP
	for identity in data.get('identities', {}).values():
		if identity.get('proxy') not in {None, '', 'direct', 'default'}:
			identity['proxy'] = SECRET_KEEP
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
				for name in ('password', 'cookies', 'proxy'):
					_restore_secret(account, previous or {}, name)
	if isinstance(data.get('identities'), dict):
		for alias, identity in data['identities'].items():
			if isinstance(identity, dict):
				_restore_secret(identity, old['identities'].get(alias, {}), 'proxy')
	if isinstance(data.get('notifications'), dict):
		for name in SECRET_NOTIFICATION_ENV_NAMES:
			_restore_secret(data['notifications'], old['notifications'], name)
	return data


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
			return validate_config(document), revision
		except (ValueError, TypeError, RecursionError):
			raise ConfigError('Stored configuration is invalid; restore a trusted backup') from None

	def load(self) -> tuple[dict, int]:
		with self._lock:
			return self._load_row()

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
				nonce = os.urandom(12)
				plaintext = json.dumps(document, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
				encrypted = nonce + self._cipher.encrypt(nonce, plaintext, _AAD + str(next_revision).encode('ascii'))
				self._connection.execute(
					'INSERT INTO config (id, revision, document) VALUES (1, ?, ?) '
					'ON CONFLICT(id) DO UPDATE SET revision=excluded.revision, document=excluded.document',
					(next_revision, encrypted),
				)
				self._connection.execute('COMMIT')
			except BaseException:
				self._connection.execute('ROLLBACK')
				raise
		return {'config': redact_config(document), 'revision': next_revision}

	def close(self) -> None:
		with self._lock:
			self._connection.close()
