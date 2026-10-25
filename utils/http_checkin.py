"""Fixed-origin, browser-free NewAPI account execution.

Only explicit HTTP credentials are accepted. Responses and exceptions are never
included in results, because either can contain account credentials.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from http.cookiejar import Cookie
from typing import Any, Callable, Protocol, cast
from urllib.parse import urlsplit

import httpx

from utils.acw_challenge import is_acw_challenge, solve_acw_sc_v2
from utils.proxy_validation import valid_socks5_credentials

ORIGINS = {'anyrouter': 'https://anyrouter.top', 'agentrouter': 'https://agentrouter.org'}
_ACW_MAX_REQUESTS = 3
_ACW_USER_AGENT = (
	'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36'
)
_COOKIE_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9a-zA-Z-]+$")
_AUTH_MESSAGES = (
	'not logged in',
	'not_logged_in',
	'unauthorized',
	'invalid token',
	'invalid access token',
	'access token is invalid',
	'token expired',
	'invalid credential',
	'password incorrect',
	'incorrect password',
	'未登录',
	'尚未登录',
	'登录已过期',
	'登录状态已失效',
	'无效的令牌',
	'令牌无效',
	'密码错误',
	'用户名或密码',
)
_CHALLENGE_MESSAGES = (
	'cf-chl-',
	'/cdn-cgi/challenge-platform',
	'cloudflare',
	'turnstile',
	'captcha',
	'验证码',
	'人机验证',
)
_ALREADY_MESSAGES = ('已经签到', '已签到', '重复签到', 'already checked', 'already signed')


class _Sessions(Protocol):
	def load(self, account_id: str, binding: str) -> dict | None: ...

	def save(self, account_id: str, binding: str, state: dict) -> None: ...


class _Failure(Exception):
	def __init__(self, outcome: str, reason: str, **details: Any):
		self.outcome = outcome
		self.reason = reason
		self.details = details
		super().__init__(reason)


class _AcwChallenge(Exception):
	def __init__(self, response: httpx.Response):
		self.response = response
		super().__init__('acw_challenge')


def account_binding(account: dict, config: dict) -> str:
	"""Return a one-way binding for credentials, identity expectations and route."""
	fields = (
		'id',
		'provider',
		'auth_type',
		'cookies',
		'username',
		'password',
		'system_access_token',
		'api_user',
		'expected_username',
		'proxy',
	)
	bound = {key: account.get(key) for key in fields}
	if account.get('proxy') in {None, '', 'default'}:
		bound['proxy_url'] = config.get('proxy_url')
	return hashlib.sha256(json.dumps(bound, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _uid(value: Any) -> str | None:
	if isinstance(value, bool):
		return None
	if isinstance(value, int) and value > 0:
		return str(value)
	if isinstance(value, str) and re.fullmatch(r'[1-9][0-9]*', value.strip()):
		return str(int(value.strip()))
	return None


def _money(value: Any) -> float | None:
	if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
		return None
	return float(value) / 500000


def _retry_after(response: httpx.Response) -> dict:
	value = response.headers.get('retry-after', '').strip()
	try:
		seconds = int(value)
	except ValueError:
		try:
			date = parsedate_to_datetime(value)
			if date.tzinfo is None:
				date = date.replace(tzinfo=timezone.utc)
			seconds = math.ceil((date - datetime.now(timezone.utc)).total_seconds())
		except (ValueError, TypeError, OverflowError):
			return {}
	return {'retry_after_seconds': min(max(seconds, 0), 86400 * 365)}


def _message(payload: dict) -> str:
	return str(payload.get('message') or payload.get('msg') or payload.get('error') or '').lower()


class HttpCheckinRuntime:
	"""One client, bounded known ACW negotiation, no error retry or browser fallback."""

	def __init__(
		self, config: dict, sessions: object, *, client_factory: Callable[..., httpx.AsyncClient] = httpx.AsyncClient
	):
		self.config = config
		self.sessions = cast(_Sessions, sessions)
		self.client_factory = client_factory

	async def balance(self, account: dict, *, on_progress: Callable[[dict], None] | None = None) -> dict:
		"""Read an existing authenticated session; this path never logs in or signs in."""
		return await self.execute(account, on_progress=on_progress, read_only=True)

	async def execute(
		self, account: dict, *, on_progress: Callable[[dict], None] | None = None, read_only: bool = False
	) -> dict:
		self.balance_observations: list[dict] = []
		self.balance_error: dict | None = None
		self._steps: list[dict] = []
		self._current: dict = {}
		self._on_progress = on_progress
		self._stage('prepare')
		result = {
			'id': account.get('id', ''),
			'name': account.get('name', ''),
			'provider': account.get('provider', ''),
			'success': False,
		}
		if account.get('enabled', True) is False:
			return self._finish({**result, 'outcome': 'skipped', 'reason': 'account_disabled'})
		try:
			provider = account.get('provider')
			auth_type = account.get('auth_type')
			if (
				provider not in ORIGINS
				or (provider == 'agentrouter' and auth_type != 'password')
				or (provider == 'anyrouter' and auth_type not in {'cookie', 'password'})
			):
				raise _Failure('failed', 'unsupported_account_configuration')
			origin = ORIGINS[provider]
			proxy = self._proxy(account)
			timeout = self.config.get('http', {}).get('timeout_seconds', 30)
			if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 1 <= timeout <= 300:
				raise _Failure('failed', 'invalid_http_configuration')
			headers = {'Accept': 'application/json'}
			if provider == 'anyrouter':
				headers['User-Agent'] = _ACW_USER_AGENT
			async with self.client_factory(
				base_url=origin,
				timeout=timeout,
				proxy=proxy,
				trust_env=False,
				verify=True,
				follow_redirects=False,
				headers=headers,
			) as client:
				if read_only:
					details = await self._balance(client, account, origin)
				elif provider == 'agentrouter':
					details = await self._agent(client, account)
				else:
					details = await self._any(client, account, origin)
			return self._finish({**result, **details, 'success': True})
		except _Failure as exc:
			return self._finish({**result, 'outcome': exc.outcome, 'reason': exc.reason, **exc.details})
		except (ValueError, TypeError):
			return self._finish({**result, 'outcome': 'failed', 'reason': 'invalid_http_configuration'})

	def _update(self, **details: Any) -> None:
		self._current.update(details)
		self._steps[-1] = dict(self._current)
		if self._on_progress:
			self._on_progress(dict(self._current))

	def _stage(self, stage: str) -> None:
		if self._current and self._current['state'] == 'running':
			self._update(state='completed')
		self._current = {'stage': stage, 'at': datetime.now(timezone.utc).isoformat(), 'state': 'running'}
		self._steps.append(dict(self._current))
		self._update()

	def _finish(self, result: dict) -> dict:
		if result.get('success'):
			self._stage('finished')
			self._update(state='completed')
		else:
			self._update(state='failed')
			result['diagnostic'] = {key: value for key, value in self._current.items() if key not in {'at', 'state'}}
		result['steps'] = [dict(step) for step in self._steps]
		return result

	def _proxy(self, account: dict) -> str | None:
		mode = account.get('proxy')
		if mode == 'direct':
			return None
		if mode in {None, '', 'default'}:
			value = self.config.get('proxy_url')
			if not value:
				if mode == 'default':
					raise _Failure('failed', 'proxy_not_configured')
				return None
		else:
			value = mode
		if (
			not isinstance(value, str)
			or len(value) > 4096
			or any(
				char.isspace() or ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in value
			)
			or '\\' in value
		):
			raise _Failure('failed', 'invalid_proxy_configuration')
		try:
			parsed = urlsplit(value)
			hostname = parsed.hostname
			if not hostname:
				raise ValueError
			try:
				ipaddress.ip_address(hostname)
			except ValueError:
				hostname = hostname.encode('idna').decode('ascii').rstrip('.')
				if len(hostname) > 253 or not all(
					re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label)
					for label in hostname.split('.')
				):
					raise ValueError from None
			if (
				parsed.scheme not in {'http', 'https', 'socks5'}
				or not parsed.port
				or parsed.path not in {'', '/'}
				or parsed.query
				or parsed.fragment
				or (parsed.scheme == 'socks5' and not valid_socks5_credentials(parsed))
			):
				raise ValueError
		except (ValueError, UnicodeError):
			raise _Failure('failed', 'invalid_proxy_configuration') from None
		return value

	async def _request(
		self, client: httpx.AsyncClient, method: str, path: str, *, side_effect: bool = False, **kwargs: Any
	) -> dict:
		stage = self._current['stage']
		login = method == 'POST' and path == '/api/user/login'
		allowed = (
			client.base_url == httpx.URL(ORIGINS['anyrouter'])
			and not side_effect
			and ((method == 'GET' and path == '/api/user/self') or login)
		)
		for attempt in range(1, _ACW_MAX_REQUESTS + 1):
			try:
				return await self._request_once(client, method, path, side_effect=side_effect, **kwargs)
			except _AcwChallenge as challenge:
				if not allowed:
					raise _Failure(
						'uncertain' if method == 'POST' or side_effect else 'blocked',
						'acw_challenge_requires_confirmation'
						if method == 'POST' or side_effect
						else 'acw_challenge_unsupported',
					) from None
				self._update(state='verification_required')
				self._stage('acw_verification')
				self._update(
					method=method,
					path=path,
					http_status=challenge.response.status_code,
					request_attempt=attempt,
					max_attempts=_ACW_MAX_REQUESTS,
					acw_challenges=attempt,
				)
				text = challenge.response.text
				value = solve_acw_sc_v2(text) if len(text) <= 100000 else None
				if value is None:
					raise _Failure('blocked', 'acw_challenge_unsupported') from None
				if attempt == _ACW_MAX_REQUESTS:
					raise _Failure('blocked', 'acw_challenge_limit') from None
				if not client.build_request(method, path).headers.get('cookie'):
					raise _Failure('blocked', 'acw_cookie_context_missing') from None
				for cookie in list(client.cookies.jar):
					if cookie.name == 'acw_sc__v2' and cookie.domain in {'anyrouter.top', '.anyrouter.top'}:
						client.cookies.jar.clear(cookie.domain, cookie.path, cookie.name)
				self._cookies(client, {'acw_sc__v2': value}, 'anyrouter.top')
				self._update(state='completed')
				self._stage(stage)
				self._update(request_attempt=attempt + 1, max_attempts=_ACW_MAX_REQUESTS, acw_challenges=attempt)
		raise _Failure('blocked', 'acw_challenge_limit')

	async def _request_once(
		self, client: httpx.AsyncClient, method: str, path: str, *, side_effect: bool = False, **kwargs: Any
	) -> dict:
		mutation = method == 'POST' or side_effect
		self._update(method=method, path=path, timeout_seconds=self.config.get('http', {}).get('timeout_seconds', 30))
		try:
			response = await client.request(method, path, **kwargs)
		except httpx.RequestError as exc:
			error_type = next(
				(
					name
					for category, name in (
						(httpx.TimeoutException, 'TimeoutException'),
						(httpx.ProxyError, 'ProxyError'),
						(httpx.ConnectError, 'ConnectError'),
						(httpx.NetworkError, 'NetworkError'),
						(httpx.ProtocolError, 'ProtocolError'),
					)
					if isinstance(exc, category)
				),
				'RequestError',
			)
			self._update(error_type=error_type)
			if isinstance(exc, httpx.ProxyError) and str(exc) == 'Invalid username/password':
				raise _Failure('failed', 'proxy_authentication_failed') from None
			raise _Failure(
				'uncertain' if mutation else 'failed', 'request_result_unknown' if mutation else 'network_error'
			) from None
		self._update(http_status=response.status_code)
		if not 200 <= response.status_code < 300:
			self._update(error_type='HTTPStatusError')
		if response.status_code == 429:
			raise _Failure('rate_limited', 'rate_limited', **_retry_after(response))
		if 300 <= response.status_code < 400:
			raise _Failure('blocked', 'response_redirected')
		if response.status_code >= 500:
			raise _Failure(
				'uncertain' if mutation else 'failed', 'request_result_unknown' if mutation else 'service_unavailable'
			)
		text = response.text[:100000].lower()
		if response.headers.get('cf-mitigated') == 'challenge':
			raise _Failure('blocked', 'interactive_verification_required')
		if 'text/html' in response.headers.get('content-type', '').lower() or text.lstrip().startswith(
			('<!doctype html', '<html')
		):
			if any(marker in text for marker in _CHALLENGE_MESSAGES):
				raise _Failure('blocked', 'interactive_verification_required')
			if is_acw_challenge(response.text):
				raise _AcwChallenge(response)
			raise _Failure('blocked', 'html_response_received')
		try:
			payload = response.json()
		except ValueError:
			if any(marker in text for marker in _CHALLENGE_MESSAGES):
				raise _Failure('blocked', 'interactive_verification_required') from None
			if response.status_code == 401:
				raise _Failure('needs_credentials', 'credentials_rejected') from None
			if response.status_code == 403:
				raise _Failure('blocked', 'access_blocked') from None
			raise _Failure('uncertain' if mutation else 'failed', 'invalid_json_response') from None
		if not isinstance(payload, dict):
			raise _Failure('uncertain' if mutation else 'failed', 'invalid_json_response')
		message = _message(payload)
		if any(marker in message for marker in _CHALLENGE_MESSAGES):
			raise _Failure('blocked', 'interactive_verification_required')
		if response.status_code == 401 or any(marker in message for marker in _AUTH_MESSAGES):
			raise _Failure('needs_credentials', 'credentials_rejected')
		if response.status_code == 403:
			raise _Failure('blocked', 'access_blocked')
		if not 200 <= response.status_code < 300:
			raise _Failure('failed', 'http_request_rejected')
		return payload

	def _verify(self, payload: dict, account: dict, saved_id: str | None = None) -> dict:
		data = payload.get('data')
		if payload.get('success') is not True or not isinstance(data, dict) or not _uid(data.get('id')):
			if payload.get('success') is False:
				raise _Failure('failed', 'user_info_rejected')
			raise _Failure('failed', 'invalid_user_info')
		actual = _uid(data['id'])
		expected_id = _uid(account.get('api_user'))
		if (expected_id and actual != expected_id) or (saved_id and actual != saved_id):
			raise _Failure('needs_credentials', 'account_identity_mismatch')
		expected_name = account.get('expected_username', '')
		if expected_name and data.get('username') != expected_name:
			raise _Failure('needs_credentials', 'account_identity_mismatch')
		return data

	async def _agent(self, client: httpx.AsyncClient, account: dict) -> dict:
		username, password = account.get('username'), account.get('password')
		if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
			raise _Failure('needs_credentials', 'username_and_password_required')
		if account.get('api_user') and not _uid(account['api_user']):
			raise _Failure('needs_credentials', 'login_identity_unverified')
		# Signing in is the write operation. A fresh client never restores a prior
		# session, and an ambiguous response must not cause another login attempt.
		self._stage('password_login')
		login = await self._request(
			client,
			'POST',
			'/api/user/login',
			params={'turnstile': ''},
			json={'username': username, 'password': password},
			headers={'X-Requested-With': 'XMLHttpRequest'},
		)
		if login.get('success') is False:
			raise _Failure('needs_credentials', 'password_login_rejected')
		self._stage('verify_identity')
		try:
			user = self._verify(login, account)
		except _Failure as exc:
			if exc.reason == 'invalid_user_info':
				raise _Failure('uncertain', 'agent_checkin_result_unknown') from None
			raise
		self._stage('verify_result')
		checked_in = user.get('checked_in')
		if type(checked_in) is not bool:
			raise _Failure('uncertain', 'agent_checkin_result_unknown')
		self._update(checked_in=checked_in)
		if not checked_in:
			raise _Failure('failed', 'agent_checkin_not_confirmed', checked_in=False)
		# Login responses contain placeholder quota fields on the live site; do
		# not present them as an observed balance or invent a reward amount.
		if self.config.get('monitoring', {}).get('enabled', False):
			try:
				self._save_session(client, account, str(user['id']))
				self._stage('read_balance')
				observed = self._verify(
					await self._request(client, 'GET', '/api/user/self', headers={'new-api-user': str(user['id'])}),
					account,
					str(user['id']),
				)
				self._observe(observed)
			except _Failure as exc:
				self.balance_error = {'outcome': exc.outcome, 'reason': exc.reason, **exc.details}
				self._update(state='failed')
			except Exception:
				self.balance_error = {'outcome': 'failed', 'reason': 'balance_collection_failed'}
				self._update(state='failed')
		return {'outcome': 'success', 'reason': 'agent_checkin_verified', 'checked_in': True}

	def _observe(self, user: dict) -> None:
		self.balance_observations.append(
			{key: user.get(key) for key in ('id', 'quota', 'used_quota', 'today_income')}
			| {'observed_at': datetime.now(timezone.utc).timestamp()}
		)

	def _save_session(self, client: httpx.AsyncClient, account: dict, user_id: str) -> None:
		host = urlsplit(str(client.base_url)).hostname or ''
		cookies = [
			{'name': item.name, 'value': item.value, 'domain': item.domain, 'path': item.path, 'expires': item.expires}
			for item in client.cookies.jar
			if item.domain in {host, '.' + host}
		]
		try:
			self.sessions.save(
				str(account['id']), account_binding(account, self.config), {'api_user': user_id, 'cookies': cookies}
			)
		except Exception:
			raise _Failure('failed', 'session_save_failed') from None

	async def _balance(self, client: httpx.AsyncClient, account: dict, origin: str) -> dict:
		self._stage('load_session')
		state = self._load(account, account_binding(account, self.config))
		host = urlsplit(origin).hostname or ''
		saved_id = _uid(state.get('api_user')) if state else None
		user_id = _uid(account.get('api_user'))
		if state:
			if not saved_id:
				raise _Failure('failed', 'invalid_saved_session')
			if user_id and saved_id != user_id:
				raise _Failure('needs_credentials', 'account_identity_mismatch')
			self._cookies(client, state.get('cookies'), host, saved=True)
			user_id = saved_id
		elif account['provider'] == 'anyrouter' and account['auth_type'] == 'cookie':
			self._cookies(client, account.get('cookies'), host)
		else:
			raise _Failure('needs_credentials', 'balance_session_required')
		if not user_id:
			raise _Failure('needs_credentials', 'cookie_user_id_required')
		if not client.build_request('GET', '/api/user/self').headers.get('cookie'):
			raise _Failure('needs_credentials', 'balance_session_required')
		self._stage('read_balance')
		user = self._verify(
			await self._request(client, 'GET', '/api/user/self', headers={'new-api-user': user_id}), account, user_id
		)
		self._observe(user)
		return {'outcome': 'success', 'reason': 'balance_refreshed'}

	def _load(self, account: dict, binding: str) -> dict | None:
		try:
			state = self.sessions.load(str(account['id']), binding)
		except Exception:
			raise _Failure('failed', 'session_load_failed') from None
		if state is not None and not isinstance(state, dict):
			raise _Failure('failed', 'invalid_saved_session')
		return state

	def _cookies(self, client: httpx.AsyncClient, cookies: Any, host: str, *, saved: bool = False) -> None:
		if saved:
			if not isinstance(cookies, list):
				raise _Failure('failed', 'invalid_saved_session')
			items = cookies
		else:
			if isinstance(cookies, str):
				parts = cookies.split(';')
				if not cookies.strip() or any('=' not in part for part in parts if part.strip()):
					raise _Failure('needs_credentials', 'invalid_cookie_configuration')
				cookies = dict(part.strip().split('=', 1) for part in parts if part.strip())
			if not isinstance(cookies, dict) or not cookies:
				raise _Failure('needs_credentials', 'invalid_cookie_configuration')
			items = [{'name': name, 'value': value, 'domain': host, 'path': '/'} for name, value in cookies.items()]
		for item in items:
			if not isinstance(item, dict):
				raise _Failure('failed', 'invalid_saved_session')
			name, value = item.get('name'), item.get('value')
			domain, path = item.get('domain', host), item.get('path', '/')
			if (
				not isinstance(name, str)
				or not _COOKIE_NAME.fullmatch(name)
				or not isinstance(value, str)
				or any(char in value for char in '\r\n;')
				or domain not in {host, '.' + host}
				or not isinstance(path, str)
				or not path.startswith('/')
			):
				raise _Failure('needs_credentials', 'invalid_cookie_configuration')
			expires = item.get('expires')
			if expires is not None and (isinstance(expires, bool) or not isinstance(expires, int)):
				raise _Failure('failed', 'invalid_saved_session')
			client.cookies.jar.set_cookie(
				Cookie(
					0,
					name,
					value,
					None,
					False,
					domain,
					domain.startswith('.'),
					domain.startswith('.'),
					path,
					True,
					True,
					expires,
					expires is None,
					None,
					None,
					{},
					False,
				)
			)

	async def _any(self, client: httpx.AsyncClient, account: dict, origin: str) -> dict:
		self._stage('load_session')
		binding = account_binding(account, self.config)
		state = self._load(account, binding)
		host = urlsplit(origin).hostname or ''
		user_id = _uid(account.get('api_user'))
		saved_id = _uid(state.get('api_user')) if state else None
		if state and not saved_id:
			raise _Failure('failed', 'invalid_saved_session')
		if saved_id and user_id and saved_id != user_id:
			raise _Failure('needs_credentials', 'account_identity_mismatch')
		user_id = user_id or saved_id
		if account['auth_type'] == 'cookie' and not user_id:
			raise _Failure('needs_credentials', 'cookie_user_id_required')
		if state:
			self._cookies(client, state.get('cookies'), host, saved=True)
		elif account['auth_type'] == 'cookie':
			self._cookies(client, account.get('cookies'), host)
		before = None
		if state or account['auth_type'] == 'cookie':
			self._stage('verify_identity')
			try:
				before = self._verify(
					await self._request(client, 'GET', '/api/user/self', headers={'new-api-user': user_id}),
					account,
					saved_id,
				)
			except _Failure as exc:
				self._update(state='failed')
				if account['auth_type'] != 'password' or exc.reason != 'credentials_rejected':
					raise
		if before is None:
			username, password = account.get('username'), account.get('password')
			if not isinstance(username, str) or not username or not isinstance(password, str) or not password:
				raise _Failure('needs_credentials', 'username_and_password_required')
			client.cookies.clear()
			self._stage('password_login')
			login = await self._request(
				client,
				'POST',
				'/api/user/login',
				json={'username': username, 'password': password},
				headers={'X-Requested-With': 'XMLHttpRequest'},
			)
			if login.get('success') is not True:
				raise _Failure('needs_credentials', 'password_login_rejected')
			login_data = login.get('data')
			login_id = _uid(login_data.get('id')) if isinstance(login_data, dict) else None
			if login_id and ((saved_id and login_id != saved_id) or (user_id and login_id != user_id)):
				raise _Failure('needs_credentials', 'account_identity_mismatch')
			user_id = user_id or login_id
			if not user_id:
				raise _Failure('needs_credentials', 'login_identity_unverified')
			self._stage('verify_identity')
			before = self._verify(
				await self._request(client, 'GET', '/api/user/self', headers={'new-api-user': user_id}),
				account,
				user_id,
			)
		user_id = cast(str, _uid(before['id']))
		if self.config.get('monitoring', {}).get('enabled', False):
			self._observe(before)
		self._stage('checkin')
		payload = await self._request(
			client, 'POST', '/api/user/sign_in', headers={'new-api-user': user_id, 'Content-Type': 'application/json'}
		)
		already = any(marker in _message(payload) for marker in _ALREADY_MESSAGES)
		accepted = payload.get('success') is True
		if 'success' not in payload:
			accepted = (type(payload.get('ret')) is int and payload['ret'] == 1) or (
				type(payload.get('code')) is int and payload['code'] == 0
			)
		if not accepted and not already:
			raise _Failure('failed', 'checkin_rejected')
		self._stage('verify_result')
		try:
			after = self._verify(
				await self._request(client, 'GET', '/api/user/self', headers={'new-api-user': user_id}),
				account,
				user_id,
			)
		except _Failure as exc:
			raise _Failure('uncertain', 'checkin_verification_failed', verification_reason=exc.reason) from None
		if self.config.get('monitoring', {}).get('enabled', False):
			self._observe(after)
		cookies = [
			{
				'name': cookie.name,
				'value': cookie.value,
				'domain': cookie.domain,
				'path': cookie.path,
				'expires': cookie.expires,
			}
			for cookie in client.cookies.jar
			if cookie.domain in {host, '.' + host}
		]
		self._stage('save_session')
		try:
			self.sessions.save(str(account['id']), binding, {'api_user': user_id, 'cookies': cookies})
		except Exception:
			raise _Failure('uncertain', 'session_save_failed') from None
		details: dict[str, Any] = {
			'outcome': 'already_checked_in' if already else 'success',
			'reason': 'already_checked_in' if already else 'checkin_verified',
		}
		for key, user in (('balance_before', before), ('balance_after', after)):
			balance = _money(user.get('quota'))
			if balance is not None:
				details[key] = balance
		values = [_money(user.get(key)) for user in (before, after) for key in ('quota', 'used_quota')]
		if all(value is not None for value in values):
			quota_before, used_before, quota_after, used_after = cast(list[float], values)
			reward = quota_after + used_after - quota_before - used_before
			if reward >= 0:
				details['reward'] = round(reward, 10)
		return details
