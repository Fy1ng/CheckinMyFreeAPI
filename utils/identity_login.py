"""Independent identity verification using the shared encrypted browser profile."""

from __future__ import annotations

import asyncio
import os
import re
import secrets
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

from playwright.async_api import Error as BrowserError

from utils.browser import launch_login_context, load_browser_login_settings
from utils.browser_backend import browser_compatibility, browser_storage_paths, get_browser_engine
from utils.config import AccountConfig, AppConfig
from utils.manual_login import ManualLoginError, ManualTakeover
from utils.oauth import AuthError
from utils.proxy import resolve_proxy
from utils.secure_state import SnapshotStore, state_key

IDENTITY_ORIGINS = {'linuxdo': 'https://linux.do', 'github': 'https://github.com'}
CHALLENGE_VISIBLE = """Boolean(
  [...document.querySelectorAll('#challenge-form, #challenge-running, #challenge-stage, [id^="cf-chl-"]')]
    .some(element => element.getClientRects().length > 0) ||
  (/just a moment|checking your browser|请稍候|正在验证/i.test(document.title) &&
    document.querySelector('script[src*="/cdn-cgi/challenge-platform/"]'))
)"""
LINUXDO_LOGIN_VISIBLE = """[...document.querySelectorAll('#login-form, #login-account-name, #login-account-password')]
  .some(element => element.getClientRects().length > 0)"""


class IdentityProbeError(AuthError):
	def __init__(self, reason: str, kind: str, result: dict):
		super().__init__(reason)
		content_kind = result.get('content_kind')
		self.diagnostics = {
			'provider': kind,
			'endpoint': '/session/current.json' if kind == 'linuxdo' else '/settings/profile',
			'http_status': 403,
			'response_kind': 'cloudflare_challenge'
			if result.get('cf_challenge') is True
			else content_kind
			if content_kind in {'json', 'html'}
			else 'other',
		}


def identity_proxy(config: AppConfig, alias: str, accounts: list[AccountConfig]) -> str | None:
	"""Resolve the same identity network policy that account OAuth will later use."""
	identity = config.identities.get(alias)
	if identity is None or identity.type not in IDENTITY_ORIGINS:
		raise AuthError('OAUTH_IDENTITY_NOT_CONFIGURED')
	resolved: set[str | None] = set()
	for account in accounts:
		if not account.auth or account.auth.get('identity') != alias:
			continue
		if account.auth.get('type') != identity.type:
			raise AuthError('OAUTH_IDENTITY_NOT_CONFIGURED')
		provider = config.get_provider(account.provider)
		if provider is None:
			raise AuthError('UNKNOWN_PROVIDER')
		setting = identity.proxy if identity.proxy is not None else account.proxy
		proxy = resolve_proxy(setting, use_proxy=provider.use_proxy)
		if account.proxy is not None and resolve_proxy(account.proxy, use_proxy=provider.use_proxy) != proxy:
			raise AuthError('ACCOUNT_IDENTITY_PROXY_CONFLICT')
		resolved.add(proxy)
	if len(resolved) > 1:
		raise AuthError('SHARED_IDENTITY_PROXY_CONFLICT')
	if resolved:
		return resolved.pop()
	return resolve_proxy(identity.proxy)


def _validated_user(user_id, username) -> dict:
	if (
		isinstance(user_id, bool)
		or not isinstance(user_id, (int, str))
		or not re.fullmatch(r'[1-9][0-9]{0,19}', str(user_id))
		or not isinstance(username, str)
		or not username.strip()
		or len(username) > 128
		or any(ord(character) < 32 for character in username)
	):
		raise AuthError('INVALID_IDENTITY_RESPONSE')
	return {'user_id': str(user_id), 'username': username}


def check_identity_subject(metadata: dict, kind: str, user: dict) -> None:
	"""An alias stays bound to its first verified platform subject, even after rename."""
	if 'identity_login' not in metadata:
		return
	previous = metadata['identity_login']
	if not isinstance(previous, dict) or previous.get('type') != kind or not previous.get('user_id'):
		raise AuthError('INVALID_SAVED_IDENTITY')
	if previous['user_id'] != user['user_id']:
		raise AuthError('IDENTITY_ACCOUNT_MISMATCH')


async def probe_identity_user(page, kind: str, *, allow_fetch: bool = True) -> dict | None:
	"""Verify the current self subject on the exact official HTTPS origin.

	GitHub's public REST /user cannot authenticate a browser cookie. Instead the
	protected same-origin settings page must return its current actor ID and two
	matching login markers. Missing/changed markup fails closed.
	"""
	origin = IDENTITY_ORIGINS.get(kind)
	if origin is None:
		raise AuthError('UNSUPPORTED_OAUTH_PROVIDER')
	if page.is_closed():
		raise AuthError('IDENTITY_BROWSER_CLOSED')
	if not (page.url == origin or page.url.startswith(origin + '/')):
		return None
	path = '/session/current.json' if kind == 'linuxdo' else '/settings/profile'
	try:
		result = await page.evaluate(
			"""async ({url, kind, allowFetch = true}) => {
		  if (location.origin !== new URL(url).origin) return {pending: true};
		  // Leave interactive verification to the user before probing authentication.
		  if (__IDENTITY_CHALLENGE__) return {challenge: true};
		  if (kind === 'linuxdo' && (__LINUXDO_LOGIN__)) return {login_required: true};
		  // Discourse renders currentUser only for the authenticated session.
		  // Read that first-party bootstrap without navigating to a challenged API.
		  const navigation = performance.getEntriesByType('navigation')[0];
		  if (kind === 'linuxdo' && navigation?.responseStatus === 200) {
		    const nodes = document.querySelectorAll('#data-preloaded');
		    const actor = document.querySelector('#current-user');
		    if (nodes.length === 1 && actor?.getClientRects().length > 0) {
		      const text = nodes[0].getAttribute('data-preloaded') || nodes[0].textContent;
		      if (text?.length <= 2097152) {
		        try {
		          const preload = JSON.parse(text);
		          const user = typeof preload.currentUser === 'string' ? JSON.parse(preload.currentUser) : preload.currentUser;
		          if (user && typeof user === 'object' && !Array.isArray(user)) {
		            return {status: 200, url, data: {current_user: {id: user.id, username: user.username}}};
		          }
		        } catch {}
		      }
		    }
		  }
		  if (!allowFetch) return {pending: true};
		  try {
		    const response = await fetch(url, {method: 'GET', credentials: 'same-origin',
		      headers: kind === 'linuxdo' ? {Accept: 'application/json', 'X-Requested-With': 'XMLHttpRequest'} : {},
		      cache: 'no-store', redirect: 'manual', referrerPolicy: 'no-referrer',
		      signal: AbortSignal.timeout(15000)});
		    if (response.type === 'opaqueredirect') return {redirected: true};
		    const text = await response.text();
		    if (text.length > 2097152) return {status: response.status, url: response.url};
		    let data = null;
		    if (response.url === url) {
		      if (kind === 'linuxdo') { try { data = JSON.parse(text); } catch {} }
		      else if (response.status === 200) {
		        const document = new DOMParser().parseFromString(text, 'text/html');
		        const marker = (name) => {
		          const nodes = document.querySelectorAll(`meta[name="${name}"]`);
		          return nodes.length === 1 ? nodes[0].getAttribute('content') : null;
		        };
		        data = {login: marker('user-login'), actor_login: marker('octolytics-actor-login'),
		          actor_id: marker('octolytics-actor-id')};
		      }
		    }
		    const contentType = response.headers.get('content-type') || '';
		    return {status: response.status, url: response.url, data,
		      cf_challenge: response.headers.get('cf-mitigated') === 'challenge',
		      content_kind: contentType.includes('application/json') ? 'json' : contentType.includes('text/html') ? 'html' : 'other'};
		  } catch { return {status: 0}; }
		}""".replace('__IDENTITY_CHALLENGE__', CHALLENGE_VISIBLE).replace('__LINUXDO_LOGIN__', LINUXDO_LOGIN_VISIBLE),
			{'url': origin + path, 'kind': kind, **({'allowFetch': False} if not allow_fetch else {})},
		)
	except BrowserError as error:
		if page.is_closed():
			raise AuthError('IDENTITY_BROWSER_CLOSED') from None
		if 'Execution context was destroyed' in str(error) or 'Cannot find context' in str(error):
			return None
		raise
	if not isinstance(result, dict):
		raise AuthError('INVALID_IDENTITY_RESPONSE')
	if result.get('redirected') is True:
		return None
	if result.get('challenge') is True:
		return None
	if result.get('login_required') is True:
		return None
	if result.get('pending') is True:
		return None
	status = result.get('status', 0)
	if status == 401:
		return None
	# Discourse's SessionController.current returns 404 when there is no user.
	if kind == 'linuxdo' and status == 404:
		return None
	if status == 429:
		raise AuthError('RATE_LIMITED')
	if status == 403:
		# Login-required Discourse sites can reject an anonymous JSON request with
		# this explicit authentication error. Keep the original browser available
		# for login; unrelated 403 responses must still stop without retrying.
		data = result.get('data')
		if (
			kind == 'linuxdo'
			and result.get('url') == origin + path
			and isinstance(data, dict)
			and data.get('error_type') == 'not_logged_in'
		):
			return None
		if kind == 'linuxdo' and result.get('url') == origin + path and result.get('cf_challenge') is True:
			raise IdentityProbeError('IDENTITY_CHALLENGE_REQUIRED', kind, result)
		raise IdentityProbeError('ACCESS_BLOCKED', kind, result)
	if not isinstance(status, int) or status == 0 or status >= 500:
		raise AuthError('NETWORK_OR_SERVICE_ERROR')
	if status != 200 or result.get('url') != origin + path or not isinstance(result.get('data'), dict):
		raise AuthError('INVALID_IDENTITY_RESPONSE')
	data = result['data']
	if kind == 'linuxdo':
		user = data.get('current_user')
		if user is None:
			return None
		if not isinstance(user, dict):
			raise AuthError('INVALID_IDENTITY_RESPONSE')
		return _validated_user(user.get('id'), user.get('username'))
	login = data.get('login')
	if not isinstance(login, str) or not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?', login):
		raise AuthError('INVALID_IDENTITY_RESPONSE')
	if data.get('actor_login') != login:
		raise AuthError('INVALID_IDENTITY_RESPONSE')
	return _validated_user(data.get('actor_id'), login)


class IdentityLoginRuntime:
	def __init__(
		self,
		config: AppConfig,
		store: SnapshotStore,
		*,
		notify_ready=None,
		accounts: list[AccountConfig] | None = None,
		bound_subjects: dict[str, str] | None = None,
	):
		self.config = config
		self.store = store
		self.accounts = accounts or []
		self.bound_subjects = bound_subjects or {}
		self.notify_ready = notify_ready
		self._lock = asyncio.Lock()
		self.diagnostics: dict = {}
		self.manual_timeout = int(os.getenv('CHECKIN_MANUAL_TIMEOUT_SECONDS', '600'))
		if not 30 <= self.manual_timeout <= 1800:
			raise AuthError('INVALID_MANUAL_TIMEOUT')

	@classmethod
	def from_environment(
		cls,
		config: AppConfig,
		*,
		notify_ready=None,
		accounts: list[AccountConfig] | None = None,
		bound_subjects: dict[str, str] | None = None,
	):
		engine = get_browser_engine()
		root, cache_file = browser_storage_paths(
			Path(os.getenv('CHECKIN_AUTH_ROOT', '.auth-state')),
			Path(os.getenv('CHECKIN_AUTH_CACHE_FILE', '.auth-cache/auth-state.enc')),
			engine,
		)
		store = SnapshotStore(
			root,
			cache_file,
			os.getenv('CHECKIN_STATE_KEY', ''),
			scope=os.getenv('CHECKIN_STATE_SCOPE', os.getenv('GITHUB_REPOSITORY', 'local-test')),
			compatibility=browser_compatibility(engine),
		)
		try:
			print(f'[STATE] Encrypted authentication snapshot: {store.restore()}')
			return cls(config, store, notify_ready=notify_ready, accounts=accounts, bound_subjects=bound_subjects)
		except BaseException:
			store.close()
			raise

	async def execute(self, alias: str) -> dict:
		async with self._lock:
			try:
				return await self._execute(alias)
			except ManualLoginError:
				raise AuthError('MANUAL_LOGIN_UNAVAILABLE') from None
			except TimeoutError:
				raise AuthError('MANUAL_LOGIN_TIMED_OUT') from None
			except BrowserError as error:
				if type(error).__name__ == 'TargetClosedError':
					raise AuthError('IDENTITY_BROWSER_CLOSED') from None
				raise

	async def _execute(self, alias: str) -> dict:
		proxy = identity_proxy(self.config, alias, self.accounts)
		kind = self.config.identities[alias].type
		profile_key = state_key(f'identity:{kind}:{alias}')
		metadata = dict(self.store.read_record('metadata', profile_key) or {})
		if 'fingerprint' not in metadata:
			metadata['fingerprint'] = secrets.randbelow(2**31 - 1) + 1
		profile = self.store.prepare_profile(profile_key)
		settings = replace(
			load_browser_login_settings(profile_key, kind, persist_profile=True), profile_dir=profile, headless=False
		)
		context = await launch_login_context(
			settings, proxy_server=proxy, fingerprint_seed=metadata['fingerprint'], secure=True
		)
		verified = None
		try:
			page = await context.new_page()
			for previous_page in context.pages:
				if previous_page != page:
					await previous_page.close()
			response = await page.goto(
				IDENTITY_ORIGINS[kind] + '/login', wait_until='domcontentloaded', timeout=settings.wait_timeout_ms
			)
			if response is not None and response.status == 429:
				raise AuthError('RATE_LIMITED')
			if response is not None and response.status >= 500:
				if await page.evaluate('() => ' + CHALLENGE_VISIBLE) is not True:
					raise AuthError('NETWORK_OR_SERVICE_ERROR')
			try:
				user = await self._probe(page, kind)
			except IdentityProbeError as error:
				if error.reason != 'IDENTITY_CHALLENGE_REQUIRED':
					raise
				user = None
			if user is None:
				await page.bring_to_front()
				user = await self._manual(page, kind, alias)
			check_identity_subject(metadata, kind, user)
			if alias in self.bound_subjects and self.bound_subjects[alias] != user['user_id']:
				raise AuthError('IDENTITY_ACCOUNT_MISMATCH')
			verified = {**user, 'verified_at': datetime.now(timezone.utc).isoformat()}
		finally:
			await context.close()
		if verified is None:
			raise AuthError('IDENTITY_LOGIN_NOT_VERIFIED')
		metadata['identity_login'] = {'type': kind, **verified}
		self.store.commit_profile(profile_key, profile)
		self.store.write_record('metadata', profile_key, metadata)
		self.store.save()
		return verified

	async def _probe(self, page, kind: str, *, allow_fetch: bool = True) -> dict | None:
		try:
			return await probe_identity_user(page, kind, allow_fetch=allow_fetch)
		except IdentityProbeError as error:
			self.diagnostics = error.diagnostics
			raise

	async def _manual(self, page, kind: str, alias: str) -> dict:
		async with ManualTakeover(self.manual_timeout) as takeover:
			deadline = time.monotonic() + self.manual_timeout
			async with asyncio.timeout(self.manual_timeout):
				if self.notify_ready is not None:
					try:
						await asyncio.wait_for(self.notify_ready(takeover.url, alias, self.manual_timeout), timeout=20)
					except Exception:
						print('[MANUAL] Notification unavailable; use the current task in WebUI')
				while time.monotonic() < deadline:
					user = await self._probe(page, kind, allow_fetch=kind != 'linuxdo')
					if user is not None:
						return user
					await asyncio.sleep(min(2, max(0, deadline - time.monotonic())))
				raise TimeoutError

	def close(self) -> None:
		self.store.close()
