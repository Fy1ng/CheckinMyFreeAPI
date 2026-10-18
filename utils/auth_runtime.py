"""Serial identity sessions and browser-native check-in with interactive recovery."""

from __future__ import annotations

import asyncio
import json
import os
import re
import secrets
import time
from dataclasses import dataclass, field, replace
from importlib.metadata import version
from pathlib import Path
from typing import cast
from urllib.parse import urlsplit

from utils.browser import launch_login_context, load_browser_login_settings, login_with_email_form, wait_for_site_ready
from utils.config import AccountConfig, AppConfig, ProviderConfig
from utils.manual_login import ManualLoginError, ManualTakeover
from utils.oauth import AuthError, ManualLoginRequired, OAuthAttempt, OAuthFlow, browser_json, origin_of
from utils.proxy import resolve_proxy
from utils.secure_state import SnapshotStore, state_key


@dataclass(frozen=True)
class AccountPlan:
	account_key: str
	profile_key: str
	binding: str
	proxy: str | None = field(repr=False)
	kind: str


def build_plans(accounts: list[AccountConfig], config: AppConfig) -> list[AccountPlan]:
	plans = []
	identities: dict[str, str | None] = {}
	seen = set()
	for index, account in enumerate(accounts):
		provider = config.get_provider(account.provider)
		if provider is None:
			raise AuthError('UNKNOWN_PROVIDER')
		origin = origin_of(provider.domain)
		if urlsplit(origin).scheme != 'https' or provider.domain.rstrip('/') != origin:
			raise AuthError('PROVIDER_REQUIRES_HTTPS_ORIGIN')
		key = state_key(account.id or f'{account.provider}:{account.get_display_name(index)}')
		if key in seen:
			raise AuthError('DUPLICATE_ACCOUNT_ID')
		seen.add(key)
		kind = 'site'
		proxy_setting = account.proxy
		identity_key = ''
		if account.has_oauth():
			assert account.auth is not None
			kind = account.auth['type']
			identity_key = account.auth['identity']
			identity = config.identities.get(identity_key)
			if identity is None or identity.type != kind:
				raise AuthError('OAUTH_IDENTITY_NOT_CONFIGURED')
			if identity.proxy is not None:
				proxy_setting = identity.proxy
			if not account.api_user and not account.expected_username:
				raise AuthError('EXPECTED_ACCOUNT_REQUIRED')
		proxy = resolve_proxy(proxy_setting, use_proxy=provider.use_proxy)
		if account.has_oauth():
			if account.proxy is not None and resolve_proxy(account.proxy, use_proxy=provider.use_proxy) != proxy:
				raise AuthError('ACCOUNT_IDENTITY_PROXY_CONFLICT')
			if identity_key in identities and identities[identity_key] != proxy:
				raise AuthError('SHARED_IDENTITY_PROXY_CONFLICT')
			identities[identity_key] = proxy
		binding = state_key(
			json.dumps(
				{
					'origin': origin,
					'kind': kind,
					'identity': identity_key,
					'proxy': proxy,
					'api_user': account.api_user,
					'expected_username': account.expected_username,
					'email': account.email,
				},
				sort_keys=True,
			)
		)
		profile_key = (
			state_key(f'identity:{kind}:{identity_key}') if identity_key else state_key(f'site:{key}:{binding}')
		)
		plans.append(AccountPlan(key, profile_key, binding, proxy, kind))
	return plans


def check_expected_user(account: AccountConfig, user: dict, *, saved_id: str | None = None) -> str:
	user_id = user.get('id')
	if user_id is None or isinstance(user_id, bool) or not str(user_id):
		raise AuthError('MISSING_ACCOUNT_ID')
	actual = str(user_id)
	if account.api_user is not None and actual != str(account.api_user):
		raise AuthError('ACCOUNT_MISMATCH')
	if saved_id is not None and actual != saved_id:
		raise AuthError('ACCOUNT_MISMATCH')
	if account.expected_username and user.get('username') != account.expected_username:
		raise AuthError('ACCOUNT_MISMATCH')
	return actual


def balance_result(user: dict) -> dict:
	quota = round(user.get('quota', 0) / 500000, 2)
	used = round(user.get('used_quota', 0) / 500000, 2)
	return {
		'success': True,
		'quota': quota,
		'used_quota': used,
		'display': ':money: Current balance: $' + str(quota) + ', Used: $' + str(used),
	}


class AuthenticationRuntime:
	def __init__(self, accounts: list[AccountConfig], config: AppConfig, store: SnapshotStore, *, notify_ready=None):
		self.config = config
		self.store = store
		self.plans = build_plans(accounts, config)
		self.notify_ready = notify_ready
		self._locks: dict[str, asyncio.Lock] = {}
		self._metadata: dict[str, dict] = {}
		self._manual_failures: set[str] = set()
		self._manual_spent = 0.0
		self.persistence_failed = False
		self.manual_timeout = int(os.getenv('CHECKIN_MANUAL_TIMEOUT_SECONDS', '600'))
		self.manual_budget = int(os.getenv('CHECKIN_MANUAL_TOTAL_TIMEOUT_SECONDS', '1800'))
		if not 30 <= self.manual_timeout <= 1800 or not 30 <= self.manual_budget <= 3600:
			raise AuthError('INVALID_MANUAL_TIMEOUT')

	@classmethod
	def from_environment(cls, accounts: list[AccountConfig], config: AppConfig, *, notify_ready=None):
		from cloakbrowser.config import get_chromium_version

		compatibility = f'{os.name}:{version("cloakbrowser")}:{get_chromium_version()}'
		store = SnapshotStore(
			Path(os.getenv('CHECKIN_AUTH_ROOT', '.auth-state')),
			Path('.auth-cache/auth-state.enc'),
			os.getenv('CHECKIN_STATE_KEY', ''),
			scope=os.getenv('GITHUB_REPOSITORY', 'local-test'),
			compatibility=compatibility,
		)
		try:
			print(f'[STATE] Encrypted authentication snapshot: {store.restore()}')
			return cls(accounts, config, store, notify_ready=notify_ready)
		except BaseException:
			store.close()
			raise

	async def execute(self, account: AccountConfig, index: int, *, allow_manual: bool):
		plan = self.plans[index]
		if allow_manual and plan.profile_key in self._manual_failures:
			raise AuthError('IDENTITY_MANUAL_LOGIN_FAILED')
		lock = self._locks.setdefault(plan.profile_key, asyncio.Lock())
		async with lock:
			try:
				return await self._execute(account, index, plan, allow_manual=allow_manual)
			except (ManualLoginError, TimeoutError):
				self._manual_failures.add(plan.profile_key)
				raise AuthError('MANUAL_LOGIN_UNAVAILABLE_OR_TIMED_OUT') from None

	async def _execute(self, account: AccountConfig, index: int, plan: AccountPlan, *, allow_manual: bool):
		provider = self.config.providers[account.provider]
		origin = origin_of(provider.domain)
		profile = self.store.prepare_profile(plan.profile_key)
		metadata = self._metadata.setdefault(
			plan.profile_key,
			self.store.read_record('metadata', plan.profile_key)
			or {
				'fingerprint': secrets.randbelow(2**31 - 1) + 1,
			},
		)
		settings = replace(
			load_browser_login_settings(plan.profile_key, account.provider, persist_profile=True),
			profile_dir=profile,
		)
		context = await launch_login_context(
			settings,
			proxy_server=plan.proxy,
			fingerprint_seed=metadata['fingerprint'],
			secure=True,
		)
		verified = False
		record = None
		try:
			page = await context.new_page()
			for previous_page in context.pages:
				if previous_page != page:
					await previous_page.close()
			cached = self.store.read_record('accounts', plan.account_key)
			if cached and cached.get('binding') != plan.binding:
				cached = None
			if cached:
				await context.add_cookies(cached['cookies'])
			elif account.cookies and not account.has_login_credentials():
				await context.add_cookies(cast(list, self._configured_cookies(account, origin)))
			await self._navigate(page, origin + provider.login_path, settings.wait_timeout_ms)
			user = await self._probe(page, provider, cached.get('api_user') if cached else account.api_user)
			if user is None:
				if account.has_oauth():
					user = await self._oauth(context, page, account, provider, allow_manual=allow_manual)
				else:
					user = await self._site(
						page, account, provider, settings.wait_timeout_ms, allow_manual=allow_manual
					)
			user_id = check_expected_user(account, user, saved_id=cached.get('api_user') if cached else None)
			before = balance_result(user)
			success, after_user = await self._check_in(page, account, provider, user_id)
			check_expected_user(account, after_user, saved_id=user_id)
			record = {'binding': plan.binding, 'api_user': user_id, 'cookies': await context.cookies(origin)}
			verified = True
			return success, before, balance_result(after_user)
		finally:
			if verified and account.has_oauth():
				try:
					await self._clear_provider_state(context, origin)
				except Exception:
					verified = False
					self.persistence_failed = True
					print('[STATE] Provider cleanup failed; keeping the last known-good snapshot')
			await context.close()
			if verified and record is not None:
				self.store.commit_profile(plan.profile_key, profile)
				self.store.write_record('metadata', plan.profile_key, metadata)
				self.store.write_record('accounts', plan.account_key, record)
				self.store.save()

	async def _navigate(self, page, url: str, timeout: int) -> None:
		response = await page.goto(url, wait_until='domcontentloaded', timeout=timeout)
		if response is not None:
			if response.status == 429:
				raise AuthError('RATE_LIMITED')
			if response.status >= 500:
				raise AuthError('NETWORK_OR_SERVICE_ERROR')
		await wait_for_site_ready(page, timeout_ms=min(timeout, 30_000))

	async def _probe(self, page, provider: ProviderConfig, api_user: str | None = None) -> dict | None:
		origin = origin_of(provider.domain)
		try:
			if origin_of(page.url) != origin:
				return None
			local_id = await page.evaluate("""() => {
			  try { return JSON.parse(localStorage.getItem('user') || 'null')?.id ?? null; }
			  catch { return null; }
			}""")
		except Exception:
			return None
		resolved_id = local_id if local_id is not None else api_user
		if resolved_id is None:
			return None
		try:
			payload = await browser_json(
				page, origin, provider.user_info_path, headers={provider.api_user_key: str(resolved_id)}
			)
		except AuthError as error:
			if error.reason == 'SESSION_EXPIRED':
				return None
			raise
		if payload.get('success') is False:
			return None
		if payload.get('success') is not True or not isinstance(payload.get('data'), dict):
			raise AuthError('INVALID_USER_RESPONSE')
		return dict(payload['data'])

	async def _wait_user(self, page, account: AccountConfig, provider: ProviderConfig, seconds: float) -> dict | None:
		deadline = time.monotonic() + seconds
		while time.monotonic() < deadline:
			user = await self._probe(page, provider, account.api_user)
			if user is not None:
				check_expected_user(account, user)
				return user
			await asyncio.sleep(min(2, max(0, deadline - time.monotonic())))
		return None

	async def _site(
		self, page, account: AccountConfig, provider: ProviderConfig, timeout: int, *, allow_manual: bool
	) -> dict:
		if account.has_login_credentials():
			assert account.email is not None and account.password is not None
			try:
				await login_with_email_form(page, account.email, account.password, timeout)
			except Exception:
				print('[AUTH] Automatic site login did not complete; interactive recovery may be needed')
			user = await self._wait_user(page, account, provider, min(timeout / 1000, 20))
			if user is not None:
				return user
		if not allow_manual:
			raise ManualLoginRequired()
		await page.bring_to_front()

		async def wait_for_login(gateway):
			user = await self._wait_user(page, account, provider, self.manual_timeout)
			if user is None:
				raise TimeoutError
			return user

		return cast(dict, await self._manual(account, wait_for_login))

	async def _oauth(
		self, context, api_page, account: AccountConfig, provider: ProviderConfig, *, allow_manual: bool
	) -> dict:
		assert account.auth is not None
		kind = account.auth['type']
		origin = origin_of(provider.domain)
		status = await browser_json(api_page, origin, provider.status_path)
		settings = status.get('data', {})
		if not status.get('success') or not isinstance(settings, dict):
			raise AuthError('OAUTH_STATUS_UNAVAILABLE')
		client_id = provider.oauth_client_ids.get(kind) or settings.get(f'{kind}_client_id')
		if not isinstance(client_id, str) or not client_id or len(client_id) > 512:
			raise AuthError('OAUTH_CLIENT_NOT_CONFIGURED')
		state_payload = await browser_json(api_page, origin, provider.auth_state_path)
		state = state_payload.get('data')
		if not state_payload.get('success') or not isinstance(state, str) or not state or len(state) > 4096:
			raise AuthError('OAUTH_STATE_UNAVAILABLE')
		attempt = OAuthAttempt(kind, origin, client_id, state)
		flow = OAuthFlow(context, attempt)
		oauth_page = await context.new_page()
		try:
			await flow.install(oauth_page)
			response = await flow.open(oauth_page)
			if response is not None and response.status == 429:
				raise AuthError('RATE_LIMITED')
			if response is not None and response.status >= 500:
				raise AuthError('NETWORK_OR_SERVICE_ERROR')
			if not await flow.wait(oauth_page, 12, automatic=True):
				if not allow_manual:
					raise ManualLoginRequired()
				await oauth_page.bring_to_front()

				async def wait_for_oauth(gateway):
					reopened = False
					while not flow.completed.done():
						requested = gateway.resume.is_set()
						if requested:
							gateway.resume.clear()
						ready = not reopened and await self._identity_logged_in(oauth_page, kind)
						if requested or ready:
							reopened = True
							await flow.open(oauth_page)
						await flow.wait(oauth_page, 1, automatic=False)
					return None

				await self._manual(account, wait_for_oauth)
			if origin_of(api_page.url) != origin:
				await self._navigate(api_page, origin + provider.login_path, 60_000)
			callback_user = await flow.exchange(api_page)
			user_id = check_expected_user(account, callback_user)
			user = await self._probe(api_page, provider, user_id)
			if user is None:
				raise AuthError('OAUTH_SESSION_NOT_VERIFIED')
			check_expected_user(account, user, saved_id=user_id)
			return user
		finally:
			await flow.close()

	async def _identity_logged_in(self, page, kind: str) -> bool:
		try:
			parsed = urlsplit(page.url)
			if parsed.scheme != 'https':
				return False
			if (
				kind == 'github'
				and parsed.netloc == 'github.com'
				and not parsed.path.startswith(('/login', '/sessions'))
			):
				return bool(await page.locator('meta[name="user-login"]').get_attribute('content'))
			if kind == 'linuxdo' and parsed.netloc == 'linux.do' and parsed.path != '/login':
				return bool(
					await page.evaluate("""async () => {
				  try { const response = await fetch('/session/current.json', {credentials:'same-origin'});
				    if (!response.ok) return false; const data = await response.json();
				    return Boolean(data.current_user?.id); } catch { return false; }
				}""")
				)
		except Exception:
			return False
		return False

	async def _manual(self, account: AccountConfig, wait_for_completion):
		remaining = min(self.manual_timeout, int(self.manual_budget - self._manual_spent))
		if remaining < 30:
			raise ManualLoginError('The total manual login budget has been exhausted')
		started = time.monotonic()
		try:
			async with ManualTakeover(remaining) as takeover:
				print(f'[MANUAL] Protected temporary browser: {takeover.url}')
				print(f'[MANUAL] Use the preconfigured remote access password; timeout {remaining}s')
				if self.notify_ready is not None:
					try:
						await asyncio.wait_for(
							self.notify_ready(takeover.url, account.name or 'Account', remaining), timeout=20
						)
					except Exception:
						print('[MANUAL] Notification unavailable; use the protected URL in this run log')
				async with asyncio.timeout(remaining):
					return await wait_for_completion(takeover.gateway)
		finally:
			self._manual_spent += time.monotonic() - started

	async def _check_in(
		self, page, account: AccountConfig, provider: ProviderConfig, user_id: str
	) -> tuple[bool, dict]:
		origin = origin_of(provider.domain)
		success = True
		if provider.needs_manual_check_in():
			assert provider.sign_in_path is not None
			payload = await browser_json(
				page,
				origin,
				provider.sign_in_path,
				method='POST',
				headers={
					provider.api_user_key: user_id,
					'Content-Type': 'application/json',
					'X-Requested-With': 'XMLHttpRequest',
				},
			)
			message = str(payload.get('message') or payload.get('msg') or '').lower()
			success = payload.get('success') is True or payload.get('ret') == 1 or payload.get('code') == 0
			success = success or any(
				text in message for text in ('已经签到', '已签到', '重复签到', 'already checked', 'already signed')
			)
		user = await self._probe(page, provider, user_id)
		if user is None:
			raise AuthError('SESSION_EXPIRED_DURING_CHECKIN')
		return success, user

	def _configured_cookies(self, account: AccountConfig, origin: str) -> list[dict]:
		cookies = account.cookies
		if isinstance(cookies, str):
			cookies = dict(part.strip().split('=', 1) for part in cookies.split(';') if '=' in part)
		if not isinstance(cookies, dict):
			raise AuthError('INVALID_COOKIE_CONFIGURATION')
		return [{'name': name, 'value': value, 'url': origin} for name, value in cookies.items()]

	async def _clear_provider_state(self, context, origin: str) -> None:
		hostname = urlsplit(origin).hostname or ''
		await context.clear_cookies(domain=re.compile(r'(^|\.)' + re.escape(hostname) + r'$'))
		for page in context.pages:
			if not page.is_closed() and page.url.startswith(origin + '/'):
				await page.evaluate("""() => { localStorage.clear(); sessionStorage.clear(); }""")
				session = await context.new_cdp_session(page)
				try:
					await session.send('Storage.clearDataForOrigin', {'origin': origin, 'storageTypes': 'all'})
				finally:
					await session.detach()
				break

	def close(self) -> None:
		self.store.close()
