import asyncio
import base64
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import checkin
from utils.auth_runtime import AuthenticationRuntime
from utils.config import AccountConfig, AppConfig, IdentityConfig
from utils.manual_login import ManualLoginError
from utils.oauth import AuthError, ManualLoginRequired
from utils.secure_state import SnapshotStore


def accounts_and_config():
	config = AppConfig.load_from_env()
	config.identities = {'main': IdentityConfig('linuxdo', proxy='direct')}
	accounts = [
		AccountConfig(
			None,
			id=provider,
			name=provider,
			provider=provider,
			expected_username=provider,
			auth={'type': 'linuxdo', 'identity': 'main'},
		)
		for provider in ('anyrouter', 'agentrouter')
	]
	return accounts, config


@pytest.mark.asyncio
async def test_shared_identity_and_fresh_run_restore_without_manual_login(monkeypatch, tmp_path):
	accounts, config = accounts_and_config()
	secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
	cache_file = tmp_path / 'cache' / 'auth-state.enc'
	launches = []
	manual_count = 0

	async def launch(settings, **kwargs):
		context = SimpleNamespace(
			pages=[], profile=settings.profile_dir, restored_cookies=[], close=AsyncMock(), clear_cookies=AsyncMock()
		)
		context.new_cdp_session = AsyncMock(return_value=SimpleNamespace(send=AsyncMock(), detach=AsyncMock()))
		launches.append((settings, kwargs, context))

		async def new_page():
			page = SimpleNamespace(url='about:blank', context=context, evaluate=AsyncMock(), is_closed=lambda: False)
			context.pages.append(page)
			return page

		async def add_cookies(cookies):
			context.restored_cookies = cookies

		async def cookies(origin):
			return [{'name': 'session', 'value': 'synthetic-site-session', 'url': origin}]

		context.new_page = new_page
		context.add_cookies = add_cookies
		context.cookies = cookies
		return context

	async def navigate(self, page, url, timeout):
		page.url = url

	def user_for(provider):
		return {
			'id': 7 if provider.name == 'anyrouter' else 9,
			'username': provider.name,
			'quota': 5000000,
			'used_quota': 0,
		}

	async def probe(self, page, provider, api_user=None):
		return user_for(provider) if page.context.restored_cookies else None

	async def oauth(self, context, page, account, provider, *, allow_manual):
		nonlocal manual_count
		marker = context.profile / 'IDP_SESSION'
		if not marker.exists():
			if not allow_manual:
				raise ManualLoginRequired()
			manual_count += 1
			marker.write_text('synthetic-identity-session')
		return user_for(provider)

	async def business(self, page, account, provider, user_id):
		return True, user_for(provider)

	monkeypatch.setattr('utils.auth_runtime.launch_login_context', launch)
	monkeypatch.setattr(AuthenticationRuntime, '_navigate', navigate)
	monkeypatch.setattr(AuthenticationRuntime, '_probe', probe)
	monkeypatch.setattr(AuthenticationRuntime, '_oauth', oauth)
	monkeypatch.setattr(AuthenticationRuntime, '_check_in', business)
	first_store = SnapshotStore(tmp_path / 'run-one', cache_file, secret, scope='test', compatibility='browser')
	first = AuthenticationRuntime(accounts, config, first_store)
	for index, account in enumerate(accounts):
		with pytest.raises(ManualLoginRequired):
			await first.execute(account, index, allow_manual=False)
	assert not cache_file.exists()
	for index, account in enumerate(accounts):
		assert (await first.execute(account, index, allow_manual=True))[0]
	assert manual_count == 1
	first.close()
	assert b'synthetic-identity-session' not in cache_file.read_bytes()
	assert b'synthetic-site-session' not in cache_file.read_bytes()
	second_store = SnapshotStore(tmp_path / 'run-two', cache_file, secret, scope='test', compatibility='browser')
	assert second_store.restore() == 'restored'
	second = AuthenticationRuntime(accounts, config, second_store)
	for index, account in enumerate(accounts):
		assert (await second.execute(account, index, allow_manual=False))[0]
	second.close()
	assert manual_count == 1
	assert len({options['fingerprint_seed'] for settings, options, context in launches}) == 1
	assert all(options['secure'] and options['proxy_server'] is None for settings, options, context in launches)
	assert all(context.close.await_count == 1 for settings, options, context in launches)


@pytest.mark.asyncio
async def test_timeout_is_not_repeated_for_shared_identity(monkeypatch, tmp_path):
	accounts, config = accounts_and_config()
	store = SnapshotStore(
		tmp_path / 'state',
		tmp_path / 'cache.enc',
		base64.urlsafe_b64encode(os.urandom(32)).decode(),
		scope='test',
		compatibility='test',
	)
	runtime = AuthenticationRuntime(accounts, config, store)
	execute = AsyncMock(side_effect=ManualLoginError('timeout'))
	monkeypatch.setattr(runtime, '_execute', execute)
	with pytest.raises(AuthError, match='MANUAL_LOGIN_UNAVAILABLE_OR_TIMED_OUT'):
		await runtime.execute(accounts[0], 0, allow_manual=True)
	with pytest.raises(AuthError, match='IDENTITY_MANUAL_LOGIN_FAILED'):
		await runtime.execute(accounts[1], 1, allow_manual=True)
	assert execute.await_count == 1


@pytest.mark.asyncio
async def test_batch_runs_all_automatic_accounts_before_manual_queue(monkeypatch):
	accounts = [AccountConfig(None, name=f'Account {index}', email='test', password='synthetic') for index in range(3)]
	order = []
	closed = []

	async def execute(account, index, *, allow_manual):
		order.append((index, allow_manual))
		if index != 1 and not allow_manual:
			raise ManualLoginRequired()
		if index == 0:
			raise AuthError('MANUAL_LOGIN_UNAVAILABLE_OR_TIMED_OUT')
		return True, None, {'success': True}

	runtime = SimpleNamespace(execute=execute, close=lambda: closed.append(True))
	monkeypatch.setenv('CHECKIN_STATE_KEY', 'synthetic')
	monkeypatch.setattr(AuthenticationRuntime, 'from_environment', lambda *args, **kwargs: runtime)
	results = await checkin.run_account_batch(accounts, AppConfig.load_from_env())
	assert order == [(0, False), (1, False), (2, False), (0, True), (2, True)]
	assert [result[0] for result in results] == [False, True, True]
	assert closed == [True]


@pytest.mark.asyncio
async def test_batch_cancellation_cleans_runtime(monkeypatch):
	closed = []
	runtime = SimpleNamespace(execute=AsyncMock(side_effect=asyncio.CancelledError), close=lambda: closed.append(True))
	monkeypatch.setenv('CHECKIN_STATE_KEY', 'synthetic')
	monkeypatch.setattr(AuthenticationRuntime, 'from_environment', lambda *args, **kwargs: runtime)
	with pytest.raises(asyncio.CancelledError):
		await checkin.run_account_batch([AccountConfig(None)], AppConfig.load_from_env())
	assert closed == [True]
