import asyncio
import base64
import os
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from utils.auth_runtime import build_plans
from utils.config import AccountConfig, AppConfig, IdentityConfig, ProviderConfig
from utils.identity_login import (
	IdentityLoginRuntime,
	IdentityProbeError,
	check_identity_subject,
	identity_proxy,
	probe_identity_user,
)
from utils.manual_login import ManualLoginError
from utils.oauth import AuthError
from utils.secure_state import SnapshotStore, state_key


def configuration(kind='linuxdo', proxy=None):
	return AppConfig(
		providers={
			'anyrouter': ProviderConfig('anyrouter', 'https://anyrouter.test'),
			'agentrouter': ProviderConfig('agentrouter', 'https://agentrouter.test', use_proxy=True),
		},
		identities={'main': IdentityConfig(kind, proxy=proxy)},
	)


def account(provider='anyrouter', proxy=None):
	return AccountConfig(
		None,
		id=provider,
		provider=provider,
		proxy=proxy,
		expected_username='site-account',
		auth={'type': 'linuxdo', 'identity': 'main'},
	)


def self_result(kind='linuxdo', user_id=42, username='identity-user'):
	if kind == 'linuxdo':
		return {
			'status': 200,
			'url': 'https://linux.do/session/current.json',
			'data': {'current_user': {'id': user_id, 'username': username}},
		}
	return {
		'status': 200,
		'url': 'https://github.com/settings/profile',
		'data': {'actor_id': str(user_id), 'login': username, 'actor_login': username},
	}


@pytest.fixture
def browser(monkeypatch, tmp_path):
	page = SimpleNamespace(url='about:blank', is_closed=lambda: False, bring_to_front=AsyncMock())
	page.evaluate = AsyncMock(return_value=self_result())
	context = SimpleNamespace(pages=[page], close=AsyncMock(), new_page=AsyncMock(return_value=page))

	async def navigate(url, **kwargs):
		page.url = url
		return SimpleNamespace(status=200)

	page.goto = AsyncMock(side_effect=navigate)
	launch = AsyncMock(return_value=context)
	monkeypatch.setattr('utils.identity_login.launch_login_context', launch)
	store = SnapshotStore(
		tmp_path / 'state',
		tmp_path / 'cache' / 'auth-state.enc',
		base64.urlsafe_b64encode(os.urandom(32)).decode(),
		scope='test',
		compatibility='browser',
	)
	return SimpleNamespace(page=page, context=context, launch=launch, store=store)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['linuxdo', 'github'])
async def test_first_login_without_accounts_preserves_shared_profile_and_encrypted_subject(browser, kind):
	browser.page.evaluate.return_value = self_result(kind)
	runtime = IdentityLoginRuntime(configuration(kind), browser.store)
	result = await runtime.execute('main')
	assert result['user_id'] == '42'
	assert result['username'] == 'identity-user'
	offset = datetime.fromisoformat(result['verified_at']).utcoffset()
	assert offset is not None and offset.total_seconds() == 0
	key = state_key(f'identity:{kind}:main')
	metadata = browser.store.read_record('metadata', key)
	assert metadata['identity_login'] == {'type': kind, **result}
	settings = browser.launch.call_args.args[0]
	assert settings.profile_dir == browser.store.live / key
	assert not settings.headless
	assert browser.launch.call_args.kwargs == {
		'proxy_server': None,
		'fingerprint_seed': metadata['fingerprint'],
		'secure': True,
	}
	assert browser.store.cache_file.exists()
	assert b'identity-user' not in browser.store.cache_file.read_bytes()
	assert browser.store.read_record('accounts', key) is None
	browser.context.close.assert_awaited_once()
	runtime.close()
	assert not browser.store.live.exists()
	assert not browser.store.saved.exists()


@pytest.mark.asyncio
async def test_relogin_same_subject_preserves_fingerprint_and_other_metadata(browser):
	key = state_key('identity:linuxdo:main')
	browser.store.write_record(
		'metadata',
		key,
		{'fingerprint': 123, 'extra': 'preserved', 'identity_login': {'type': 'linuxdo', 'user_id': '42'}},
	)
	browser.page.evaluate.return_value = self_result(username='renamed-user')
	result = await IdentityLoginRuntime(configuration(), browser.store).execute('main')
	metadata = browser.store.read_record('metadata', key)
	assert metadata['fingerprint'] == 123
	assert metadata['extra'] == 'preserved'
	assert result['user_id'] == '42'
	assert result['username'] == 'renamed-user'


@pytest.mark.asyncio
async def test_mismatched_subject_keeps_last_known_good_snapshot(browser):
	key = state_key('identity:linuxdo:main')
	metadata = {'fingerprint': 55, 'identity_login': {'type': 'linuxdo', 'user_id': '7'}}
	browser.store.write_record('metadata', key, metadata)
	browser.store.save()
	previous = browser.store.cache_file.read_bytes()
	runtime = IdentityLoginRuntime(configuration(), browser.store)
	with pytest.raises(AuthError, match='IDENTITY_ACCOUNT_MISMATCH'):
		await runtime.execute('main')
	assert browser.store.cache_file.read_bytes() == previous
	assert browser.store.read_record('metadata', key) == metadata
	assert not (browser.store.saved / 'profiles' / key).exists()
	browser.context.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_new_browser_cannot_rebind_existing_alias_to_a_different_user(browser):
	runtime = IdentityLoginRuntime(configuration(), browser.store, bound_subjects={'main': '7'})
	with pytest.raises(AuthError, match='IDENTITY_ACCOUNT_MISMATCH'):
		await runtime.execute('main')
	assert not browser.store.cache_file.exists()
	assert not browser.store.dirty
	browser.context.close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize('transport', ['desktop', 'remote'])
@pytest.mark.parametrize(
	'anonymous',
	[
		{'status': 401},
		{
			'status': 403,
			'url': 'https://linux.do/session/current.json',
			'data': {'error_type': 'not_logged_in', 'errors': ['You need to be logged in to do that.']},
		},
	],
)
async def test_manual_wait_uses_original_browser_and_notifies_when_ready(browser, monkeypatch, transport, anonymous):
	browser.page.evaluate.side_effect = [anonymous, self_result()]
	entered: list = []

	class Takeover:
		def __init__(self, timeout):
			self.timeout = timeout
			self.url = '' if transport == 'desktop' else 'http://127.0.0.1:12345'
			self.transport = transport

		async def __aenter__(self):
			entered.append(self)
			return self

		async def __aexit__(self, *args):
			entered.append('closed')

	monkeypatch.setattr('utils.identity_login.ManualTakeover', Takeover)
	notify = AsyncMock()
	result = await IdentityLoginRuntime(configuration(), browser.store, notify_ready=notify).execute('main')
	assert result['user_id'] == '42'
	assert browser.launch.await_count == 1
	assert browser.page.goto.await_count == 1
	browser.page.bring_to_front.assert_awaited_once()
	notify.assert_awaited_once_with(entered[0].url, 'main', 600)
	assert entered[1] == 'closed'


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'failure,reason',
	[(TimeoutError(), 'MANUAL_LOGIN_TIMED_OUT'), (ManualLoginError('disabled'), 'MANUAL_LOGIN_UNAVAILABLE')],
)
async def test_manual_failure_never_commits_unverified_state(browser, monkeypatch, failure, reason):
	browser.page.evaluate.return_value = {'status': 401}
	runtime = IdentityLoginRuntime(configuration(), browser.store)
	monkeypatch.setattr(runtime, '_manual', AsyncMock(side_effect=failure))
	with pytest.raises(AuthError, match=reason):
		await runtime.execute('main')
	assert not browser.store.cache_file.exists()
	assert not browser.store.dirty
	browser.context.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_actual_manual_deadline_and_gateway_cleanup(browser, monkeypatch):
	browser.page.evaluate.return_value = {'status': 401}
	takeover = SimpleNamespace(url='', __aenter__=AsyncMock(), __aexit__=AsyncMock())

	class Takeover:
		async def __aenter__(self):
			return takeover

		async def __aexit__(self, *args):
			await takeover.__aexit__(*args)

	monkeypatch.setattr('utils.identity_login.ManualTakeover', lambda timeout: Takeover())
	# Expire the polling deadline without sleeping or changing the process clock.
	monkeypatch.setattr('utils.identity_login.time', SimpleNamespace(monotonic=iter([0, 601]).__next__))
	runtime = IdentityLoginRuntime(configuration(), browser.store)
	with pytest.raises(AuthError, match='MANUAL_LOGIN_TIMED_OUT'):
		await runtime.execute('main')
	takeover.__aexit__.assert_awaited_once()
	assert not browser.store.cache_file.exists()
	browser.context.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_cancellation_and_user_browser_close_never_save(browser):
	browser.page.evaluate.side_effect = asyncio.CancelledError
	runtime = IdentityLoginRuntime(configuration(), browser.store)
	with pytest.raises(asyncio.CancelledError):
		await runtime.execute('main')
	assert not browser.store.cache_file.exists()
	browser.context.close.assert_awaited_once()
	browser.context.close.reset_mock()
	browser.page.is_closed = lambda: True
	with pytest.raises(AuthError, match='IDENTITY_BROWSER_CLOSED'):
		await runtime.execute('main')
	assert not browser.store.cache_file.exists()
	browser.context.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_cancellation_during_manual_wait_revokes_gateway_without_saving(browser, monkeypatch):
	browser.page.evaluate.side_effect = [{'status': 401}, asyncio.CancelledError]
	exit_gateway = AsyncMock()

	class Takeover:
		async def __aenter__(self):
			return SimpleNamespace(url='http://127.0.0.1:12345')

		async def __aexit__(self, *args):
			await exit_gateway(*args)

	monkeypatch.setattr('utils.identity_login.ManualTakeover', lambda timeout: Takeover())
	with pytest.raises(asyncio.CancelledError):
		await IdentityLoginRuntime(configuration(), browser.store).execute('main')
	exit_gateway.assert_awaited_once()
	browser.context.close.assert_awaited_once()
	assert not browser.store.cache_file.exists()


def test_proxy_policy_matches_account_profile_key(monkeypatch):
	monkeypatch.setenv('CHECKIN_PROXY_URL', 'http://127.0.0.1:8888')
	config = configuration(proxy='direct')
	accounts = [account(), account('agentrouter')]
	assert identity_proxy(config, 'main', accounts) is None
	assert {plan.profile_key for plan in build_plans(accounts, config)} == {state_key('identity:linuxdo:main')}
	config.identities['main'] = IdentityConfig('linuxdo')
	assert identity_proxy(config, 'main', []) is None
	assert identity_proxy(config, 'main', [account('agentrouter')]) == 'http://127.0.0.1:8888'
	with pytest.raises(AuthError, match='SHARED_IDENTITY_PROXY_CONFLICT'):
		identity_proxy(config, 'main', accounts)
	config.identities['main'] = IdentityConfig('linuxdo', proxy='default')
	assert identity_proxy(config, 'main', []) == 'http://127.0.0.1:8888'
	with pytest.raises(AuthError, match='ACCOUNT_IDENTITY_PROXY_CONFLICT'):
		identity_proxy(config, 'main', [account(proxy='direct')])


@pytest.mark.asyncio
async def test_proxy_conflict_is_rejected_before_launch(browser, monkeypatch):
	monkeypatch.setenv('CHECKIN_PROXY_URL', 'http://127.0.0.1:8888')
	runtime = IdentityLoginRuntime(configuration(), browser.store, accounts=[account(), account('agentrouter')])
	with pytest.raises(AuthError, match='SHARED_IDENTITY_PROXY_CONFLICT'):
		await runtime.execute('main')
	browser.launch.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['linuxdo', 'github'])
@pytest.mark.parametrize(
	'status,reason', [(403, 'ACCESS_BLOCKED'), (429, 'RATE_LIMITED'), (503, 'NETWORK_OR_SERVICE_ERROR')]
)
async def test_probe_does_not_retry_blocked_or_limited_services(browser, kind, status, reason):
	browser.page.url = 'https://linux.do/login' if kind == 'linuxdo' else 'https://github.com/login'
	browser.page.evaluate.return_value = {'status': status}
	with pytest.raises(AuthError, match=reason):
		await probe_identity_user(browser.page, kind)
	assert browser.page.evaluate.await_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'url',
	['http://linux.do/login', 'https://linux.do.evil.test/', 'https://linux.do:443/login', 'https://user@linux.do/'],
)
async def test_probe_never_fetches_from_unexpected_origin(browser, url):
	browser.page.url = url
	assert await probe_identity_user(browser.page, 'linuxdo') is None
	browser.page.evaluate.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize('result', [{'status': 401}, {'redirected': True}])
async def test_unauthenticated_self_probe_needs_manual_login(browser, result):
	browser.page.url = 'https://github.com/login'
	browser.page.evaluate.return_value = result
	assert await probe_identity_user(browser.page, 'github') is None


@pytest.mark.asyncio
@pytest.mark.parametrize('result', [{'status': 404}, {'challenge': True}])
async def test_linuxdo_anonymous_session_or_visible_challenge_keeps_manual_login_open(browser, result):
	browser.page.url = 'https://linux.do/login'
	browser.page.evaluate.return_value = result
	assert await probe_identity_user(browser.page, 'linuxdo') is None
	assert not browser.context.close.called


@pytest.mark.asyncio
async def test_linuxdo_explicit_not_logged_in_403_keeps_manual_login_open(browser):
	browser.page.url = 'https://linux.do/login'
	browser.page.evaluate.return_value = {
		'status': 403,
		'url': 'https://linux.do/session/current.json',
		'data': {'error_type': 'not_logged_in', 'errors': ['You need to be logged in to do that.']},
	}
	assert await probe_identity_user(browser.page, 'linuxdo') is None
	assert not browser.context.close.called


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'kind,url,data',
	[
		('linuxdo', 'https://linux.do/session/current.json', {'error_type': 'invalid_access'}),
		('linuxdo', 'https://linux.do/session/current.json', {'errors': ['You need to be logged in.']}),
		('linuxdo', 'https://linux.do/session/current.json', None),
		('linuxdo', 'https://other.test/session/current.json', {'error_type': 'not_logged_in'}),
		('linuxdo', None, {'error_type': 'not_logged_in'}),
		('github', 'https://github.com/settings/profile', {'error_type': 'not_logged_in'}),
	],
)
async def test_other_forbidden_responses_still_stop_without_retry(browser, kind, url, data):
	browser.page.url = 'https://linux.do/login' if kind == 'linuxdo' else 'https://github.com/login'
	browser.page.evaluate.return_value = {'status': 403, 'url': url, 'data': data}
	with pytest.raises(AuthError, match='ACCESS_BLOCKED'):
		await probe_identity_user(browser.page, kind)
	assert browser.page.evaluate.await_count == 1


@pytest.mark.asyncio
async def test_cloudflare_api_challenge_has_only_safe_diagnostics(browser):
	browser.page.url = 'https://linux.do/'
	browser.page.evaluate.return_value = {
		'status': 403,
		'url': 'https://linux.do/session/current.json',
		'cf_challenge': True,
		'content_kind': 'html',
		'data': {'private': 'synthetic-private-response'},
		'headers': {'set-cookie': 'synthetic-private-cookie'},
	}
	with pytest.raises(IdentityProbeError, match='IDENTITY_CHALLENGE_REQUIRED') as caught:
		await probe_identity_user(browser.page, 'linuxdo')
	assert caught.value.diagnostics == {
		'provider': 'linuxdo',
		'endpoint': '/session/current.json',
		'http_status': 403,
		'response_kind': 'cloudflare_challenge',
	}
	assert 'synthetic-private' not in repr(caught.value.diagnostics)


@pytest.mark.asyncio
async def test_identity_challenge_never_redirects_or_retries_api_while_user_operates(browser, monkeypatch):
	browser.page.evaluate.side_effect = [
		{
			'status': 403,
			'url': 'https://linux.do/session/current.json',
			'cf_challenge': True,
		},
		asyncio.CancelledError,
	]

	class Takeover:
		async def __aenter__(self):
			return SimpleNamespace(url='')

		async def __aexit__(self, *args):
			pass

	monkeypatch.setattr('utils.identity_login.ManualTakeover', lambda timeout: Takeover())
	runtime = IdentityLoginRuntime(configuration(), browser.store)
	with pytest.raises(asyncio.CancelledError):
		await runtime.execute('main')
	assert [call.args[0] for call in browser.page.goto.await_args_list] == [
		'https://linux.do/login',
	]
	assert browser.page.evaluate.call_args.args[1]['allowFetch'] is False
	assert browser.launch.await_count == 1
	assert not browser.store.cache_file.exists()
	assert not browser.store.dirty
	browser.context.close.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'mutation',
	[
		{'url': 'https://github.com/login'},
		{'url': 'https://github.com.evil.test/settings/profile'},
		{'data': {'login': 'identity-user'}},
		{'data': {'login': 'identity-user', 'actor_login': 'other-user', 'actor_id': '42'}},
		{'data': {'login': 'identity-user', 'actor_login': 'identity-user', 'actor_id': '0'}},
	],
)
async def test_github_requires_authenticated_settings_response_and_matching_actor(browser, mutation):
	browser.page.url = 'https://github.com/login'
	browser.page.evaluate.return_value = {**self_result('github'), **mutation}
	with pytest.raises(AuthError, match='INVALID_IDENTITY_RESPONSE'):
		await probe_identity_user(browser.page, 'github')
	request = browser.page.evaluate.call_args.args[1]
	assert request == {'kind': 'github', 'url': 'https://github.com/settings/profile'}
	assert "credentials: 'same-origin'" in browser.page.evaluate.call_args.args[0]
	assert "redirect: 'manual'" in browser.page.evaluate.call_args.args[0]


@pytest.mark.asyncio
@pytest.mark.parametrize('user_id', [True, None, '', 0, -1, '4.2'])
async def test_linuxdo_requires_real_self_subject(browser, user_id):
	browser.page.url = 'https://linux.do/login'
	browser.page.evaluate.return_value = self_result(user_id=user_id)
	with pytest.raises(AuthError, match='INVALID_IDENTITY_RESPONSE'):
		await probe_identity_user(browser.page, 'linuxdo')


def test_malformed_saved_subject_never_rebinds():
	for previous in (None, {}, {'type': 'github', 'user_id': '42'}):
		with pytest.raises(AuthError, match='INVALID_SAVED_IDENTITY'):
			check_identity_subject({'identity_login': previous}, 'linuxdo', {'user_id': '42'})


@pytest.mark.asyncio
async def test_snapshot_is_not_committed_when_browser_cleanup_fails(browser):
	browser.context.close.side_effect = RuntimeError('browser close failed')
	with pytest.raises(RuntimeError, match='browser close failed'):
		await IdentityLoginRuntime(configuration(), browser.store).execute('main')
	assert not browser.store.cache_file.exists()
	assert not browser.store.dirty
