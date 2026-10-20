"""Pure HTTP execution, with every request intercepted by MockTransport."""

import asyncio
import copy
import json
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import httpx
import pytest

from utils.http_checkin import HttpCheckinRuntime, account_binding

CONFIG = {'http': {'timeout_seconds': 30}, 'proxy_url': 'http://localhost:8080'}
COOKIE = 'session=private-cookie'


class Sessions:
	def __init__(self):
		self.saved = {}
		self.loads = []
		self.writes = []

	def load(self, account_id, binding):
		self.loads.append((account_id, binding))
		return copy.deepcopy(self.saved.get((account_id, binding)))

	def save(self, account_id, binding, state):
		self.writes.append((account_id, binding, copy.deepcopy(state)))
		self.saved[account_id, binding] = copy.deepcopy(state)


def account(**changes):
	return {
		'id': 'account-1',
		'name': 'First account',
		'provider': 'anyrouter',
		'auth_type': 'cookie',
		'enabled': True,
		'cookies': COOKIE,
		'api_user': '42',
		'expected_username': 'alice',
		'proxy': 'direct',
		**changes,
	}


def agent(**changes):
	return account(
		**{
			'provider': 'agentrouter',
			'auth_type': 'system_token',
			'system_access_token': 'private-system-token',
			**changes,
		}
	)


def password(**changes):
	return account(
		**{'auth_type': 'password', 'cookies': '', 'username': 'alice', 'password': 'private-password', **changes}
	)


def user(**changes):
	return httpx.Response(
		200,
		json={
			'success': True,
			'data': {'id': 42, 'username': 'alice', 'quota': 500000, 'used_quota': 100000, **changes},
		},
	)


def saved_session(user_id='42', value='old-good-cookie'):
	return {
		'api_user': user_id,
		'cookies': [{'name': 'session', 'value': value, 'domain': 'anyrouter.top', 'path': '/', 'expires': None}],
	}


def runtime(handler, sessions=None, config=None):
	store = sessions if sessions is not None else Sessions()
	requests = []
	options = []
	clients = []

	async def transport(request):
		requests.append(request)
		response = handler(request)
		if asyncio.iscoroutine(response):
			response = await response
		return response

	def factory(**kwargs):
		options.append(kwargs.copy())
		kwargs.pop('proxy')
		client = httpx.AsyncClient(transport=httpx.MockTransport(transport), **kwargs)
		clients.append(client)
		return client

	return HttpCheckinRuntime(config or CONFIG, store, client_factory=factory), store, requests, options, clients


async def test_any_cookie_checkin_verifies_identity_and_persists_only_successful_session(capsys):
	probes = 0

	def handler(request):
		nonlocal probes
		assert request.url.host == 'anyrouter.top'
		assert request.headers['new-api-user'] == '42'
		assert COOKIE in request.headers['cookie']
		assert 'authorization' not in request.headers
		assert not request.url.query
		if request.method == 'GET':
			probes += 1
			return user(quota=500000 if probes == 1 else 1000000, used_quota=100000)
		return httpx.Response(
			200, json={'success': True}, headers={'Set-Cookie': 'refreshed=safe; Path=/; HttpOnly; Secure'}
		)

	runner, store, requests, options, clients = runtime(handler)
	events = []
	result = await runner.execute(account(), on_progress=lambda event: events.append(copy.deepcopy(event)))
	steps = result.pop('steps')
	assert [step['stage'] for step in steps] == [
		'prepare',
		'load_session',
		'verify_identity',
		'checkin',
		'verify_result',
		'save_session',
		'finished',
	]
	assert all(step['state'] == 'completed' for step in steps)
	assert any(
		event.get('method') == 'POST' and event['stage'] == 'checkin' and event['state'] == 'running'
		for event in events
	)
	assert [step.get('http_status') for step in steps if 'method' in step] == [200, 200, 200]
	assert result == {
		'id': 'account-1',
		'name': 'First account',
		'provider': 'anyrouter',
		'success': True,
		'outcome': 'success',
		'reason': 'checkin_verified',
		'balance_before': 1,
		'balance_after': 2,
		'reward': 1,
	}
	assert [request.method for request in requests] == ['GET', 'POST', 'GET']
	assert [request.url.path for request in requests] == ['/api/user/self', '/api/user/sign_in', '/api/user/self']
	assert len(store.writes) == 1
	assert store.writes[0][2]['api_user'] == '42'
	assert {cookie['name'] for cookie in store.writes[0][2]['cookies']} == {'session', 'refreshed'}
	assert options[0]['trust_env'] is False
	assert options[0]['follow_redirects'] is False
	assert options[0]['verify'] is True
	assert options[0]['proxy'] is None
	assert options[0]['timeout'] == 30
	assert clients[0].is_closed
	assert capsys.readouterr().out == ''
	assert 'private-cookie' not in json.dumps(events)
	assert 'private-cookie' not in json.dumps(result)


async def test_agent_uses_only_one_info_request_without_session_cookies_or_fake_reward():
	def handler(request):
		assert request.url == 'https://agentrouter.org/api/user/self'
		assert request.method == 'GET'
		assert request.headers['Authorization'] == 'Bearer private-system-token'
		assert request.headers['new-api-user'] == '42'
		assert 'cookie' not in request.headers
		return user()

	runner, store, requests, _, _ = runtime(handler)
	result = await runner.execute(agent())
	assert result['success'] is True
	assert result['reason'] == 'user_info_requested_reward_unverified'
	assert result['balance_after'] == 1
	assert 'reward' not in result and 'balance_before' not in result
	assert len(requests) == 1
	assert not store.loads and not store.writes


async def test_password_login_binds_first_returned_uid_then_reuses_verified_session():
	probes = 0

	def handler(request):
		nonlocal probes
		assert 'authorization' not in request.headers
		if request.url.path == '/api/user/login':
			assert json.loads(request.content) == {'username': 'alice', 'password': 'private-password'}
			assert 'cookie' not in request.headers
			return httpx.Response(
				200, json={'success': True, 'data': {'id': 42}}, headers={'Set-Cookie': 'session=fresh; Path=/; Secure'}
			)
		assert request.headers['new-api-user'] == '42'
		assert request.headers['cookie'] == 'session=fresh'
		if request.url.path == '/api/user/self':
			probes += 1
			return user(quota=500000 + probes)
		return httpx.Response(200, json={'success': True})

	runner, store, requests, _, _ = runtime(handler)
	credentials = password(api_user='')
	assert (await runner.execute(credentials))['success'] is True
	assert (await runner.execute(credentials))['success'] is True
	assert [request.url.path for request in requests].count('/api/user/login') == 1
	assert len(store.writes) == 2
	assert store.writes[0][2]['api_user'] == '42'


async def test_password_cached_expiration_allows_one_login_without_losing_identity_binding():
	credentials = password(api_user='')
	store = Sessions()
	store.saved['account-1', account_binding(credentials, CONFIG)] = saved_session()
	steps = iter(
		[
			httpx.Response(401, json={'success': False}),
			httpx.Response(
				200, json={'success': True, 'data': {'id': 42}}, headers={'Set-Cookie': 'session=fresh; Path=/'}
			),
			user(),
			httpx.Response(200, json={'success': True}),
			user(),
		]
	)
	runner, _, requests, _, _ = runtime(lambda request: next(steps), store)
	result = await runner.execute(credentials)
	assert result['success'] is True
	assert [request.url.path for request in requests].count('/api/user/login') == 1
	assert 'old-good-cookie' not in requests[1].headers.get('cookie', '')
	assert len(store.writes) == 1


async def test_changed_credentials_do_not_load_old_bound_cookie():
	credentials = password(password='new-password')
	store = Sessions()
	store.saved['account-1', account_binding(password(), CONFIG)] = saved_session()

	def handler(request):
		assert request.url.path == '/api/user/login'
		assert 'cookie' not in request.headers
		assert json.loads(request.content)['password'] == 'new-password'
		return httpx.Response(401, json={'success': False})

	runner, _, requests, _, _ = runtime(handler, store)
	result = await runner.execute(credentials)
	assert result['outcome'] == 'needs_credentials'
	assert len(requests) == 1 and not store.writes


@pytest.mark.parametrize(
	'changes',
	[
		{'id': 'other'},
		{'provider': 'agentrouter'},
		{'auth_type': 'password'},
		{'cookies': 'session=changed'},
		{'username': 'other'},
		{'password': 'other'},
		{'system_access_token': 'other'},
		{'api_user': '9'},
		{'expected_username': 'other'},
		{'proxy': 'default'},
	],
)
def test_binding_changes_for_credentials_account_identity_and_route(changes):
	assert account_binding(account(), CONFIG) != account_binding(account(**changes), CONFIG)
	assert len(account_binding(account(), CONFIG)) == 64
	assert 'private' not in account_binding(account(), CONFIG)


def test_default_proxy_url_changes_binding_but_display_name_does_not():
	assert account_binding(account(), CONFIG) == account_binding(account(name='New label'), CONFIG)
	assert account_binding(account(proxy='default'), CONFIG) != account_binding(
		account(proxy='default'), {**CONFIG, 'proxy_url': 'http://localhost:9090'}
	)
	assert account_binding(account(), CONFIG) == account_binding(account(), {**CONFIG, 'proxy_url': 'changed'})


@pytest.mark.parametrize('changes', [{'api_user': '43'}, {'expected_username': 'bob'}])
async def test_cookie_identity_mismatch_prevents_signin_and_preserves_last_good_session(changes):
	credentials = account(**changes)
	store = Sessions()
	store.saved['account-1', account_binding(credentials, CONFIG)] = saved_session(user_id=credentials['api_user'])
	baseline = copy.deepcopy(store.saved)
	runner, _, requests, _, _ = runtime(lambda request: user(), store)
	result = await runner.execute(credentials)
	assert result['reason'] == 'account_identity_mismatch'
	assert result['outcome'] == 'needs_credentials'
	assert len(requests) == 1 and requests[0].method == 'GET'
	assert not store.writes and store.saved == baseline


async def test_password_new_login_cannot_change_saved_identity():
	credentials = password(api_user='')
	store = Sessions()
	store.saved['account-1', account_binding(credentials, CONFIG)] = saved_session()
	steps = iter([httpx.Response(401), httpx.Response(200, json={'success': True, 'data': {'id': 43}})])
	runner, _, requests, _, _ = runtime(lambda request: next(steps), store)
	result = await runner.execute(credentials)
	assert result['reason'] == 'account_identity_mismatch'
	assert result['outcome'] == 'needs_credentials'
	assert len(requests) == 2 and not store.writes


async def test_after_checkin_identity_mismatch_is_uncertain_and_never_saves_new_cookie():
	credentials = account()
	store = Sessions()
	store.saved['account-1', account_binding(credentials, CONFIG)] = saved_session()
	baseline = copy.deepcopy(store.saved)
	steps = iter(
		[user(), httpx.Response(200, json={'success': True}, headers={'Set-Cookie': 'session=wrong'}), user(id=43)]
	)
	runner, _, requests, _, _ = runtime(lambda request: next(steps), store)
	result = await runner.execute(credentials)
	assert result['outcome'] == 'uncertain'
	assert result['reason'] == 'checkin_verification_failed'
	assert result['verification_reason'] == 'account_identity_mismatch'
	assert len(requests) == 3 and not store.writes and store.saved == baseline


@pytest.mark.parametrize(
	('response', 'outcome', 'reason'),
	[
		(
			httpx.Response(403, text='<html>Cloudflare challenge</html>', headers={'content-type': 'text/html'}),
			'blocked',
			'interactive_verification_required',
		),
		(httpx.Response(403, headers={'cf-mitigated': 'challenge'}), 'blocked', 'interactive_verification_required'),
		(
			httpx.Response(200, json={'success': False, 'message': 'Turnstile captcha required'}),
			'blocked',
			'interactive_verification_required',
		),
		(httpx.Response(403, text='<html>Forbidden</html>'), 'blocked', 'html_response_received'),
		(httpx.Response(200, text='<html>Login</html>'), 'blocked', 'html_response_received'),
		(httpx.Response(403, json={'success': False, 'message': 'Forbidden'}), 'blocked', 'access_blocked'),
		(httpx.Response(401, json={'success': False}), 'needs_credentials', 'credentials_rejected'),
		(
			httpx.Response(200, json={'success': False, 'message': 'Not logged in'}),
			'needs_credentials',
			'credentials_rejected',
		),
		(httpx.Response(200, json={'success': False, 'message': 'Not available'}), 'failed', 'user_info_rejected'),
		(httpx.Response(200, text='private-cookie is not JSON'), 'failed', 'invalid_json_response'),
		(httpx.Response(200, json=[]), 'failed', 'invalid_json_response'),
		(httpx.Response(200, json={'success': True, 'data': {'id': True}}), 'failed', 'invalid_user_info'),
		(httpx.Response(200, json={'success': True, 'data': {'id': 0}}), 'failed', 'invalid_user_info'),
		(httpx.Response(503, json={'message': 'private-cookie'}), 'failed', 'service_unavailable'),
	],
)
async def test_info_failures_are_classified_without_credentials_or_mutation(response, outcome, reason):
	runner, store, requests, _, _ = runtime(lambda request: response)
	result = await runner.execute(account())
	assert result['success'] is False and result['outcome'] == outcome and result['reason'] == reason
	assert len(requests) == 1 and not store.writes
	assert 'private-cookie' not in json.dumps(result)


async def test_redirect_never_follows_or_sends_credentials_to_another_origin():
	def handler(request):
		assert request.url.host == 'agentrouter.org'
		return httpx.Response(302, headers={'Location': 'https://attacker.invalid/collect'})

	runner, store, requests, _, _ = runtime(handler)
	result = await runner.execute(agent())
	assert result['outcome'] == 'blocked' and result['reason'] == 'response_redirected'
	assert len(requests) == 1 and not store.writes


@pytest.mark.parametrize(('retry', 'expected'), [('120', 120), ('-1', 0), ('invalid', None)])
async def test_rate_limit_has_bounded_retry_after_without_retry(retry, expected):
	runner, store, requests, _, _ = runtime(lambda request: httpx.Response(429, headers={'retry-after': retry}))
	result = await runner.execute(agent())
	assert result['outcome'] == 'rate_limited'
	assert result.get('retry_after_seconds') == expected
	assert len(requests) == 1 and not store.writes


async def test_rate_limit_accepts_http_date():
	retry = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=120), usegmt=True)
	runner, _, _, _, _ = runtime(lambda request: httpx.Response(429, headers={'retry-after': retry}))
	result = await runner.execute(account())
	assert 118 <= result['retry_after_seconds'] <= 120


@pytest.mark.parametrize('path', ['/api/user/sign_in', '/api/user/login'])
@pytest.mark.parametrize('failure', ['timeout', 'network', 'server', 'malformed'])
async def test_mutation_unknown_result_is_never_repeated(path, failure):
	def handler(request):
		if request.url.path != path:
			return user()
		if failure == 'timeout':
			raise httpx.ReadTimeout('private-password', request=request)
		if failure == 'network':
			raise httpx.ConnectError('private-password', request=request)
		if failure == 'server':
			return httpx.Response(503, json={'message': 'private-password'})
		return httpx.Response(200, text='private-password')

	runner, store, requests, _, clients = runtime(handler)
	result = await runner.execute(account() if path.endswith('sign_in') else password())
	assert result['outcome'] == 'uncertain' and result['success'] is False
	assert [request.url.path for request in requests].count(path) == 1
	assert not store.writes
	assert 'private-password' not in json.dumps(result)
	assert clients[0].is_closed


async def test_info_network_error_does_not_login_or_retry():
	def handler(request):
		raise httpx.ConnectError('secret details', request=request)

	runner, store, requests, _, _ = runtime(handler)
	result = await runner.execute(account())
	assert result['outcome'] == 'failed' and result['reason'] == 'network_error'
	assert len(requests) == 1 and not store.writes


@pytest.mark.parametrize(
	'error_type', [httpx.ReadTimeout, httpx.ConnectError, httpx.ProxyError, httpx.RemoteProtocolError]
)
async def test_diagnostics_keep_failure_stage_without_exception_text(error_type):
	def handler(request):
		raise error_type('private-cookie private-password private-system-token private-proxy', request=request)

	runner, _, requests, _, _ = runtime(handler)
	events: list[dict] = []
	result = await runner.execute(account(), on_progress=events.append)
	assert result['reason'] == 'network_error'
	diagnostic = result['diagnostic']
	assert diagnostic['stage'] == 'verify_identity'
	assert diagnostic['method'] == 'GET' and diagnostic['path'] == '/api/user/self'
	assert diagnostic['error_type'] in {'TimeoutException', 'ConnectError', 'ProxyError', 'ProtocolError'}
	assert diagnostic['timeout_seconds'] == 30
	assert result['steps'][-1]['state'] == 'failed'
	assert len(requests) == 1
	for secret in ('private-cookie', 'private-password', 'private-system-token', 'private-proxy'):
		assert secret not in json.dumps([result, events])


async def test_http_failure_diagnostics_include_status_without_response_body():
	runner, _, requests, _, _ = runtime(
		lambda request: httpx.Response(403, json={'message': 'private-cookie private-password'})
	)
	result = await runner.execute(account())
	assert result['reason'] == 'access_blocked'
	assert result['diagnostic'] == {
		'stage': 'verify_identity',
		'method': 'GET',
		'path': '/api/user/self',
		'timeout_seconds': 30,
		'http_status': 403,
		'error_type': 'HTTPStatusError',
	}
	assert len(requests) == 1
	assert 'private-cookie' not in json.dumps(result) and 'private-password' not in json.dumps(result)


@pytest.mark.parametrize('failure', ['timeout', 'network', 'server', 'malformed', 'array', 'invalid_user', 'empty'])
async def test_agent_side_effecting_info_request_unknown_result_is_not_retryable(failure):
	def handler(request):
		if failure == 'timeout':
			raise httpx.ReadTimeout('private-system-token', request=request)
		if failure == 'network':
			raise httpx.ConnectError('private-system-token', request=request)
		if failure == 'server':
			return httpx.Response(503, json={'message': 'private-system-token'})
		if failure == 'array':
			return httpx.Response(200, json=[])
		if failure == 'invalid_user':
			return httpx.Response(200, json={'success': True, 'data': {'id': True}})
		if failure == 'empty':
			return httpx.Response(200, json={})
		return httpx.Response(200, text='private-system-token')

	runner, store, requests, _, clients = runtime(handler)
	result = await runner.execute(agent())
	assert result['success'] is False and result['outcome'] == 'uncertain'
	assert result['reason'] in {'request_result_unknown', 'invalid_json_response', 'invalid_user_info'}
	assert len(requests) == 1 and requests[0].method == 'GET'
	assert not store.loads and not store.writes and clients[0].is_closed
	assert 'private-system-token' not in json.dumps(result)


@pytest.mark.parametrize('user_changes', [{'id': 43}, {'username': 'bob'}])
async def test_agent_identity_mismatch_requires_credentials_and_one_request(user_changes):
	runner, _, requests, _, _ = runtime(lambda request: user(**user_changes))
	result = await runner.execute(agent())
	assert result['success'] is False and result['outcome'] == 'needs_credentials'
	assert result['reason'] == 'account_identity_mismatch'
	assert len(requests) == 1


async def test_password_cached_identity_mismatch_does_not_attempt_login_or_checkin():
	credentials = password(api_user='')
	store = Sessions()
	store.saved['account-1', account_binding(credentials, CONFIG)] = saved_session()
	runner, _, requests, _, _ = runtime(lambda request: user(id=43), store)
	result = await runner.execute(credentials)
	assert result['outcome'] == 'needs_credentials' and result['reason'] == 'account_identity_mismatch'
	assert len(requests) == 1 and requests[0].method == 'GET'
	assert not store.writes


@pytest.mark.parametrize(
	'payload',
	[
		{'success': False},
		{'success': False, 'code': 0},
		{'code': False},
		{'ret': True},
		{'other': 'success'},
	],
)
async def test_business_failure_does_not_become_success(payload):
	steps = iter([user(), httpx.Response(200, json=payload)])
	runner, store, requests, _, _ = runtime(lambda request: next(steps))
	result = await runner.execute(account())
	assert result['outcome'] == 'failed' and result['reason'] == 'checkin_rejected'
	assert len(requests) == 2 and not store.writes


@pytest.mark.parametrize('payload', [{'ret': 1}, {'code': 0}, {'success': True}])
async def test_explicit_supported_any_checkin_success_formats(payload):
	steps = iter([user(), httpx.Response(200, json=payload), user()])
	runner, store, _, _, _ = runtime(lambda request: next(steps))
	result = await runner.execute(account())
	assert result['success'] is True and len(store.writes) == 1


async def test_already_checked_in_is_verified_before_saving():
	steps = iter([user(), httpx.Response(200, json={'success': False, 'message': '已经签到'}), user()])
	runner, store, requests, _, _ = runtime(lambda request: next(steps))
	result = await runner.execute(account())
	assert result['outcome'] == 'already_checked_in' and result['success'] is True
	assert len(requests) == 3 and len(store.writes) == 1


@pytest.mark.parametrize(
	'credentials',
	[
		account(api_user=''),
		account(api_user=True),
		account(cookies='broken'),
		account(cookies={'bad\r\nname': 'secret'}),
		account(cookies={'session': 'bad\r\nvalue'}),
		agent(system_access_token=''),
		agent(api_user='0'),
		password(username=''),
		password(password=''),
		account(provider='unknown'),
		account(auth_type='github'),
		agent(auth_type='cookie'),
		account(proxy='default'),
	],
)
async def test_invalid_or_unsupported_credentials_do_not_send_network_request(credentials):
	runner, store, requests, _, _ = runtime(lambda request: pytest.fail('Unexpected request'), config={'http': {}})
	result = await runner.execute(credentials)
	assert result['success'] is False and result['outcome'] in {'needs_credentials', 'failed'}
	assert not requests and not store.writes


async def test_explicit_proxy_is_used_without_environment_inheritance():
	runner, _, _, options, _ = runtime(lambda request: user())
	assert (await runner.execute(agent(proxy='default')))['success'] is True
	assert options[0]['proxy'] == CONFIG['proxy_url']
	assert options[0]['trust_env'] is False


@pytest.mark.parametrize('route', [None, '', 'missing', 'default'])
async def test_unset_or_default_proxy_inherits_configured_route(route):
	credentials = agent(proxy=route)
	if route == 'missing':
		del credentials['proxy']
	runner, _, _, options, _ = runtime(lambda request: user())
	assert (await runner.execute(credentials))['success'] is True
	assert options[0]['proxy'] == CONFIG['proxy_url']
	assert options[0]['trust_env'] is False


@pytest.mark.parametrize('route', [None, '', 'missing'])
async def test_unset_proxy_without_global_route_is_direct(route):
	credentials = agent(proxy=route)
	if route == 'missing':
		del credentials['proxy']
	runner, _, _, options, _ = runtime(lambda request: user(), config={'http': {}})
	assert (await runner.execute(credentials))['success'] is True
	assert options[0]['proxy'] is None


@pytest.mark.parametrize(
	'route',
	[
		'http://localhost:8080',
		'https://user:private-proxy-password@proxy.example:8443/',
		'socks5://127.0.0.1:1080',
		'socks5://user:private-proxy-password@proxy.example:1080',
		'socks5://user%40dept:private%3Aproxy%2Fpassword%23%25@proxy.example:1080',
		'http://[::1]:8080',
	],
)
async def test_explicit_custom_proxy_is_supported_and_not_exposed(route):
	runner, _, _, options, _ = runtime(lambda request: user())
	result = await runner.execute(agent(proxy=route))
	assert result['success'] is True and options[0]['proxy'] == route
	assert 'private-proxy-password' not in json.dumps(result)


@pytest.mark.parametrize(
	'route',
	[
		'http://proxy.example',
		'http://proxy.example:0',
		'http://proxy.example:65536',
		'http://proxy.example:8080/path',
		'http://proxy.example:8080?secret=private-proxy-password',
		'http://proxy.example:8080#fragment',
		'http://private-proxy-password@proxy.example:80\r\n',
		' http://proxy.example:80',
		'http://proxy.example:80\x00',
		'http://proxy.example:80\\path',
		'ftp://proxy.example:80',
		'socks5://user@proxy.example:1080',
		'socks5://user:@proxy.example:1080',
		'socks5://:private-proxy-password@proxy.example:1080',
		'socks5://user:%FF@proxy.example:1080',
		'socks5://user:private%0Aproxy-password@proxy.example:1080',
		'socks5://user:' + 'p' * 256 + '@proxy.example:1080',
		'http://bad_host:80',
		'http://[invalid]:80',
		'http://proxy.example:not-a-port',
	],
)
async def test_invalid_custom_proxy_is_rejected_before_request_and_never_exposed(route):
	runner, _, requests, options, _ = runtime(lambda request: pytest.fail('Unexpected request'))
	result = await runner.execute(agent(proxy=route))
	assert result['reason'] == 'invalid_proxy_configuration'
	assert not requests and not options
	assert 'private-proxy-password' not in json.dumps(result)


@pytest.mark.parametrize('route', [None, '', 'missing', 'default'])
def test_inherited_proxy_binding_tracks_global_route(route):
	credentials = account(proxy=route)
	if route == 'missing':
		del credentials['proxy']
	assert account_binding(credentials, CONFIG) != account_binding(
		credentials, {**CONFIG, 'proxy_url': 'http://localhost:9090'}
	)


def test_custom_proxy_binding_tracks_explicit_route_and_ignores_global_route():
	credentials = account(proxy='http://localhost:8081')
	assert account_binding(credentials, CONFIG) != account_binding(account(proxy='http://localhost:8082'), CONFIG)
	assert account_binding(credentials, CONFIG) == account_binding(
		credentials, {**CONFIG, 'proxy_url': 'http://localhost:9090'}
	)


async def test_disabled_account_does_not_open_client_or_session():
	runner, store, requests, options, _ = runtime(lambda request: pytest.fail('Unexpected request'))
	assert (await runner.execute(account(enabled=False)))['outcome'] == 'skipped'
	assert not requests and not options and not store.loads


async def test_cancellation_propagates_and_closes_client_without_persisting():
	async def handler(request):
		raise asyncio.CancelledError

	runner, store, _, _, clients = runtime(handler)
	with pytest.raises(asyncio.CancelledError):
		await runner.execute(account())
	assert clients[0].is_closed and not store.writes


async def test_saved_offhost_cookie_is_rejected_without_request():
	credentials = account()
	store = Sessions()
	state = saved_session()
	state['cookies'][0]['domain'] = 'attacker.invalid'
	store.saved['account-1', account_binding(credentials, CONFIG)] = state
	runner, _, requests, _, _ = runtime(lambda request: pytest.fail('Unexpected request'), store)
	result = await runner.execute(credentials)
	assert result['success'] is False and not requests and not store.writes


async def test_session_load_failure_does_not_replace_or_clear_stored_state():
	class Unavailable(Sessions):
		def load(self, account_id, binding):
			raise RuntimeError('private-cookie')

	runner, store, requests, _, _ = runtime(lambda request: pytest.fail('Unexpected request'), Unavailable())
	result = await runner.execute(account())
	assert result['reason'] == 'session_load_failed'
	assert not requests and not store.writes
	assert 'private-cookie' not in json.dumps(result)


async def test_session_save_failure_is_reported_without_exposing_exception():
	class Unavailable(Sessions):
		def save(self, account_id, binding, state):
			raise RuntimeError('private-cookie')

	steps = iter([user(), httpx.Response(200, json={'success': True}), user()])
	runner, _, requests, _, _ = runtime(lambda request: next(steps), Unavailable())
	result = await runner.execute(account())
	assert result['success'] is False and result['reason'] == 'session_save_failed'
	assert result['outcome'] == 'uncertain'
	assert len(requests) == 3 and 'private-cookie' not in json.dumps(result)


async def test_successful_username_containing_challenge_word_is_not_blocked():
	runner, _, _, _, _ = runtime(lambda request: user(username='cloudflare'))
	result = await runner.execute(agent(expected_username='cloudflare'))
	assert result['success'] is True


async def test_missing_quota_does_not_invent_zero_balance_or_reward():
	def handler(request):
		if request.method == 'POST':
			return httpx.Response(200, json={'success': True})
		return user(quota=None, used_quota=None)

	runner, _, _, _, _ = runtime(handler)
	result = await runner.execute(account())
	assert result['success'] is True
	assert 'balance_before' not in result and 'balance_after' not in result and 'reward' not in result
