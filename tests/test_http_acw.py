"""Bounded ACW negotiation using intercepted requests and synthetic credentials."""

import json
from pathlib import Path

import httpx
import pytest
from test_http_checkin import COOKIE, account, agent, password, runtime, user

ACW_HTML = (Path(__file__).parent / 'fixtures' / 'anyrouter_acw_challenge.html').read_text(encoding='utf-8')
ACW_VALUE = '699dbedad126579b6bc0ebb91eaae8d7af3548b5'


def acw_response(*, seed=True, **headers):
	response_headers = {'Content-Type': 'text/html; charset=utf-8', **headers}
	if seed:
		response_headers['Set-Cookie'] = 'cdn_sec_tc=synthetic-waf-seed; Path=/; Secure; HttpOnly'
	return httpx.Response(200, text=ACW_HTML, headers=response_headers)


async def test_password_login_negotiates_acw_and_persists_cookies_for_next_execution():
	login_attempts = 0

	def handler(request):
		nonlocal login_attempts
		if request.url.path == '/api/user/login':
			login_attempts += 1
			assert request.headers['x-requested-with'] == 'XMLHttpRequest'
			assert 'Chrome/' in request.headers['user-agent']
			if login_attempts == 1:
				assert 'cookie' not in request.headers
				return acw_response()
			assert f'acw_sc__v2={ACW_VALUE}' in request.headers['cookie']
			assert 'cdn_sec_tc=synthetic-waf-seed' in request.headers['cookie']
			return httpx.Response(
				200,
				json={'success': True, 'data': {'id': 42}},
				headers={'Set-Cookie': 'session=synthetic-fresh-session; Path=/; Secure; HttpOnly'},
			)
		assert 'session=synthetic-fresh-session' in request.headers['cookie']
		return user() if request.method == 'GET' else httpx.Response(200, json={'success': True})

	runner, store, requests, _, _ = runtime(handler)
	events: list[dict] = []
	result = await runner.execute(password(), on_progress=events.append)
	assert result['success'] is True and login_attempts == 2
	assert [request.url.path for request in requests] == [
		'/api/user/login',
		'/api/user/login',
		'/api/user/self',
		'/api/user/sign_in',
		'/api/user/self',
	]
	assert any(event['stage'] == 'acw_verification' for event in events)
	assert [step['state'] for step in result['steps'] if step['stage'] == 'password_login'] == [
		'verification_required',
		'completed',
	]
	assert not any(step['state'] == 'failed' for step in result['steps'])
	assert any(step.get('request_attempt') == 2 for step in result['steps'])
	assert {cookie['name'] for cookie in store.writes[0][2]['cookies']} >= {'session', 'acw_sc__v2', 'cdn_sec_tc'}
	assert (await runner.execute(password()))['success'] is True
	assert login_attempts == 2 and len(requests) == 8
	for value in ('private-password', 'synthetic-fresh-session', ACW_VALUE, 'synthetic-waf-seed'):
		assert value not in json.dumps([result, events])


async def test_cookie_auth_refreshes_acw_on_read_without_repeating_checkin():
	reads = 0

	def handler(request):
		nonlocal reads
		if request.method == 'GET':
			reads += 1
			if reads == 1:
				return acw_response()
		assert request.headers['cookie'].count('acw_sc__v2=') == 1
		assert f'acw_sc__v2={ACW_VALUE}' in request.headers['cookie']
		return user() if request.method == 'GET' else httpx.Response(200, json={'success': True})

	runner, store, requests, _, _ = runtime(handler)
	result = await runner.execute(account(cookies=COOKIE + '; acw_sc__v2=old-waf'))
	assert result['success'] is True and len(store.writes) == 1
	assert [request.method for request in requests] == ['GET', 'GET', 'POST', 'GET']


async def test_wrong_password_after_acw_is_still_a_login_failure():
	attempts = 0

	def handler(request):
		nonlocal attempts
		attempts += 1
		if attempts == 1:
			return acw_response()
		return httpx.Response(401, json={'success': False, 'message': 'incorrect password'})

	runner, store, requests, _, _ = runtime(handler)
	result = await runner.execute(password())
	assert result['success'] is False and result['reason'] == 'credentials_rejected'
	assert [step['state'] for step in result['steps'] if step['stage'] == 'password_login'] == [
		'verification_required',
		'failed',
	]
	assert len(requests) == 2 and not store.writes


async def test_acw_challenge_has_three_request_limit_and_never_saves_failed_session():
	runner, store, requests, _, _ = runtime(lambda request: acw_response())
	result = await runner.execute(password())
	assert result['reason'] == 'acw_challenge_limit' and result['outcome'] == 'blocked'
	assert len(requests) == 3 and not store.writes
	assert all(request.url.path == '/api/user/login' for request in requests)
	assert result['diagnostic']['request_attempt'] == 3
	assert result['diagnostic']['max_attempts'] == 3


@pytest.mark.parametrize('mode', ['unknown-template', 'no-cookie-context', 'wrong-cookie-domain', 'additional-script'])
async def test_unsupported_acw_challenge_never_resends_password(mode):
	def handler(request):
		response = acw_response(seed=mode != 'no-cookie-context')
		if mode == 'unknown-template':
			return httpx.Response(
				200, text=ACW_HTML.replace('function a0i()', 'function unknown()'), headers=response.headers
			)
		if mode == 'additional-script':
			return httpx.Response(200, text=ACW_HTML + '<script>fetch("/business")</script>', headers=response.headers)
		if mode == 'wrong-cookie-domain':
			response.headers['Set-Cookie'] = 'cdn_sec_tc=synthetic-waf-seed; Domain=unrelated.test; Path=/'
		return response

	runner, store, requests, _, _ = runtime(handler)
	result = await runner.execute(password())
	assert result['reason'] == (
		'acw_cookie_context_missing'
		if mode in {'no-cookie-context', 'wrong-cookie-domain'}
		else 'acw_challenge_unsupported'
	)
	assert len(requests) == 1 and not store.writes


@pytest.mark.parametrize(
	'code,headers,reason',
	[
		(200, {'cf-mitigated': 'challenge'}, 'interactive_verification_required'),
		(429, {'Retry-After': '60'}, 'rate_limited'),
		(503, {}, 'request_result_unknown'),
		(302, {'Location': 'https://unrelated.test/'}, 'response_redirected'),
	],
)
async def test_acw_markers_do_not_override_cf_rate_limits_service_errors_or_redirects(code, headers, reason):
	runner, store, requests, _, _ = runtime(
		lambda request: httpx.Response(
			code,
			text=ACW_HTML,
			headers={'Content-Type': 'text/html', 'Set-Cookie': 'cdn_sec_tc=synthetic; Path=/', **headers},
		)
	)
	result = await runner.execute(password())
	assert result['reason'] == reason
	assert len(requests) == 1 and not store.writes


@pytest.mark.parametrize('credentials', [account(), agent()])
async def test_side_effecting_requests_returning_acw_are_uncertain_and_never_repeated(credentials):
	def handler(request):
		if credentials['provider'] == 'agentrouter' or request.method == 'POST':
			return acw_response()
		return user()

	runner, store, requests, _, _ = runtime(handler)
	result = await runner.execute(credentials)
	assert result['outcome'] == 'uncertain'
	assert result['reason'] == 'acw_challenge_requires_confirmation'
	assert len(requests) == (1 if credentials['provider'] == 'agentrouter' else 2)
	assert not store.writes


async def test_network_failure_after_acw_is_not_retried_again():
	attempts = 0

	def handler(request):
		nonlocal attempts
		attempts += 1
		if attempts == 1:
			return acw_response()
		raise httpx.ReadTimeout('private-password', request=request)

	runner, store, requests, _, _ = runtime(handler)
	result = await runner.execute(password())
	assert result['reason'] == 'request_result_unknown' and result['outcome'] == 'uncertain'
	assert len(requests) == 2 and not store.writes
	assert 'private-password' not in json.dumps(result)


async def test_post_checkin_read_can_negotiate_acw_without_repeating_the_write():
	reads = 0

	def handler(request):
		nonlocal reads
		if request.method == 'POST':
			return httpx.Response(200, json={'success': True})
		reads += 1
		return acw_response() if reads == 2 else user()

	runner, store, requests, _, _ = runtime(handler)
	assert (await runner.execute(account()))['success'] is True
	assert [request.method for request in requests] == ['GET', 'POST', 'GET', 'GET']
	assert len(store.writes) == 1
