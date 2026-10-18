from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import urlencode

import pytest

from utils.oauth import AuthError, OAuthAttempt, OAuthFlow, browser_json


@pytest.fixture
def attempt():
	return OAuthAttempt('linuxdo', 'https://provider.test', 'test-client', 'synthetic-state')


def test_callback_requires_exact_origin_path_and_state(attempt):
	url = 'https://provider.test/oauth/linuxdo?' + urlencode({'code': 'synthetic-code', 'state': attempt.state})
	assert attempt.callback_code(url) == 'synthetic-code'
	assert attempt.state not in repr(attempt)


@pytest.mark.parametrize(
	'url',
	[
		'https://provider.test.attacker.test/oauth/linuxdo?code=fake&state=synthetic-state',
		'https://provider.test/oauth/github?code=fake&state=synthetic-state',
		'https://provider.test/oauth/linuxdo?code=fake&state=wrong',
		'https://provider.test/oauth/linuxdo?code=fake&state=synthetic-state&state=synthetic-state',
		'https://provider.test/oauth/linuxdo?code=one&code=two&state=synthetic-state',
		'https://provider.test/oauth/linuxdo?state=synthetic-state',
		'http://provider.test/oauth/linuxdo?code=fake&state=synthetic-state',
	],
)
def test_invalid_callbacks_fail_without_echoing_secrets(attempt, url):
	with pytest.raises(AuthError) as error:
		attempt.callback_code(url)
	assert 'synthetic-state' not in str(error.value)
	assert url not in str(error.value)


def test_denied_authorization_is_not_success(attempt):
	with pytest.raises(AuthError, match='OAUTH_DENIED'):
		attempt.callback_code('https://provider.test/oauth/linuxdo?error=access_denied&state=synthetic-state')


def test_automatic_approval_checks_client_state_origin_and_scopes():
	attempt = OAuthAttempt('github', 'https://provider.test', 'client', 'state')
	assert attempt.can_approve(attempt.authorization_url)
	assert not attempt.can_approve(attempt.authorization_url.replace('client_id=client', 'client_id=other'))
	assert not attempt.can_approve(attempt.authorization_url.replace('state=state', 'state=other'))
	assert not attempt.can_approve(attempt.authorization_url.replace('user%3Aemail', 'repo'))
	assert not attempt.can_approve('https://github.com/login')


@pytest.mark.asyncio
async def test_oauth_exchange_is_consumed_exactly_once(attempt):
	context = SimpleNamespace(route=AsyncMock(), unroute=AsyncMock())
	flow = OAuthFlow(context, attempt)
	flow.completed.set_result(('synthetic-code', None))
	page = SimpleNamespace(
		url=attempt.origin + '/login',
		evaluate=AsyncMock(return_value={'status': 200, 'data': {'success': True, 'data': {'id': 7}}}),
	)
	assert await flow.exchange(page) == {'id': 7}
	with pytest.raises(AuthError, match='OAUTH_CALLBACK_NOT_AVAILABLE'):
		await flow.exchange(page)
	assert page.evaluate.await_count == 1
	assert 'credentials' in page.evaluate.call_args.args[0]
	assert 'redirect' in page.evaluate.call_args.args[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'status,reason',
	[
		(429, 'RATE_LIMITED'),
		(403, 'ACCESS_BLOCKED'),
		(502, 'NETWORK_OR_SERVICE_ERROR'),
		(0, 'NETWORK_OR_SERVICE_ERROR'),
		(401, 'SESSION_EXPIRED'),
	],
)
async def test_api_error_classification(status, reason):
	page = SimpleNamespace(
		url='https://provider.test/login', evaluate=AsyncMock(return_value={'status': status, 'data': None})
	)
	with pytest.raises(AuthError, match=reason):
		await browser_json(page, 'https://provider.test', '/api/user/self')


@pytest.mark.asyncio
async def test_json_api_does_not_accept_html_containing_success():
	page = SimpleNamespace(
		url='https://provider.test/login', evaluate=AsyncMock(return_value={'status': 200, 'data': None})
	)
	with pytest.raises(AuthError, match='INVALID_API_RESPONSE'):
		await browser_json(page, 'https://provider.test', '/api/user/sign_in', method='POST')


@pytest.mark.asyncio
async def test_api_call_does_not_run_on_an_identity_provider_page():
	page = SimpleNamespace(url='https://github.com/login', evaluate=AsyncMock())
	with pytest.raises(AuthError, match='PROVIDER_ORIGIN_MISMATCH'):
		await browser_json(page, 'https://provider.test', '/api/oauth/github?code=fake')
	page.evaluate.assert_not_awaited()
