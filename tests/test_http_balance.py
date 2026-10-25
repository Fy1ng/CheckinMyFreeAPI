"""Only MockTransport is used. Balance reads must never send a login or checkin."""

import copy

import httpx
import pytest

from utils.http_checkin import HttpCheckinRuntime, account_binding


class Sessions:
	def __init__(self):
		self.data = {}

	def load(self, account_id, binding):
		return copy.deepcopy(self.data.get((account_id, binding)))

	def save(self, account_id, binding, state):
		self.data[account_id, binding] = copy.deepcopy(state)


def config_account(provider='anyrouter', auth_type='cookie'):
	account = {
		'id': 'one',
		'name': 'Name',
		'provider': provider,
		'auth_type': auth_type,
		'api_user': '7',
		'cookies': 'session=synthetic' if auth_type == 'cookie' else '',
		'username': 'alice',
		'password': 'synthetic-password',
	}
	return {'http': {'timeout_seconds': 30}, 'monitoring': {'enabled': True}}, account


def runner(config, handler, sessions=None):
	store = sessions or Sessions()
	requests = []

	def dispatch(request):
		requests.append(request)
		return handler(request)

	def factory(**kwargs):
		kwargs.pop('proxy')
		return httpx.AsyncClient(transport=httpx.MockTransport(dispatch), **kwargs)

	return HttpCheckinRuntime(config, store, client_factory=factory), store, requests


def user(**extra):
	return httpx.Response(
		200, json={'success': True, 'data': {'id': 7, 'quota': 750000, 'used_quota': 100000, **extra}}
	)


async def test_cookie_balance_only_uses_self_and_never_mutates():
	config, account = config_account()
	runtime, store, requests = runner(config, lambda _: user())
	result = await runtime.balance(account)
	assert result['success'] and result['reason'] == 'balance_refreshed'
	assert [(r.method, r.url.path) for r in requests] == [('GET', '/api/user/self')]
	assert runtime.balance_observations[0]['quota'] == 750000
	assert store.data == {}


@pytest.mark.parametrize('provider', ['anyrouter', 'agentrouter'])
async def test_password_balance_without_session_never_logs_in(provider):
	config, account = config_account(provider, 'password')
	runtime, _, requests = runner(config, lambda _: pytest.fail('No request is allowed'))
	result = await runtime.balance(account)
	assert not result['success'] and result['reason'] == 'balance_session_required'
	assert requests == []


async def test_agent_balance_uses_session_and_expired_session_does_not_login():
	config, account = config_account('agentrouter', 'password')
	store = Sessions()
	store.save(
		'one',
		account_binding(account, config),
		{
			'api_user': '7',
			'cookies': [
				{
					'name': 'session',
					'value': 'synthetic-agent',
					'domain': 'agentrouter.org',
					'path': '/',
					'expires': None,
				}
			],
		},
	)
	runtime, _, requests = runner(config, lambda _: httpx.Response(401, json={'success': False}), store)
	result = await runtime.balance(account)
	assert result['reason'] == 'credentials_rejected'
	assert len(requests) == 1 and requests[0].method == 'GET'
	assert requests[0].headers['cookie'] == 'session=synthetic-agent'


async def test_agent_normal_login_persists_session_and_reads_real_balance_not_login_placeholder():
	config, account = config_account('agentrouter', 'password')

	def dispatch(request):
		if request.method == 'POST':
			assert 'cookie' not in request.headers
			return httpx.Response(
				200,
				json={'success': True, 'data': {'id': 7, 'checked_in': True, 'quota': 0}},
				headers={'Set-Cookie': 'session=synthetic-fresh; Path=/; Secure; HttpOnly'},
			)
		return user()

	runtime, store, requests = runner(config, dispatch)
	result = await runtime.execute(account)
	assert result['success'] and result['checked_in'] is True
	assert 'balance_after' not in result and runtime.balance_observations[0]['quota'] == 750000
	assert len(store.data) == 1 and [r.method for r in requests] == ['POST', 'GET']


async def test_failed_balance_after_successful_agent_login_does_not_undo_checkin():
	config, account = config_account('agentrouter', 'password')

	def dispatch(request):
		if request.method == 'POST':
			return user(checked_in=True)
		return httpx.Response(429, headers={'Retry-After': '60'})

	runtime, _, requests = runner(config, dispatch)
	result = await runtime.execute(account)
	assert result['success'] and result['reason'] == 'agent_checkin_verified'
	assert runtime.balance_error['outcome'] == 'rate_limited'
	assert runtime.balance_error['retry_after_seconds'] == 60 and len(requests) == 2
