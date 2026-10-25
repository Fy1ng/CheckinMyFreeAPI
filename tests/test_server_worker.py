"""HTTP worker execution, persistent pauses, and secret-free notifications."""

import asyncio
import base64
import copy
import json
import os
import time
from unittest.mock import Mock

import httpx
import pytest

from server import worker
from server.balance_store import BalanceStore
from server.config_store import default_config
from server.execution_state import ExecutionState
from utils.http_checkin import HttpCheckinRuntime, account_binding

AGENT_PASSWORD = 'synthetic-private-password'


async def test_balance_refresh_is_read_only_does_not_notify_or_clear_uncertain_write(fixture, monkeypatch):
	payload, notify = fixture
	payload['kind'] = 'balance'
	config = payload['config']
	account = config['accounts'][0]
	state = ExecutionState(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	state.record(account['id'], account_binding(account, config), {'outcome': 'uncertain', 'reason': 'write_unknown'})
	state.close()

	class Runtime:
		def __init__(self, config, sessions):
			self.balance_observations = []
			self.balance_error = None

		async def execute(self, *args, **kwargs):
			pytest.fail('A balance refresh cannot execute checkin')

		async def balance(self, account, *, on_progress=None):
			self.balance_observations = [{'id': 42, 'quota': 500000, 'used_quota': 0, 'observed_at': time.time()}]
			return {'id': account['id'], 'success': True, 'outcome': 'success', 'reason': 'balance_refreshed'}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(payload) == 0
	notify.assert_not_called()
	state = ExecutionState(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	pending = state.get(account['id'], account_binding(account, config))
	assert pending is not None and pending['reason'] == 'write_unknown'
	state.close()
	store = BalanceStore(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	assert store.snapshot(config)['summary']['balance'] == 1
	store.close()


async def test_balance_rate_limit_prevents_immediate_manual_retry_without_pausing_checkin_as_unknown(
	fixture, monkeypatch
):
	payload, notify = fixture
	payload['kind'] = 'balance'
	calls = []

	class Runtime:
		def __init__(self, config, sessions):
			self.balance_observations = []
			self.balance_error = None

		async def balance(self, account, *, on_progress=None):
			calls.append(account['id'])
			return {
				'id': account['id'],
				'success': False,
				'outcome': 'rate_limited',
				'reason': 'rate_limited',
				'retry_after_seconds': 300,
			}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(payload) == 1
	assert await worker.execute(payload) == 1
	assert calls == ['main']
	notify.assert_not_called()
	state = ExecutionState(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	assert state.get('main', account_binding(payload['config']['accounts'][0], payload['config'])) is None
	state.close()


async def test_balance_cancellation_does_not_create_write_uncertainty(fixture, monkeypatch):
	payload, notify = fixture
	payload['kind'] = 'balance'

	class Runtime:
		def __init__(self, config, sessions):
			pass

		async def balance(self, *args, **kwargs):
			raise asyncio.CancelledError

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	with pytest.raises(asyncio.CancelledError):
		await worker.execute(payload)
	state = ExecutionState(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	assert state.get('main', account_binding(payload['config']['accounts'][0], payload['config'])) is None
	state.close()
	notify.assert_not_called()


async def test_auxiliary_balance_storage_failure_does_not_undo_confirmed_checkin(fixture, monkeypatch):
	payload, _ = fixture

	class Runtime:
		def __init__(self, config, sessions):
			self.balance_observations = [{'id': 42, 'quota': 500000}]

		async def execute(self, account, *, on_progress=None):
			return {'id': account['id'], 'success': True, 'outcome': 'success', 'reason': 'agent_checkin_verified'}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	monkeypatch.setattr(BalanceStore, 'record', Mock(side_effect=RuntimeError('synthetic private exception')))
	assert await worker.execute(payload) == 0
	progress = json.loads(open(payload['event_file'], encoding='utf-8').read())
	assert progress['summary']['accounts'][0]['reason'] == 'agent_checkin_verified'
	assert progress['summary']['accounts'][0]['balance_warning'] == 'balance_storage_failed'
	assert 'private exception' not in json.dumps(progress)


@pytest.fixture
def fixture(monkeypatch, tmp_path):
	monkeypatch.setattr(os, 'environ', dict(os.environ))
	monkeypatch.setattr('utils.logging_safety.install_redaction', lambda: None)
	notify = Mock()
	monkeypatch.setattr('utils.notify.notify.push_message', notify)
	config = default_config()
	config['webui_url'] = 'https://console.example.test'
	config['accounts'] = [
		{
			'id': 'main',
			'provider': 'agentrouter',
			'auth_type': 'password',
			'username': 'synthetic-agent-user',
			'password': AGENT_PASSWORD,
			'api_user': '42',
			'name': 'Fixture',
		}
	]
	payload = {
		'config': config,
		'data_dir': str(tmp_path),
		'event_file': str(tmp_path / 'run.json'),
		'key': base64.b64encode(os.urandom(32)).decode(),
	}
	return payload, notify


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'outcome,expected',
	[
		('success', 'succeeded'),
		('needs_credentials', 'needs_attention'),
		('blocked', 'needs_attention'),
		('rate_limited', 'needs_attention'),
		('uncertain', 'uncertain'),
		('failed', 'failed'),
	],
)
async def test_http_worker_result_categories_and_private_notifications(fixture, monkeypatch, outcome, expected):
	payload, notify = fixture
	calls = []

	class Runtime:
		def __init__(self, config, sessions):
			pass

		async def execute(self, account, *, on_progress=None):
			calls.append(account['id'])
			return {
				'id': account['id'],
				'name': account['name'],
				'provider': account['provider'],
				'success': outcome == 'success',
				'outcome': outcome,
				'reason': 'synthetic_reason',
			}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	before = copy.deepcopy(payload)
	assert await worker.execute(payload) == (0 if outcome == 'success' else 1)
	assert payload == before
	progress = json.loads(open(payload['event_file'], encoding='utf-8').read())
	assert progress['state'] == expected
	assert calls == ['main']
	assert AGENT_PASSWORD not in json.dumps(progress)
	assert AGENT_PASSWORD not in str(notify.call_args_list)
	if outcome != 'success':
		assert 'https://console.example.test/?account=main' in notify.call_args.args[1]


@pytest.mark.asyncio
async def test_scheduled_accounts_stay_paused_and_uncertain_requires_explicit_resolution(fixture, monkeypatch):
	payload, notify = fixture
	calls = []

	class Runtime:
		def __init__(self, config, sessions):
			pass

		async def execute(self, account, *, on_progress=None):
			calls.append(account['id'])
			return {
				'id': 'main',
				'name': 'Fixture',
				'provider': 'agentrouter',
				'success': False,
				'outcome': 'uncertain',
				'reason': 'agent_checkin_result_unknown',
			}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(payload) == 1
	payload['trigger'] = 'scheduled'
	assert await worker.execute(payload) == 1
	payload['trigger'] = 'manual'
	assert await worker.execute(payload) == 1
	assert calls == ['main']
	assert notify.call_count == 1
	payload['config']['accounts'][0]['password'] = 'changed-password-still-requires-confirmation'
	await worker.execute(payload)
	assert calls == ['main']
	state = ExecutionState(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	state.clear('main')
	state.close()
	await worker.execute(payload)
	assert calls == ['main', 'main']


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'field,value',
	[
		('username', 'replacement-agent-user'),
		('password', 'replacement-private-password'),
		('api_user', '43'),
		('proxy', 'http://127.0.0.1:8081'),
	],
)
async def test_credential_or_route_update_releases_old_pause(fixture, monkeypatch, field, value):
	payload, _ = fixture
	state = ExecutionState(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	state.record(
		'main',
		account_binding(payload['config']['accounts'][0], payload['config']),
		{'outcome': 'blocked', 'reason': 'interactive_verification_required'},
	)
	state.close()
	payload['config']['accounts'][0][field] = value
	payload['trigger'] = 'scheduled'
	calls = []

	class Runtime:
		def __init__(self, config, sessions):
			pass

		async def execute(self, account, *, on_progress=None):
			calls.append(account['id'])
			return {
				'id': 'main',
				'name': 'Fixture',
				'provider': 'agentrouter',
				'success': True,
				'outcome': 'success',
				'reason': 'agent_checkin_verified',
			}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(payload) == 0
	assert calls == ['main']


@pytest.mark.asyncio
async def test_cancellation_records_uncertainty_and_does_not_retry(fixture, monkeypatch):
	payload, _ = fixture

	class Runtime:
		def __init__(self, config, sessions):
			pass

		async def execute(self, account, *, on_progress=None):
			raise asyncio.CancelledError

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	with pytest.raises(asyncio.CancelledError):
		await worker.execute(payload)
	state = ExecutionState(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	saved = state.get('main', account_binding(payload['config']['accounts'][0], payload['config']))
	state.close()
	assert saved is not None and saved['outcome'] == 'uncertain'


@pytest.mark.asyncio
async def test_unexpected_mid_account_error_pauses_instead_of_silently_replaying(fixture, monkeypatch):
	payload, _ = fixture
	calls = []

	class Runtime:
		def __init__(self, config, sessions):
			pass

		async def execute(self, account, *, on_progress=None):
			calls.append(account['id'])
			raise RuntimeError('synthetic-private-exception')

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(payload) == 1
	payload['trigger'] = 'scheduled'
	assert await worker.execute(payload) == 1
	assert calls == ['main']
	assert 'synthetic-private-exception' not in open(payload['event_file'], encoding='utf-8').read()


@pytest.mark.asyncio
async def test_worker_single_account_scope_reports_live_stages_and_stable_notifications(fixture, monkeypatch):
	payload, notify = fixture
	payload['config']['accounts'].append({**payload['config']['accounts'][0], 'id': 'other'})
	payload['account_id'] = 'other'
	calls, observed = [], []

	class Runtime:
		def __init__(self, config, sessions):
			pass

		async def execute(self, account, *, on_progress=None):
			calls.append(account['id'])
			event = {
				'stage': 'password_login',
				'state': 'running',
				'at': str(len(calls)),
				'method': 'POST',
				'path': '/api/user/login',
			}
			on_progress(event)
			observed.append(json.loads(open(payload['event_file'], encoding='utf-8').read()))
			return {
				'id': account['id'],
				'name': account['name'],
				'provider': account['provider'],
				'success': True,
				'outcome': 'success',
				'reason': 'agent_checkin_verified',
				'steps': [event],
			}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(payload) == 0
	assert calls == ['other']
	assert observed[0]['summary']['progress']['active_account']['stage'] == 'password_login'
	assert observed[0]['active_account'] == 'other'
	assert observed[0]['summary']['progress']['completed'] == 0
	assert observed[0]['summary']['progress']['total'] == 1
	assert AGENT_PASSWORD not in json.dumps(observed)
	final = json.loads(open(payload['event_file'], encoding='utf-8').read())
	assert [result['id'] for result in final['summary']['accounts']] == ['other']
	assert final['summary']['progress'] == {'total': 1, 'completed': 1, 'active_account': None}
	assert notify.call_count == 1
	assert await worker.execute(payload) == 0
	assert notify.call_count == 1
	payload.pop('account_id')
	assert await worker.execute(payload) == 0
	assert calls == ['other', 'other', 'main', 'other']
	assert notify.call_count == 2
	payload['account_id'] = 'other'
	assert await worker.execute(payload) == 0
	assert notify.call_count == 2


@pytest.mark.asyncio
@pytest.mark.parametrize('scope', ['missing', 1])
async def test_worker_rejects_invalid_single_account_before_any_execution(fixture, scope):
	payload, notify = fixture
	payload['account_id'] = scope
	with pytest.raises(ValueError):
		await worker.execute(payload)
	notify.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'checked_in,outcome,reason,state',
	[
		(True, 'success', 'agent_checkin_verified', 'succeeded'),
		(False, 'failed', 'agent_checkin_not_confirmed', 'failed'),
		(None, 'uncertain', 'agent_checkin_result_unknown', 'uncertain'),
		('true', 'uncertain', 'agent_checkin_result_unknown', 'uncertain'),
	],
)
async def test_agent_login_result_flows_through_worker_and_unknown_results_stay_paused(
	fixture, monkeypatch, checked_in, outcome, reason, state
):
	payload, notify = fixture
	payload['config']['accounts'][0]['api_user'] = ''
	requests = []

	def handler(request):
		requests.append(request)
		if request.method == 'GET':
			assert request.url == 'https://agentrouter.org/api/user/self'
			assert request.headers['new-api-user'] == '42'
			assert 'session=ignored-agent-session' in request.headers['cookie']
			return httpx.Response(200, json={'success': True, 'data': {'id': 42, 'quota': 500000, 'used_quota': 0}})
		assert request.method == 'POST' and request.url == 'https://agentrouter.org/api/user/login?turnstile='
		assert json.loads(request.content) == {'username': 'synthetic-agent-user', 'password': AGENT_PASSWORD}
		assert 'authorization' not in request.headers and 'cookie' not in request.headers
		data = {'id': 42}
		if checked_in is not None:
			data['checked_in'] = checked_in
		return httpx.Response(
			200,
			json={'success': True, 'data': data},
			headers={'Set-Cookie': 'session=ignored-agent-session; Path=/; Secure; HttpOnly'},
		)

	def runtime_factory(config, sessions):
		def client_factory(**kwargs):
			assert kwargs.pop('proxy') is None
			assert kwargs['verify'] is True and kwargs['trust_env'] is False
			assert kwargs['follow_redirects'] is False
			return httpx.AsyncClient(transport=httpx.MockTransport(handler), **kwargs)

		return HttpCheckinRuntime(config, sessions, client_factory=client_factory)

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', runtime_factory)
	assert await worker.execute(payload) == (0 if outcome == 'success' else 1)
	progress = json.loads(open(payload['event_file'], encoding='utf-8').read())
	assert progress['state'] == state
	result = progress['summary']['accounts'][0]
	assert result['outcome'] == outcome and result['reason'] == reason
	assert len(requests) == (2 if checked_in is True else 1)
	assert AGENT_PASSWORD not in json.dumps(progress) + str(notify.call_args_list)
	assert 'ignored-agent-session' not in json.dumps(progress) + str(notify.call_args_list)
	if outcome == 'uncertain':
		payload['trigger'] = 'scheduled'
		assert await worker.execute(payload) == 1
		payload['trigger'] = 'manual'
		payload['config']['accounts'][0]['password'] = 'updated-password-needs-confirmation'
		assert await worker.execute(payload) == 1
		assert len(requests) == 1 and notify.call_count == 1
