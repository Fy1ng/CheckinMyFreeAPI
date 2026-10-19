"""HTTP worker execution, persistent pauses, and secret-free notifications."""

import asyncio
import base64
import copy
import json
import os
from unittest.mock import Mock

import pytest

from server import worker
from server.config_store import default_config
from server.execution_state import ExecutionState
from utils.http_checkin import account_binding


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
			'auth_type': 'system_token',
			'system_access_token': 'synthetic-private-token',
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

		async def execute(self, account):
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
	assert 'synthetic-private-token' not in json.dumps(progress)
	assert 'synthetic-private-token' not in str(notify.call_args_list)
	if outcome != 'success':
		assert 'https://console.example.test/?account=main' in notify.call_args.args[1]


@pytest.mark.asyncio
async def test_scheduled_accounts_stay_paused_and_uncertain_requires_explicit_resolution(fixture, monkeypatch):
	payload, notify = fixture
	calls = []

	class Runtime:
		def __init__(self, config, sessions):
			pass

		async def execute(self, account):
			calls.append(account['id'])
			return {
				'id': 'main',
				'name': 'Fixture',
				'provider': 'agentrouter',
				'success': False,
				'outcome': 'uncertain',
				'reason': 'request_result_unknown',
			}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(payload) == 1
	payload['trigger'] = 'scheduled'
	assert await worker.execute(payload) == 1
	payload['trigger'] = 'manual'
	assert await worker.execute(payload) == 1
	assert calls == ['main']
	assert notify.call_count == 1
	payload['config']['accounts'][0]['system_access_token'] = 'changed-token-still-requires-confirmation'
	await worker.execute(payload)
	assert calls == ['main']
	state = ExecutionState(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	state.clear('main')
	state.close()
	await worker.execute(payload)
	assert calls == ['main', 'main']


@pytest.mark.asyncio
async def test_credential_update_releases_old_pause(fixture, monkeypatch):
	payload, _ = fixture
	state = ExecutionState(worker.Path(payload['data_dir']) / 'webui.sqlite3')
	state.record(
		'main',
		account_binding(payload['config']['accounts'][0], payload['config']),
		{'outcome': 'blocked', 'reason': 'interactive_verification_required'},
	)
	state.close()
	payload['config']['accounts'][0]['system_access_token'] = 'replacement-private-token'
	payload['trigger'] = 'scheduled'
	calls = []

	class Runtime:
		def __init__(self, config, sessions):
			pass

		async def execute(self, account):
			calls.append(account['id'])
			return {
				'id': 'main',
				'name': 'Fixture',
				'provider': 'agentrouter',
				'success': True,
				'outcome': 'success',
				'reason': 'user_info_requested_reward_unverified',
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

		async def execute(self, account):
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

		async def execute(self, account):
			calls.append(account['id'])
			raise RuntimeError('synthetic-private-exception')

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(payload) == 1
	payload['trigger'] = 'scheduled'
	assert await worker.execute(payload) == 1
	assert calls == ['main']
	assert 'synthetic-private-exception' not in open(payload['event_file'], encoding='utf-8').read()
