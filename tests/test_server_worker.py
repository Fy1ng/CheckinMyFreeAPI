"""Worker adapter contracts using disposable data and fake authentication only."""

import asyncio
import base64
import copy
import hmac
import json
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import server.worker as worker_module
import utils.auth_runtime as auth_module
import utils.logging_safety as logging_module
import utils.notify as notify_module
from server.config_store import build_app_config, default_config
from utils.config import AccountConfig
from utils.oauth import AuthError, ManualLoginRequired


@pytest.fixture
def isolated_worker(monkeypatch, tmp_path):
	# execute() is a subprocess entry point. Give direct unit calls a detached
	# environment mapping, and leave the real test runner's process environment intact.
	parent_environment = os.environ
	parent_values = dict(parent_environment)
	monkeypatch.setattr(os, 'environ', dict(parent_values))
	monkeypatch.setattr(logging_module, 'install_redaction', lambda: None)
	monkeypatch.setattr(auth_module, 'ManualTakeover', auth_module.ManualTakeover)
	monkeypatch.setattr(
		auth_module, 'launch_login_context', AsyncMock(side_effect=AssertionError('No real browser allowed'))
	)
	notify = Mock()
	monkeypatch.setattr(notify_module, 'notify', SimpleNamespace(push_message=notify))
	key = bytes(range(32))
	config = default_config()
	config['accounts'] = [
		{
			'id': 'password-account',
			'name': 'Synthetic password account',
			'email': 'synthetic@example.test',
			'password': 'synthetic-account-password',
			'proxy': 'direct',
		},
		{
			'id': 'oauth-account',
			'provider': 'agentrouter',
			'api_user': '9',
			'expected_username': 'synthetic-user',
			'auth': {'type': 'github', 'identity': 'main'},
		},
	]
	config['identities'] = {'main': {'type': 'github', 'proxy': 'direct'}}
	config['providers'] = {'anyrouter': {'domain': 'https://synthetic.example.test'}}
	config['proxy_url'] = 'http://proxy.example.test:8080'
	config['notifications'] = {'EMAIL_PASS': 'synthetic-notification-password', 'EMAIL_TO': 'recipient@example.test'}
	payload = {
		'config': config,
		'key': base64.b64encode(key).decode(),
		'data_dir': str(tmp_path),
		'event_file': str(tmp_path / 'run-1.json'),
		'run_id': 1,
		'manual_session': 'synthetic-manual-session-with-at-least-32-characters',
	}
	yield SimpleNamespace(
		payload=payload,
		key=key,
		notify=notify,
		parent_environment=parent_environment,
		parent_values=parent_values,
	)
	assert dict(parent_environment) == parent_values


def install_runtime(monkeypatch, runtime, captured=None):
	def factory(accounts, config, **kwargs):
		if captured is not None:
			captured.update(accounts=accounts, config=config, environment=dict(os.environ), **kwargs)
		return runtime

	monkeypatch.setattr(auth_module.AuthenticationRuntime, 'from_environment', factory)


@pytest.mark.asyncio
async def test_worker_converts_config_and_derives_separate_login_key(isolated_worker, monkeypatch, tmp_path):
	fixture = isolated_worker
	runtime = SimpleNamespace(
		execute=AsyncMock(return_value=(True, None, {'quota': 12.5})),
		close=Mock(),
	)
	captured: dict = {}
	install_runtime(monkeypatch, runtime, captured)
	before = copy.deepcopy(fixture.payload)
	assert await worker_module.execute(fixture.payload) == 0
	assert fixture.payload == before
	accounts = captured['accounts']
	assert all(isinstance(account, AccountConfig) for account in accounts)
	assert accounts[0].password == 'synthetic-account-password'
	assert accounts[1].auth == {'type': 'github', 'identity': 'main'}
	assert accounts[1].api_user == '9'
	assert captured['config'] == build_app_config(fixture.payload['config'])
	environment = captured['environment']
	expected_state_key = hmac.digest(fixture.key, b'checkin-server-login-state-v1', 'sha256')
	assert base64.urlsafe_b64decode(environment['CHECKIN_STATE_KEY']) == expected_state_key
	assert expected_state_key != fixture.key
	assert json.loads(environment['ANYROUTER_ACCOUNTS']) == fixture.payload['config']['accounts']
	assert json.loads(environment['CHECKIN_IDENTITIES']) == fixture.payload['config']['identities']
	assert json.loads(environment['PROVIDERS']) == fixture.payload['config']['providers']
	assert environment['CHECKIN_PROXY_URL'] == 'http://proxy.example.test:8080'
	assert environment['EMAIL_PASS'] == 'synthetic-notification-password'
	assert environment['EMAIL_TO'] == 'recipient@example.test'
	assert environment['CHECKIN_MANUAL_TRANSPORT'] == 'local'
	assert environment['CHECKIN_MANUAL_SESSION'] == fixture.payload['manual_session']
	assert environment['CHECKIN_HEADLESS'] == 'false'
	assert environment['CHECKIN_HUMANIZE'] == 'true'
	assert environment['CHECKIN_WAIT_TIMEOUT_MS'] == '60000'
	assert environment['CHECKIN_AUTH_CACHE_FILE'] == str(tmp_path / 'auth-cache' / 'auth-state.enc')
	assert environment['CHECKIN_STATE_SCOPE'] == 'checkin-server-v1'
	assert fixture.parent_environment is not os.environ
	assert dict(fixture.parent_environment) == fixture.parent_values
	runtime.close.assert_called_once()
	progress = json.loads((tmp_path / 'run-1.json').read_text(encoding='utf-8'))
	assert progress['state'] == 'succeeded'
	assert progress['manual'] is None
	assert progress['summary']['success_count'] == 2
	assert progress['summary']['accounts'][0]['balance'] == 12.5
	assert 'synthetic-account-password' not in json.dumps(progress)
	assert 'synthetic-notification-password' not in json.dumps(progress)
	assert fixture.key.hex() not in json.dumps(progress)
	fixture.notify.assert_called_once()


@pytest.mark.asyncio
async def test_all_automatic_accounts_run_before_manual_queue(isolated_worker, monkeypatch, tmp_path):
	fixture = isolated_worker
	fixture.payload['config']['accounts'].append(
		{'id': 'third', 'email': 'third@example.test', 'password': 'synthetic'}
	)
	order = []

	async def execute(account, index, *, allow_manual):
		order.append((index, allow_manual))
		if index != 1 and not allow_manual:
			raise ManualLoginRequired()
		if index == 0:
			raise AuthError('SYNTHETIC_MANUAL_FAILURE')
		return True, None, {'quota': index}

	runtime = SimpleNamespace(execute=execute, close=Mock())
	install_runtime(monkeypatch, runtime)
	assert await worker_module.execute(fixture.payload) == 1
	assert order == [(0, False), (1, False), (2, False), (0, True), (2, True)]
	progress = json.loads((tmp_path / 'run-1.json').read_text(encoding='utf-8'))
	assert progress['summary']['success_count'] == 2
	assert [result['success'] for result in progress['summary']['accounts']] == [False, True, True]
	assert progress['summary']['accounts'][0]['error'] == 'SYNTHETIC_MANUAL_FAILURE'
	assert progress['manual'] is None
	runtime.close.assert_called_once()


@pytest.mark.asyncio
async def test_manual_entry_is_published_only_during_takeover(isolated_worker, monkeypatch, tmp_path):
	fixture = isolated_worker
	inside = []
	exited = []

	class FakeTakeover:
		def __init__(self, timeout):
			self.timeout = timeout
			self.url = 'http://127.0.0.1:1234'

		async def __aenter__(self):
			return self

		async def __aexit__(self, *args):
			exited.append(True)

	monkeypatch.setattr(worker_module, 'ManualTakeover', FakeTakeover)

	async def execute(account, index, *, allow_manual):
		if not allow_manual:
			raise ManualLoginRequired()
		async with auth_module.ManualTakeover(30):
			progress = json.loads((tmp_path / 'run-1.json').read_text(encoding='utf-8'))
			inside.append(progress['manual'])
		assert json.loads((tmp_path / 'run-1.json').read_text(encoding='utf-8'))['manual'] is None
		return True, None, None

	install_runtime(monkeypatch, SimpleNamespace(execute=execute, close=Mock()))
	assert await worker_module.execute(fixture.payload) == 0
	assert len(inside) == len(exited) == 2
	assert all(manual['session'] == fixture.payload['manual_session'] for manual in inside)
	assert all(manual['url'] == 'http://127.0.0.1:1234' and manual['deadline'] > 0 for manual in inside)
	assert json.loads((tmp_path / 'run-1.json').read_text(encoding='utf-8'))['manual'] is None


@pytest.mark.asyncio
async def test_generic_account_error_does_not_leak_exception_or_block_other_accounts(
	isolated_worker, monkeypatch, tmp_path
):
	async def execute(account, index, *, allow_manual):
		if index == 0:
			raise RuntimeError('synthetic password and private callback token')
		return True, None, {'quota': 7}

	runtime = SimpleNamespace(execute=execute, close=Mock())
	install_runtime(monkeypatch, runtime)
	assert await worker_module.execute(isolated_worker.payload) == 1
	progress = json.loads((tmp_path / 'run-1.json').read_text(encoding='utf-8'))
	assert progress['summary']['accounts'][0]['error'] == 'RuntimeError'
	assert progress['summary']['accounts'][1]['success'] is True
	assert 'private callback token' not in json.dumps(progress)
	runtime.close.assert_called_once()


@pytest.mark.asyncio
async def test_cancellation_closes_runtime_and_main_returns_cancel_status(isolated_worker, monkeypatch):
	monkeypatch.setattr(asyncio.get_running_loop(), 'add_signal_handler', Mock())
	runtime = SimpleNamespace(execute=AsyncMock(side_effect=asyncio.CancelledError), close=Mock())
	install_runtime(monkeypatch, runtime)
	assert await worker_module.main(isolated_worker.payload) == 130
	runtime.close.assert_called_once()
	isolated_worker.notify.assert_not_called()


@pytest.mark.asyncio
async def test_runtime_startup_failure_is_sanitized_by_main(isolated_worker, monkeypatch, tmp_path):
	monkeypatch.setattr(asyncio.get_running_loop(), 'add_signal_handler', Mock())

	def fail(accounts, config, **kwargs):
		raise RuntimeError('synthetic password and token must stay private')

	monkeypatch.setattr(auth_module.AuthenticationRuntime, 'from_environment', fail)
	assert await worker_module.main(isolated_worker.payload) == 1
	progress = json.loads((tmp_path / 'run-1.json').read_text(encoding='utf-8'))
	assert progress['state'] == 'failed'
	assert progress['manual'] is None
	assert 'RuntimeError' in progress['error']
	assert 'synthetic password' not in progress['error']
	isolated_worker.notify.assert_not_called()


@pytest.mark.asyncio
async def test_unchanged_success_skips_notification_and_changed_result_notifies(isolated_worker, monkeypatch):
	fixture = isolated_worker
	quota = 1

	async def execute(account, index, *, allow_manual):
		return True, None, {'quota': quota}

	install_runtime(monkeypatch, SimpleNamespace(execute=execute, close=Mock()))
	assert await worker_module.execute(fixture.payload) == 0
	assert await worker_module.execute(fixture.payload) == 0
	assert fixture.notify.call_count == 1
	quota = 2
	assert await worker_module.execute(fixture.payload) == 0
	assert fixture.notify.call_count == 2


@pytest.mark.asyncio
async def test_notification_failure_does_not_invalidate_successful_checkin(isolated_worker, monkeypatch, tmp_path):
	runtime = SimpleNamespace(execute=AsyncMock(return_value=(True, None, None)), close=Mock())
	install_runtime(monkeypatch, runtime)
	isolated_worker.notify.side_effect = RuntimeError('synthetic notification password')
	assert await worker_module.execute(isolated_worker.payload) == 0
	progress = json.loads((tmp_path / 'run-1.json').read_text(encoding='utf-8'))
	assert progress['state'] == 'succeeded'
	assert progress['summary']['notification_error'] is True
	assert 'synthetic notification password' not in json.dumps(progress)
