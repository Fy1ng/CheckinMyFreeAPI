"""Identity task dispatch cannot call account check-in or require a site account."""

import asyncio
import base64
import json
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

import utils.auth_runtime as auth_module
import utils.identity_login as identity_module
import utils.logging_safety as logging_module
import utils.notify as notify_module
from server import worker
from server.config_store import default_config
from utils.oauth import AuthError


@pytest.fixture
def identity_worker(monkeypatch, tmp_path):
	monkeypatch.setattr(os, 'environ', dict(os.environ))
	monkeypatch.setattr(logging_module, 'install_redaction', lambda: None)
	monkeypatch.setattr(identity_module, 'ManualTakeover', identity_module.ManualTakeover)
	monkeypatch.setattr(auth_module, 'ManualTakeover', auth_module.ManualTakeover)
	checkin = Mock(side_effect=AssertionError('Identity login must not execute site check-in'))
	monkeypatch.setattr(auth_module.AuthenticationRuntime, 'from_environment', checkin)
	notify = Mock()
	monkeypatch.setattr(notify_module, 'notify', SimpleNamespace(push_message=notify))
	config = default_config()
	config['browser']['headless'] = True
	config['identities'] = {'main': {'type': 'linuxdo', 'proxy': 'direct'}}
	payload = {
		'kind': 'identity_login',
		'identity': 'main',
		'config': config,
		'key': base64.b64encode(os.urandom(32)).decode(),
		'data_dir': str(tmp_path),
		'event_file': str(tmp_path / 'run-1.json'),
		'manual_session': 'synthetic-session-for-identity-only',
	}
	runtime = SimpleNamespace(
		execute=AsyncMock(
			return_value={'user_id': '42', 'username': 'fixture-user', 'verified_at': '2026-10-19T00:00:00+00:00'}
		),
		close=Mock(),
	)
	captured: dict = {}

	def factory(config, *, accounts, notify_ready, bound_subjects):
		captured.update(
			accounts=accounts, notify_ready=notify_ready, bound_subjects=bound_subjects, environment=dict(os.environ)
		)
		return runtime

	monkeypatch.setattr(identity_module.IdentityLoginRuntime, 'from_environment', factory)
	return payload, runtime, captured, checkin, notify


@pytest.mark.asyncio
async def test_identity_task_runs_without_accounts_and_forces_only_this_browser_headed(identity_worker):
	payload, runtime, captured, checkin, notify = identity_worker
	assert await worker.execute(payload) == 0
	runtime.execute.assert_awaited_once_with('main')
	runtime.close.assert_called_once()
	checkin.assert_not_called()
	notify.assert_not_called()
	assert captured['accounts'] == []
	assert captured['environment']['CHECKIN_HEADLESS'] == 'false'
	assert captured['environment']['CHECKIN_MANUAL_HEADLESS'] == 'false'
	assert payload['config']['browser']['headless'] is True
	with open(payload['event_file'], encoding='utf-8') as stream:
		result = json.load(stream)
	assert result['state'] == 'succeeded'
	assert result['summary']['kind'] == 'identity_login'
	assert result['summary']['identity_result']['user_id'] == '42'
	assert result['summary']['identity_result']['state'] == 'verified'
	assert 'accounts' not in result['summary']


@pytest.mark.asyncio
async def test_identity_rejection_closes_runtime_without_site_actions(identity_worker):
	payload, runtime, _, checkin, _ = identity_worker
	runtime.execute.side_effect = AuthError('IDENTITY_ACCOUNT_MISMATCH')
	assert await worker.execute(payload) == 1
	runtime.close.assert_called_once()
	checkin.assert_not_called()
	with open(payload['event_file'], encoding='utf-8') as stream:
		assert json.load(stream)['error'] == 'IDENTITY_ACCOUNT_MISMATCH'


@pytest.mark.asyncio
async def test_identity_task_cancellation_closes_runtime(identity_worker):
	payload, runtime, _, checkin, _ = identity_worker
	runtime.execute.side_effect = asyncio.CancelledError
	with pytest.raises(asyncio.CancelledError):
		await worker.execute(payload)
	runtime.close.assert_called_once()
	checkin.assert_not_called()


@pytest.mark.asyncio
async def test_failed_identity_task_persists_safe_probe_diagnostics(identity_worker):
	payload, runtime, _, checkin, _ = identity_worker
	runtime.diagnostics = {
		'provider': 'linuxdo',
		'endpoint': '/session/current.json',
		'http_status': 403,
		'response_kind': 'cloudflare_challenge',
	}
	runtime.execute.side_effect = AuthError('MANUAL_LOGIN_TIMED_OUT')
	assert await worker.execute(payload) == 1
	with open(payload['event_file'], encoding='utf-8') as stream:
		result = json.load(stream)
	assert result['summary']['identity_result'] == {'state': 'unverified', 'diagnostics': runtime.diagnostics}
	assert result['error'] == 'MANUAL_LOGIN_TIMED_OUT'
	checkin.assert_not_called()


@pytest.mark.asyncio
async def test_chrome_selection_reaches_identity_worker_without_touching_other_engine(identity_worker, tmp_path):
	payload, runtime, captured, checkin, _ = identity_worker
	payload['config']['browser']['engine'] = 'chrome'
	base = tmp_path / 'auth-root'
	legacy = base / 'live'
	legacy.mkdir(parents=True)
	marker = legacy / 'preserved-legacy-profile'
	marker.write_text('synthetic')
	os.environ['CHECKIN_AUTH_ROOT'] = str(base)
	assert await worker.execute(payload) == 0
	assert captured['environment']['CHECKIN_BROWSER_ENGINE'] == 'chrome'
	assert marker.read_text() == 'synthetic'
	runtime.execute.assert_awaited_once_with('main')
	checkin.assert_not_called()


@pytest.mark.asyncio
async def test_missing_system_chrome_reports_actionable_code(identity_worker, monkeypatch):
	payload, runtime, _, checkin, _ = identity_worker
	monkeypatch.setattr(
		identity_module.IdentityLoginRuntime,
		'from_environment',
		Mock(side_effect=AuthError('SYSTEM_CHROME_NOT_INSTALLED')),
	)
	assert await worker.execute(payload) == 1
	with open(payload['event_file'], encoding='utf-8') as stream:
		assert json.load(stream)['error'] == 'SYSTEM_CHROME_NOT_INSTALLED'
	runtime.execute.assert_not_called()
	checkin.assert_not_called()


@pytest.mark.asyncio
async def test_account_worker_startup_preserves_browser_error_code(identity_worker, monkeypatch):
	payload, _, _, _, _ = identity_worker
	monkeypatch.setattr(worker, 'execute', AsyncMock(side_effect=AuthError('SYSTEM_CHROME_NOT_INSTALLED')))
	assert await worker.main(payload) == 1
	with open(payload['event_file'], encoding='utf-8') as stream:
		assert json.load(stream)['error'] == 'SYSTEM_CHROME_NOT_INSTALLED'
