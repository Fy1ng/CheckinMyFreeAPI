"""Notification acceptance is observable without any live network calls."""

import base64
import json
import os
import sqlite3
import time
from unittest.mock import Mock

import pytest

from server import worker
from server.automation_store import AutomationStore
from server.config_store import default_config
from utils.notify import NotificationKit, NotificationRejected


def payload(tmp_path):
	config = default_config()
	config['accounts'] = [
		{
			'id': 'one',
			'name': 'Account',
			'enabled': True,
			'provider': 'anyrouter',
			'auth_type': 'cookie',
			'cookies': 'session=synthetic',
			'api_user': '7',
		}
	]
	with sqlite3.connect(tmp_path / 'webui.sqlite3') as db:
		db.execute('CREATE TABLE runs(kind TEXT,summary TEXT,started_at REAL,finished_at REAL,state TEXT)')
	return {
		'config': config,
		'key': base64.b64encode(os.urandom(32)).decode(),
		'data_dir': str(tmp_path),
		'event_file': str(tmp_path / 'event.json'),
		'run_id': 1,
	}


def test_observable_delivery_has_no_configured_channels(monkeypatch):
	from server.config_store import NOTIFICATION_ENV_NAMES

	for name in NOTIFICATION_ENV_NAMES:
		monkeypatch.delenv(name, raising=False)
	result = NotificationKit().deliver_message('Title', 'Body')
	assert result['state'] == 'not_configured' and not result['channels']


def test_observable_delivery_distinguishes_acceptance_rejection_and_unknown_without_secret_logs(monkeypatch, capsys):
	from server.config_store import NOTIFICATION_ENV_NAMES

	for name in NOTIFICATION_ENV_NAMES:
		monkeypatch.delenv(name, raising=False)
	kit = NotificationKit()
	kit.pushplus_token = 'synthetic'
	monkeypatch.setattr(kit, 'send_pushplus', Mock())
	assert kit.deliver_message('Title', 'Body')['state'] == 'accepted'
	monkeypatch.setattr(kit, 'send_pushplus', Mock(side_effect=NotificationRejected('private-token')))
	assert kit.deliver_message('Title', 'Body')['state'] == 'failed'
	monkeypatch.setattr(kit, 'send_pushplus', Mock(side_effect=RuntimeError('private-token')))
	result = kit.deliver_message('Title', 'Body')
	assert result['state'] == 'unknown' and result['device_delivery'] == 'unconfirmed'
	assert 'private-token' not in json.dumps(result) + capsys.readouterr().out


@pytest.mark.asyncio
async def test_summary_isolated_worker_sends_cached_data_once_and_never_calls_site(tmp_path, monkeypatch):
	import utils.notify as notify_module

	request = payload(tmp_path)
	request['kind'] = 'summary'
	notifier = Mock()
	notifier.deliver_message.return_value = {
		'state': 'accepted',
		'channels': [{'channel': 'Fy1Push', 'state': 'accepted'}],
	}
	monkeypatch.setattr(notify_module, 'notify', notifier)
	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Mock(side_effect=AssertionError('A summary cannot access sites')))
	assert await worker.execute(request) == 0
	assert await worker.execute(request) == 0
	notifier.deliver_message.assert_called_once()
	notifier.push_message.assert_not_called()
	summary = json.loads((tmp_path / 'event.json').read_text(encoding='utf-8'))['summary']
	assert summary['notification_state'] == 'already_recorded'


@pytest.mark.asyncio
async def test_notification_failure_is_recorded_but_does_not_undo_successful_checkin(tmp_path, monkeypatch):
	import utils.notify as notify_module

	request = payload(tmp_path)
	request['config']['automation']['low_balance']['enabled'] = True
	notifier = Mock()
	notifier.deliver_message.side_effect = RuntimeError('private-token')
	monkeypatch.setattr(notify_module, 'notify', notifier)

	class Runtime:
		def __init__(self, config, sessions):
			self.balance_error = None
			self.balance_observations = [{'id': 7, 'quota': 125000, 'used_quota': 0, 'observed_at': time.time()}]

		async def execute(self, account, *, on_progress=None):
			return {'id': account['id'], 'success': True, 'outcome': 'success', 'reason': 'checkin_verified'}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(request) == 0
	result = json.loads((tmp_path / 'event.json').read_text(encoding='utf-8'))
	assert result['state'] == 'succeeded' and result['summary']['accounts'][0]['success']
	store = AutomationStore(tmp_path / 'webui.sqlite3')
	try:
		notifications = store.snapshot(request['config'])['notifications']
		assert notifications[0]['state'] == 'unknown'
		assert 'private-token' not in json.dumps(notifications)
	finally:
		store.close()


@pytest.mark.asyncio
async def test_summary_without_channel_is_failure_not_fake_success(tmp_path, monkeypatch):
	import utils.notify as notify_module

	request = payload(tmp_path)
	request['kind'] = 'summary'
	notifier = Mock()
	notifier.deliver_message.return_value = {'state': 'not_configured', 'channels': []}
	monkeypatch.setattr(notify_module, 'notify', notifier)
	assert await worker.execute(request) == 1
	assert json.loads((tmp_path / 'event.json').read_text(encoding='utf-8'))['state'] == 'needs_attention'


@pytest.mark.asyncio
async def test_same_round_alerts_are_batched_and_each_event_remains_observable(tmp_path):
	store = AutomationStore(tmp_path / 'db')
	ids = [
		store.claim('low:one', 'low_balance', 'Low balance', 'First'),
		store.claim('low:two', 'low_balance', 'Low balance', 'Second'),
	]
	assert all(item is not None for item in ids)
	notifier = Mock()
	notifier.deliver_message.return_value = {'state': 'accepted', 'channels': []}
	try:
		results = await worker.deliver_automation(store, notifier, [item for item in ids if item is not None])
		notifier.deliver_message.assert_called_once()
		assert len(results) == 2 and all(item['state'] == 'accepted' for item in results)
	finally:
		store.close()


@pytest.mark.asyncio
async def test_successful_balance_read_before_uncertain_checkin_does_not_merge_health_scopes(tmp_path, monkeypatch):
	import utils.notify as notify_module

	request = payload(tmp_path)
	monkeypatch.setattr(notify_module, 'notify', Mock())

	class Runtime:
		def __init__(self, config, sessions):
			self.balance_error = None
			self.balance_observations = [{'id': 7, 'quota': 500000, 'used_quota': 0, 'observed_at': time.time()}]

		async def execute(self, account, *, on_progress=None):
			return {
				'id': account['id'],
				'name': account['name'],
				'success': False,
				'outcome': 'uncertain',
				'reason': 'write_unknown',
			}

	monkeypatch.setattr(worker, 'HttpCheckinRuntime', Runtime)
	assert await worker.execute(request) == 1
	store = AutomationStore(tmp_path / 'webui.sqlite3')
	try:
		health = {row['scope']: row for row in store.snapshot(request['config'])['health']}
		assert health['checkin']['state'] == 'uncertain'
		assert health['balance']['state'] == 'healthy'
	finally:
		store.close()
