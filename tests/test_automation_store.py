"""Health and notifications are persistent and never treat unknown data as zero."""

import copy
import json
import sqlite3
from datetime import datetime

import pytest

from server.automation_store import AutomationStore, build_daily_summary
from server.balance_store import BalanceStore
from server.config_store import default_config, validate_config
from utils.cron_schedule import LOCAL_TIMEZONE


def config():
	document = default_config()
	document['accounts'] = [
		{
			'id': 'one',
			'name': 'Account',
			'provider': 'anyrouter',
			'auth_type': 'cookie',
			'api_user': '7',
			'cookies': 'session=synthetic',
		}
	]
	document['automation']['low_balance'].update(enabled=True, threshold=5, cooldown_minutes=60)
	document['automation']['recovery'].update(enabled=True, cooldown_minutes=60)
	return validate_config(document)


def test_low_balance_threshold_cooldown_recovery_and_credential_changes(tmp_path):
	settings = config()
	account = settings['accounts'][0]
	store = AutomationStore(tmp_path / 'db')
	row = {'state': 'ok', 'stale': False, 'balance': 2}
	first = store.check_low_balance(account, settings, row, now=1000)
	assert len(first) == 1
	store.finish(first[0], {'state': 'accepted', 'channels': []})
	assert store.check_low_balance(account, settings, row, now=1100) == []
	store.close()
	store = AutomationStore(tmp_path / 'db')
	assert store.check_low_balance(account, settings, row, now=1200) == []
	assert len(store.check_low_balance(account, settings, row, now=4700)) == 1
	assert store.check_low_balance(account, settings, {**row, 'balance': 6}, now=4800) == []
	assert len(store.check_low_balance(account, settings, row, now=4900)) == 1
	updated = copy.deepcopy(settings)
	updated['accounts'][0]['cookies'] = 'session=replaced'
	assert len(store.check_low_balance(updated['accounts'][0], updated, row, now=5000)) == 1
	store.close()


@pytest.mark.parametrize(
	'changes', [{'stale': True}, {'balance': None}, {'balance': float('nan')}, {'balance': True}, {'state': 'failed'}]
)
def test_missing_stale_or_failed_balance_does_not_alert(tmp_path, changes):
	settings = config()
	store = AutomationStore(tmp_path / 'db')
	assert (
		store.check_low_balance(
			settings['accounts'][0], settings, {'state': 'ok', 'stale': False, 'balance': 0, **changes}
		)
		== []
	)
	store.close()


def test_per_account_threshold_and_disabled_account(tmp_path):
	settings = config()
	account = settings['accounts'][0]
	account['low_balance_threshold'] = 1
	store = AutomationStore(tmp_path / 'db')
	row = {'state': 'ok', 'stale': False, 'balance': 2}
	assert store.check_low_balance(account, settings, row) == []
	account['enabled'] = False
	assert store.check_low_balance(account, settings, {**row, 'balance': 0}) == []
	store.close()


def test_unknown_low_balance_delivery_is_not_retried_after_cooldown(tmp_path):
	settings = config()
	account = settings['accounts'][0]
	row = {'state': 'ok', 'stale': False, 'balance': 2}
	store = AutomationStore(tmp_path / 'db')
	claim = store.check_low_balance(account, settings, row, now=1000)[0]
	store.finish(claim, {'state': 'unknown', 'channels': []})
	assert store.check_low_balance(account, settings, row, now=100000) == []
	store.check_low_balance(account, settings, {**row, 'balance': 10}, now=100001)
	assert len(store.check_low_balance(account, settings, row, now=100002)) == 1
	store.close()


def test_health_scopes_are_independent_and_recovery_is_real_transition(tmp_path):
	settings = config()
	account = settings['accounts'][0]
	store = AutomationStore(tmp_path / 'db')
	ok = {'success': True, 'outcome': 'success'}
	failed = {'success': False, 'outcome': 'uncertain', 'reason': 'write_unknown'}
	assert store.record_health(account, settings, 'balance', ok, now=1000) == []
	assert store.record_health(account, settings, 'checkin', failed, now=1001) == []
	assert store.record_health(account, settings, 'checkin', {'outcome': 'skipped'}, now=1002) == []
	assert store.record_health(account, settings, 'balance', ok, now=1003) == []
	health = store.snapshot(settings)['health']
	checkin = next(item for item in health if item['scope'] == 'checkin')
	assert checkin['state'] == 'uncertain' and checkin['consecutive_failures'] == 1
	assert len(store.record_health(account, settings, 'checkin', ok, now=1100)) == 1
	assert store.record_health(account, settings, 'checkin', ok, now=1200) == []
	store.record_health(account, settings, 'checkin', failed, now=1201)
	assert store.record_health(account, settings, 'checkin', ok, now=1202) == []
	store.close()


def test_notification_claim_survives_restart_without_retries_or_raw_errors(tmp_path):
	settings = config()
	store = AutomationStore(tmp_path / 'db', run_id=7)
	claim = store.claim('summary:2026-10-25', 'daily_summary', 'Title', 'Body')
	assert claim is not None
	store.close()
	store = AutomationStore(tmp_path / 'db')
	store.interrupt_pending()
	assert store.claim('summary:2026-10-25', 'daily_summary', 'Title', 'Body') is None
	assert store.pending(claim) is None
	assert store.snapshot(settings)['daily_summary']['last_state'] == 'unknown'
	claim2 = store.claim('another', 'recovery', 'Title', 'Body')
	assert claim2 is not None
	store.finish(
		claim2,
		{
			'state': 'failed',
			'channels': [{'channel': 'Fy1Push', 'state': 'failed', 'error_code': 'token=private-secret'}],
		},
	)
	assert 'private-secret' not in json.dumps(store.snapshot(settings))
	store.close()


def test_daily_summary_reports_partial_coverage_and_current_day_runs(tmp_path):
	settings = config()
	now = datetime(2026, 10, 20, 23, 55, tzinfo=LOCAL_TIMEZONE).timestamp()
	path = tmp_path / 'db'
	balances = BalanceStore(path)
	balances.record(
		settings['accounts'][0], settings, {'id': 7, 'quota': 1000000, 'used_quota': 0, 'observed_at': now - 20}
	)
	balances.record(
		settings['accounts'][0], settings, {'id': 7, 'quota': 1250000, 'used_quota': 250000, 'observed_at': now - 10}
	)
	balances.close()
	with sqlite3.connect(path) as db:
		db.execute('CREATE TABLE runs(kind TEXT,summary TEXT,started_at REAL,finished_at REAL,state TEXT)')
		db.execute(
			'INSERT INTO runs VALUES (?,?,?,?,?)',
			('checkin', json.dumps({'accounts': [{'id': 'one', 'success': True}]}), now - 10, now - 5, 'succeeded'),
		)
		db.execute(
			'INSERT INTO runs VALUES (?,?,?,?,?)',
			(
				'checkin',
				json.dumps({'accounts': [{'id': 'one', 'success': False}]}),
				now - 100000,
				now - 99999,
				'failed',
			),
		)
	title, body = build_daily_summary(path, settings, now=now)
	assert title == '每日摘要 2026-10-20'
	assert '今日新增: $1.0000' in body and '含部分采集时段' in body
	assert '成功 1, 失败或待处理 0' in body
	assert '采集期净变化: $0.5000' in body
	late = datetime(2026, 10, 21, 0, 1, tzinfo=LOCAL_TIMEZONE).timestamp()
	late_title, late_body = build_daily_summary(path, settings, now=late, day='2026-10-20')
	assert late_title == title and '日期: 2026-10-20' in late_body
	assert '总余额: $2.5000' in late_body


@pytest.mark.parametrize(
	'section,field,value',
	[
		('low_balance', 'threshold', -1),
		('low_balance', 'threshold', True),
		('low_balance', 'threshold', float('nan')),
		('low_balance', 'cooldown_minutes', 0),
		('recovery', 'enabled', 1),
		('daily_summary', 'time', '24:00'),
	],
)
def test_automation_configuration_rejects_invalid_values(section, field, value):
	settings = config()
	settings['automation'][section][field] = value
	with pytest.raises(ValueError):
		validate_config(settings)


def test_legacy_schedule_defaults_remain_interval_and_automation_is_opt_in():
	settings = default_config()
	settings.pop('automation')
	settings['schedule'] = {'enabled': False, 'interval_minutes': 720}
	settings = validate_config(settings)
	assert settings['schedule']['mode'] == 'interval' and settings['schedule']['interval_minutes'] == 720
	assert not any(item['enabled'] for item in settings['automation'].values())
