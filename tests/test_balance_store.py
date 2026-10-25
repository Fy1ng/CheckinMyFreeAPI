"""Balance arithmetic uses only validated observations, never a fabricated baseline."""

import copy
from datetime import datetime, timezone

import pytest

from server.balance_store import BalanceStore, day_at
from server.config_store import default_config, validate_config


def fixture_config():
	config = default_config()
	config['accounts'] = [
		{
			'id': 'one',
			'name': 'Account',
			'provider': 'anyrouter',
			'auth_type': 'cookie',
			'cookies': 'session=synthetic',
			'api_user': '7',
			'enabled': True,
		}
	]
	return config


def at(text):
	return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


BASE = at('2026-10-20T03:00:00')


def test_unknown_is_not_zero_and_first_sample_is_not_daily_income(tmp_path):
	store = BalanceStore(tmp_path / 'db')
	config = fixture_config()
	assert store.snapshot(config, now=BASE)['summary']['balance'] is None
	assert store.record(config['accounts'][0], config, {'id': 7, 'quota': 500000, 'used_quota': 0, 'observed_at': BASE})
	snapshot = store.snapshot(config, now=BASE)
	assert snapshot['summary']['balance'] == 1
	assert snapshot['summary']['today_income'] is None
	assert snapshot['summary']['today_net_change'] is None
	assert snapshot['summary']['fresh_count'] == 1
	store.close()


def test_consumption_does_not_count_as_negative_income_and_credit_delta_excludes_consumption(tmp_path):
	store = BalanceStore(tmp_path / 'db')
	config = fixture_config()
	account = config['accounts'][0]
	store.record(account, config, {'id': 7, 'quota': 1000000, 'used_quota': 0, 'observed_at': BASE})
	store.record(account, config, {'id': 7, 'quota': 750000, 'used_quota': 250000, 'observed_at': BASE + 10})
	row = store.snapshot(config, now=BASE + 10)['accounts'][0]
	assert row['today_income'] == 0 and row['today_net_change'] == -0.5
	store.record(account, config, {'id': 7, 'quota': 1250000, 'used_quota': 500000, 'observed_at': BASE + 20})
	row = store.snapshot(config, now=BASE + 20)['accounts'][0]
	assert row['today_income'] == 1.5 and row['today_net_change'] == 0.5
	assert row['income_source'] == 'observed' and row['partial'] is True
	store.close()


def test_site_today_income_takes_precedence_and_cross_day_does_not_count_overnight_delta(tmp_path):
	store = BalanceStore(tmp_path / 'db')
	config = fixture_config()
	account = config['accounts'][0]
	before_midnight = at('2026-10-20T15:59:59')
	after_midnight = before_midnight + 2
	assert day_at(before_midnight) == '2026-10-20' and day_at(after_midnight) == '2026-10-21'
	store.record(
		account,
		config,
		{'id': 7, 'quota': 500000, 'used_quota': 0, 'today_income': 750000, 'observed_at': before_midnight},
	)
	row = store.snapshot(config, now=before_midnight)['accounts'][0]
	assert row['today_income'] == 1.5 and row['income_source'] == 'site' and not row['income_partial']
	store.record(account, config, {'id': 7, 'quota': 900000, 'used_quota': 0, 'observed_at': after_midnight})
	row = store.snapshot(config, now=after_midnight)['accounts'][0]
	assert row['today_income'] is None and row['today_net_change'] is None
	assert len(store.snapshot(config, now=after_midnight)['history']) == 2
	store.close()


@pytest.mark.parametrize('invalid', [None, True, False, -1, float('nan'), float('inf'), '500000', {}, 10**30])
def test_invalid_quota_never_overwrites_last_known_balance(tmp_path, invalid):
	store = BalanceStore(tmp_path / 'db')
	config = fixture_config()
	account = config['accounts'][0]
	store.record(account, config, {'id': 7, 'quota': 500000, 'observed_at': BASE})
	assert not store.record(account, config, {'id': 7, 'quota': invalid, 'observed_at': BASE + 1})
	row = store.snapshot(config, now=BASE + 2)['accounts'][0]
	assert row['balance'] == 1 and row['stale'] and row['state'] == 'failed'
	store.close()


@pytest.mark.parametrize('field,value', [('cookies', 'session=replaced'), ('api_user', '8'), ('proxy', 'direct')])
def test_credentials_identity_and_proxy_changes_invalidate_current_and_daily_history(tmp_path, field, value):
	store = BalanceStore(tmp_path / 'db')
	config = fixture_config()
	store.record(config['accounts'][0], config, {'id': 7, 'quota': 500000, 'observed_at': BASE})
	updated = copy.deepcopy(config)
	updated['accounts'][0][field] = value
	snapshot = store.snapshot(updated, now=BASE + 1)
	assert snapshot['summary']['balance'] is None and snapshot['history'] == []
	store.failure(updated['accounts'][0], updated, 'needs_credentials', 'balance_session_required')
	assert store.snapshot(updated, now=BASE + 2)['accounts'][0]['balance'] is None
	store.close()


def test_identity_mismatch_preserves_original_observation_and_negative_total_reset_is_unknown(tmp_path):
	store = BalanceStore(tmp_path / 'db')
	config = fixture_config()
	account = config['accounts'][0]
	store.record(account, config, {'id': 7, 'quota': 500000, 'used_quota': 500000, 'observed_at': BASE})
	assert not store.record(account, config, {'id': 8, 'quota': 900000, 'observed_at': BASE + 1})
	assert store.snapshot(config, now=BASE + 1)['accounts'][0]['balance'] == 1
	store.record(account, config, {'id': 7, 'quota': 500000, 'used_quota': 0, 'observed_at': BASE + 2})
	assert store.snapshot(config, now=BASE + 2)['accounts'][0]['today_income'] is None
	store.close()


def test_disabled_accounts_are_shown_but_not_in_totals_and_old_observations_are_stale(tmp_path):
	store = BalanceStore(tmp_path / 'db')
	config = fixture_config()
	config['accounts'].append({**config['accounts'][0], 'id': 'two', 'enabled': False})
	for account in config['accounts']:
		store.record(account, config, {'id': 7, 'quota': 500000, 'observed_at': BASE})
	snapshot = store.snapshot(config, now=BASE + 5000)
	assert snapshot['summary']['balance'] == 1 and snapshot['summary']['account_count'] == 1
	assert snapshot['summary']['fresh_count'] == 0 and len(snapshot['accounts']) == 2
	assert snapshot['accounts'][1]['state'] == 'disabled'
	store.close()


@pytest.mark.parametrize(
	'changes', [{'enabled': 'yes'}, {'interval_minutes': 1}, {'interval_minutes': True}, {'unexpected': 1}]
)
def test_monitoring_config_is_validated(changes):
	config = default_config()
	config['monitoring'].update(changes)
	with pytest.raises(ValueError):
		validate_config(config)


def test_monitoring_defaults_are_backward_compatible():
	config = default_config()
	del config['monitoring']
	assert validate_config(config)['monitoring'] == {'enabled': True, 'interval_minutes': 60}


def test_largest_supported_quota_can_be_serialized_and_aggregated(tmp_path):
	store = BalanceStore(tmp_path / 'db')
	config = fixture_config()
	config['accounts'].append({**config['accounts'][0], 'id': 'two'})
	try:
		for account in config['accounts']:
			assert store.record(account, config, {'id': 7, 'quota': 10**24, 'used_quota': 0, 'observed_at': BASE})
		snapshot = store.snapshot(config, now=BASE)
		assert snapshot['summary']['balance'] == 4e18
		assert snapshot['summary']['balance_count'] == 2
	finally:
		store.close()
