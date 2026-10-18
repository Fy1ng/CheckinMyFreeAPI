"""Local-only configuration validation and encrypted persistence checks."""

import ast
import copy
import os
import sqlite3
from pathlib import Path

import pytest

from server.config_store import (
	NOTIFICATION_ENV_NAMES,
	SECRET_KEEP,
	ConfigError,
	ConfigStore,
	ConflictError,
	build_app_config,
	default_config,
	redact_config,
	validate_config,
)


def password_account(account_id='first', password='synthetic-password-one'):
	return {'id': account_id, 'name': account_id, 'email': f'{account_id}@example.test', 'password': password}


def populated_config():
	config = default_config()
	config['accounts'] = [password_account(), password_account('second', 'synthetic-password-two')]
	config['accounts'][0]['cookies'] = {'session': 'synthetic-cookie'}
	config['accounts'][0]['proxy'] = 'http://user:synthetic-proxy-password@proxy.example.test:8080'
	config['identities'] = {
		'primary': {'type': 'linuxdo', 'proxy': 'http://identity:synthetic-id-password@proxy.test:88'}
	}
	config['proxy_url'] = 'https://global:synthetic-global-password@proxy.example.test:444'
	config['notifications'] = {'EMAIL_PASS': 'synthetic-notify-password', 'EMAIL_TO': 'recipient@example.test'}
	return config


def test_default_is_independent_and_does_not_read_environment(monkeypatch):
	monkeypatch.setenv('CHECKIN_PROXY_URL', 'broken')
	monkeypatch.setenv('PROVIDERS', 'broken')
	monkeypatch.setenv('CHECKIN_IDENTITIES', 'broken')
	before = dict(os.environ)
	first = default_config()
	first['browser']['headless'] = True
	assert default_config()['browser']['headless'] is False
	assert validate_config({}) == default_config()
	assert build_app_config(default_config()).providers['agentrouter'].use_proxy is True
	assert dict(os.environ) == before


def test_encrypted_database_has_no_plaintext_and_reopens(tmp_path):
	path = tmp_path / 'private' / 'config.sqlite3'
	key = os.urandom(32)
	store = ConfigStore(path, key)
	assert store.load() == (default_config(), 0)
	config = populated_config()
	result = store.save(config, 0)
	assert result['revision'] == 1
	assert result['config'] == redact_config(validate_config(config))
	store.close()
	for file in path.parent.iterdir():
		data = file.read_bytes()
		for secret in (
			b'synthetic-password-one',
			b'synthetic-cookie',
			b'synthetic-proxy-password',
			b'synthetic-id-password',
			b'synthetic-global-password',
			b'synthetic-notify-password',
		):
			assert secret not in data
		assert key not in data
	reopened = ConfigStore(path, key)
	assert reopened.load() == (validate_config(config), 1)
	reopened.close()
	if os.name != 'nt':
		assert path.stat().st_mode & 0o777 == 0o600


def test_compare_and_swap_across_two_connections(tmp_path):
	path, key = tmp_path / 'config.db', os.urandom(32)
	first, second = ConfigStore(path, key), ConfigStore(path, key)
	first.save(default_config(), 0)
	with pytest.raises(ConflictError, match='changed'):
		second.save(default_config(), 0)
	assert second.load()[1] == 1
	second.save(default_config(), 1)
	assert first.load()[1] == 2
	first.close()
	second.close()


def test_secret_retention_is_bound_to_account_id_and_identity_alias(tmp_path):
	store = ConfigStore(tmp_path / 'config.db', os.urandom(32))
	config = populated_config()
	public = store.save(config, 0)
	public['config']['accounts'].reverse()
	public['config']['identities'] = {
		'new': {'type': 'github', 'proxy': 'direct'},
		'primary': public['config']['identities']['primary'],
	}
	store.save(public['config'], 1)
	loaded, _ = store.load()
	assert loaded['accounts'][0]['password'] == 'synthetic-password-two'
	assert loaded['accounts'][1]['password'] == 'synthetic-password-one'
	assert loaded['accounts'][1]['cookies'] == {'session': 'synthetic-cookie'}
	assert loaded['identities']['primary'] == config['identities']['primary']
	assert loaded['notifications'] == config['notifications']
	assert loaded['proxy_url'] == config['proxy_url']
	changed = store.public()['config']
	changed['accounts'][0]['id'] = 'renamed'
	with pytest.raises(ConfigError, match='no stored value'):
		store.save(changed, 2)
	assert store.load()[1] == 2
	changed = store.public()['config']
	changed['identities']['renamed'] = changed['identities'].pop('primary')
	with pytest.raises(ConfigError, match='no stored value'):
		store.save(changed, 2)
	store.close()


def test_explicit_empty_and_omission_delete_secrets(tmp_path):
	store = ConfigStore(tmp_path / 'config.db', os.urandom(32))
	config = populated_config()
	public = store.save(config, 0)['config']
	public['accounts'][0].update(password='', email='', api_user='7', proxy='direct')
	public['proxy_url'] = ''
	public['identities'] = {}
	public['notifications'] = {}
	store.save(public, 1)
	loaded, _ = store.load()
	assert loaded['accounts'][0]['password'] == ''
	assert loaded['accounts'][0]['cookies'] == {'session': 'synthetic-cookie'}
	assert loaded['accounts'][0]['proxy'] == 'direct'
	assert loaded['proxy_url'] == ''
	assert loaded['notifications'] == {}
	loaded['accounts'][0] = password_account(password='replacement')
	store.save(loaded, 2)
	assert 'cookies' not in store.load()[0]['accounts'][0]
	store.close()


def test_wrong_key_and_tampered_revision_never_reset_database(tmp_path):
	path, key = tmp_path / 'config.db', os.urandom(32)
	store = ConfigStore(path, key)
	store.save(populated_config(), 0)
	wrong = ConfigStore(path, os.urandom(32))
	for operation in (wrong.load, lambda: wrong.save(default_config(), 1)):
		with pytest.raises(ConfigError, match='cannot be decrypted'):
			operation()
	wrong.close()
	assert store.load()[1] == 1
	with sqlite3.connect(path) as db:
		db.execute('UPDATE config SET revision = 2')
	with pytest.raises(ConfigError, match='cannot be decrypted'):
		store.load()
	store.close()


def test_redaction_keeps_nonsecret_flags_and_does_not_mutate():
	config = populated_config()
	config['accounts'][1]['proxy'] = 'default'
	config['identities']['secondary'] = {'type': 'github', 'proxy': 'direct'}
	before = copy.deepcopy(config)
	public = redact_config(config)
	assert config == before
	assert public['accounts'][0]['password'] == SECRET_KEEP
	assert public['accounts'][0]['cookies'] == SECRET_KEEP
	assert public['accounts'][0]['proxy'] == SECRET_KEEP
	assert public['accounts'][1]['proxy'] == 'default'
	assert public['identities']['primary']['proxy'] == SECRET_KEEP
	assert public['identities']['secondary']['proxy'] == 'direct'
	assert public['notifications']['EMAIL_PASS'] == SECRET_KEEP
	assert public['notifications']['EMAIL_TO'] == 'recipient@example.test'


def test_notification_allowlist_matches_existing_notifier():
	module = ast.parse((Path(__file__).parents[1] / 'utils' / 'notify.py').read_text(encoding='utf-8'))
	read_names = {
		node.args[0].value
		for node in ast.walk(module)
		if isinstance(node, ast.Call)
		and isinstance(node.func, ast.Attribute)
		and isinstance(node.func.value, ast.Name)
		and node.func.value.id == 'os'
		and node.func.attr == 'getenv'
		and node.args
		and isinstance(node.args[0], ast.Constant)
	}
	assert NOTIFICATION_ENV_NAMES == read_names


@pytest.mark.parametrize('name', ['PATH', 'PYTHONPATH', 'CHECKIN_STATE_KEY', 'CHECKIN_PROXY_URL'])
def test_unknown_notification_environment_is_rejected(name):
	config = default_config()
	config['notifications'][name] = 'synthetic-secret'
	with pytest.raises(ConfigError, match='unsupported field') as error:
		validate_config(config)
	assert 'synthetic-secret' not in str(error.value)


def oauth_config():
	config = default_config()
	config['identities'] = {'main': {'type': 'github'}}
	config['proxy_url'] = 'http://proxy.example.test:8080'
	config['accounts'] = [
		{
			'id': provider,
			'provider': provider,
			'expected_username': 'synthetic',
			'auth': {'type': 'github', 'identity': 'main'},
		}
		for provider in ('anyrouter', 'agentrouter')
	]
	return config


def test_shared_identity_requires_consistent_effective_proxy():
	config = oauth_config()
	with pytest.raises(ConfigError, match='same effective proxy'):
		validate_config(config)
	config['identities']['main']['proxy'] = 'direct'
	assert len(validate_config(config)['accounts']) == 2
	config['accounts'][0]['proxy'] = 'default'
	with pytest.raises(ConfigError, match='proxy settings conflict'):
		validate_config(config)


def test_shared_identity_explicit_proxy_is_independent_of_process_env(monkeypatch):
	config = oauth_config()
	config['identities']['main']['proxy'] = 'default'
	monkeypatch.setenv('CHECKIN_PROXY_URL', 'http://different.example.test:9090')
	before = dict(os.environ)
	assert validate_config(config) == config
	assert dict(os.environ) == before


@pytest.mark.parametrize(
	'change',
	[
		lambda config: config.update(unknown='secret-value'),
		lambda config: config.update(accounts=[password_account(), password_account()]),
		lambda config: config.update(accounts=[{'email': 'x', 'password': 'secret-value'}]),
		lambda config: config['schedule'].update(enabled=True),
		lambda config: config['schedule'].update(interval_minutes=29),
		lambda config: config['browser'].update(wait_timeout_ms=999),
		lambda config: config['browser'].update(headless='false'),
		lambda config: config.update(proxy_url='http://user:secret-value@proxy.test:99999'),
		lambda config: config.update(proxy_url='socks5://user:secret-value@proxy.test:88'),
		lambda config: config.update(providers={'custom': {'domain': 'http://example.test'}}),
		lambda config: config.update(providers={'custom': {'domain': 'https://secret-value@example.test'}}),
		lambda config: config.update(providers={'custom': {'domain': 'https://example.test/path'}}),
		lambda config: config.update(
			providers={'custom': {'domain': 'https://example.test', 'login_path': '//evil.test'}}
		),
		lambda config: config.update(
			providers={'custom': {'domain': 'https://example.test', 'login_path': '/%2e%2e/x'}}
		),
		lambda config: config.update(
			providers={'custom': {'domain': 'https://example.test', 'api_user_key': 'X\r\nX'}}
		),
	],
)
def test_invalid_values_are_rejected_without_reflecting_credentials(change):
	config = default_config()
	change(config)
	with pytest.raises(ConfigError) as error:
		validate_config(config)
	assert 'secret-value' not in str(error.value)


def test_provider_overrides_and_numeric_binding_normalize():
	config = default_config()
	config['providers'] = {
		'anyrouter': {'domain': 'https://custom.example.test/', 'sign_in_path': None, 'use_proxy': False},
		'custom': {'domain': 'https://new.example.test', 'login_path': '/signin'},
	}
	config['accounts'] = [{'id': 'cookie-account', 'api_user': 7, 'cookies': 'session=synthetic'}]
	normalized = validate_config(config)
	assert normalized['providers']['anyrouter']['domain'] == 'https://custom.example.test'
	assert normalized['accounts'][0]['api_user'] == '7'
	app = build_app_config(normalized)
	assert app.providers['anyrouter'].persist_profile is True
	assert app.providers['anyrouter'].sign_in_path is None
	assert app.providers['custom'].login_path == '/signin'


@pytest.mark.parametrize('value', [None, [], {}, False, 0, 1])
def test_invalid_global_proxy_types_are_not_silently_treated_as_empty(value):
	config = default_config()
	config['proxy_url'] = value
	with pytest.raises(ConfigError):
		validate_config(config)


@pytest.mark.parametrize('value', [None, [], {}, False, 0, 1])
def test_invalid_identity_and_oauth_types_raise_config_error(value):
	config = default_config()
	config['identities']['main'] = {'type': value}
	with pytest.raises(ConfigError):
		validate_config(config)
	config = oauth_config()
	config['accounts'][0]['auth']['type'] = value
	with pytest.raises(ConfigError):
		validate_config(config)


@pytest.mark.parametrize(
	'domain',
	['https://example.test:', 'https://bad%20host.test', 'https://bad_host.test', 'https://-bad.example.test'],
)
def test_invalid_origin_host_is_rejected(domain):
	config = default_config()
	config['providers']['custom'] = {'domain': domain}
	with pytest.raises(ConfigError):
		validate_config(config)


def test_unicode_origin_and_scheme_are_normalized():
	config = default_config()
	config['providers']['custom'] = {'domain': 'HTTPS://例子.example:8443/'}
	assert validate_config(config)['providers']['custom']['domain'] == 'https://xn--fsqu00a.example:8443'


def test_failed_validation_rolls_back_and_preserves_previous_config(tmp_path):
	store = ConfigStore(tmp_path / 'config.db', os.urandom(32))
	store.save(populated_config(), 0)
	before = store.load()
	with pytest.raises(ConfigError):
		store.save({'schedule': {'enabled': True}}, 1)
	assert store.load() == before
	assert store.save(before[0], 1)['revision'] == 2
	store.close()


@pytest.mark.parametrize('revision', [-1, True, '0', 2**63])
def test_invalid_revision_is_rejected(tmp_path, revision):
	store = ConfigStore(tmp_path / 'config.db', os.urandom(32))
	with pytest.raises(ConfigError, match='revision'):
		store.save(default_config(), revision)
	store.close()
