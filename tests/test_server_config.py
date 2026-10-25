"""HTTP-only schema validation, migration, and encrypted persistence checks."""

import ast
import copy
import json
import os
import sqlite3
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server.config_store import (
	NOTIFICATION_ENV_NAMES,
	SECRET_KEEP,
	ConfigError,
	ConfigStore,
	ConflictError,
	default_config,
	redact_config,
	validate_config,
)


def password_account(account_id='first', password='synthetic-password-one'):
	return {
		'id': account_id,
		'provider': 'anyrouter',
		'auth_type': 'password',
		'username': f'{account_id}@example.test',
		'password': password,
	}


def cookie_account(account_id='cookie'):
	return {
		'id': account_id,
		'provider': 'anyrouter',
		'auth_type': 'cookie',
		'cookies': {'session': 'synthetic-cookie'},
		'api_user': '7',
	}


def agent_account(account_id='agent'):
	return {**password_account(account_id, 'synthetic-agent-password'), 'provider': 'agentrouter'}


def token_account(account_id='token'):
	return {
		'id': account_id,
		'provider': 'agentrouter',
		'auth_type': 'system_token',
		'system_access_token': 'synthetic-system-token',
		'api_user': '8',
	}


def populated_config():
	config = default_config()
	config['accounts'] = [password_account(), cookie_account(), agent_account()]
	config['accounts'][0]['proxy'] = 'http://user:synthetic-proxy-password@proxy.example.test:8080'
	config['proxy_url'] = 'https://global:synthetic-global-password@proxy.example.test:444'
	config['notifications'] = {'EMAIL_PASS': 'synthetic-notify-password', 'EMAIL_TO': 'recipient@example.test'}
	return config


def legacy_database(path, key, document, revision=4):
	nonce = os.urandom(12)
	encrypted = nonce + AESGCM(key).encrypt(
		nonce, json.dumps(document).encode(), b'anyrouter.server.configuration.v1:' + str(revision).encode()
	)
	with sqlite3.connect(path) as db:
		db.execute('CREATE TABLE config (id INTEGER PRIMARY KEY, revision INTEGER NOT NULL, document BLOB NOT NULL)')
		db.execute('INSERT INTO config VALUES (1, ?, ?)', (revision, encrypted))
	return encrypted


def test_default_is_independent_and_does_not_read_environment(monkeypatch):
	monkeypatch.setenv('CHECKIN_PROXY_URL', 'broken')
	monkeypatch.setenv('PROVIDERS', 'broken')
	before = dict(os.environ)
	first = default_config()
	first['http']['timeout_seconds'] = 60
	assert default_config() == {
		'schema_version': 2,
		'accounts': [],
		'proxy_url': '',
		'notifications': {},
		'schedule': {'enabled': False, 'interval_minutes': 360},
		'monitoring': {'enabled': True, 'interval_minutes': 60},
		'http': {'timeout_seconds': 30},
		'webui_url': '',
	}
	assert validate_config({}) == default_config()
	assert dict(os.environ) == before


def test_encrypted_database_has_no_plaintext_and_reopens(tmp_path):
	path, key = tmp_path / 'private' / 'config.sqlite3', os.urandom(32)
	store = ConfigStore(path, key)
	assert store.load() == (default_config(), 0)
	assert store.migration_info() is None
	config = populated_config()
	result = store.save(config, 0)
	assert result == {'revision': 1, 'config': redact_config(validate_config(config))}
	assert store.migration_info() is None
	store.close()
	for file in path.parent.iterdir():
		data = file.read_bytes()
		for secret in (
			b'synthetic-password-one',
			b'synthetic-cookie',
			b'synthetic-agent-password',
			b'synthetic-proxy-password',
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
	try:
		first.save(default_config(), 0)
		with pytest.raises(ConflictError, match='changed'):
			second.save(default_config(), 0)
		assert second.load()[1] == 1
		second.save(default_config(), 1)
		assert first.load()[1] == 2
	finally:
		first.close()
		second.close()


def test_secret_retention_is_bound_to_id_provider_and_authentication(tmp_path):
	store = ConfigStore(tmp_path / 'config.db', os.urandom(32))
	try:
		config = populated_config()
		public = store.save(config, 0)['config']
		public['accounts'].reverse()
		store.save(public, 1)
		assert store.load()[0] == validate_config({**config, 'accounts': list(reversed(config['accounts']))})
		changed = store.public()['config']
		changed['accounts'][0]['id'] = 'renamed'
		with pytest.raises(ConfigError, match='no stored value'):
			store.save(changed, 2)
		changed = store.public()['config']
		changed['accounts'][0].update(provider='anyrouter', auth_type='cookie')
		with pytest.raises(ConfigError, match='no stored value'):
			store.save(changed, 2)
		assert store.load()[1] == 2
	finally:
		store.close()


def test_explicit_empty_and_omission_delete_secrets(tmp_path):
	store = ConfigStore(tmp_path / 'config.db', os.urandom(32))
	try:
		public = store.save(populated_config(), 0)['config']
		public['accounts'][0].update(password='', enabled=False, proxy='direct')
		public['accounts'][2].update(password='', enabled=False)
		public['proxy_url'] = ''
		public['notifications'] = {}
		store.save(public, 1)
		loaded, _ = store.load()
		assert loaded['accounts'][0]['password'] == ''
		assert loaded['accounts'][2]['password'] == ''
		assert loaded['proxy_url'] == ''
		assert loaded['notifications'] == {}
		loaded['accounts'][0].pop('password')
		store.save(loaded, 2)
		assert 'password' not in store.load()[0]['accounts'][0]
	finally:
		store.close()


def test_wrong_key_and_tampered_revision_never_reset_database(tmp_path):
	path, key = tmp_path / 'config.db', os.urandom(32)
	store = ConfigStore(path, key)
	store.save(populated_config(), 0)
	wrong = ConfigStore(path, os.urandom(32))
	try:
		for operation in (wrong.load, lambda: wrong.save(default_config(), 1)):
			with pytest.raises(ConfigError, match='cannot be decrypted'):
				operation()
		assert store.load()[1] == 1
		with sqlite3.connect(path) as db:
			db.execute('UPDATE config SET revision = 2')
		with pytest.raises(ConfigError, match='cannot be decrypted'):
			store.load()
	finally:
		wrong.close()
		store.close()


def test_redaction_keeps_nonsecret_flags_and_does_not_mutate():
	config = populated_config()
	config['accounts'][1]['proxy'] = 'direct'
	before = copy.deepcopy(config)
	public = redact_config(config)
	assert config == before
	assert public['accounts'][0]['password'] == SECRET_KEEP
	assert public['accounts'][1]['cookies'] == SECRET_KEEP
	assert public['accounts'][2]['password'] == SECRET_KEEP
	assert public['accounts'][0]['proxy'] == SECRET_KEEP
	assert public['accounts'][1]['proxy'] == 'direct'
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


def test_fy1push_token_encrypted_redacted_retained_and_explicitly_cleared(tmp_path):
	path = tmp_path / 'config.db'
	store = ConfigStore(path, os.urandom(32))
	try:
		config = default_config()
		config['notifications'] = {
			'FY1PUSH_SERVER': 'https://push.example.test',
			'FY1PUSH_TOKEN': 'synthetic-fy1push-secret',
			'FY1PUSH_CHANNEL': 'checkin',
		}
		public = store.save(config, 0)
		assert public['config']['notifications']['FY1PUSH_TOKEN'] == SECRET_KEEP
		assert b'synthetic-fy1push-secret' not in path.read_bytes()
		store.save(public['config'], 1)
		assert store.load()[0]['notifications']['FY1PUSH_TOKEN'] == 'synthetic-fy1push-secret'
		public = store.public()
		public['config']['notifications']['FY1PUSH_TOKEN'] = ''
		store.save(public['config'], 2)
		assert store.load()[0]['notifications']['FY1PUSH_TOKEN'] == ''
	finally:
		store.close()


@pytest.mark.parametrize(
	'field,value',
	[
		('FY1PUSH_SERVER', 'http://remote.example.test'),
		('FY1PUSH_SERVER', 'https://name:synthetic-secret@push.example.test'),
		('FY1PUSH_CHANNEL', 'two words'),
		('FY1PUSH_TOKEN', 'synthetic\tinjection'),
	],
)
def test_invalid_fy1push_configuration_fails_before_saving(field, value):
	config = default_config()
	config['notifications'][field] = value
	with pytest.raises(ConfigError):
		validate_config(config)


@pytest.mark.parametrize('name', ['PATH', 'PYTHONPATH', 'CHECKIN_STATE_KEY', 'CHECKIN_PROXY_URL'])
def test_unknown_notification_environment_is_rejected(name):
	config = default_config()
	config['notifications'][name] = 'synthetic-secret'
	with pytest.raises(ConfigError, match='unsupported field') as error:
		validate_config(config)
	assert 'synthetic-secret' not in str(error.value)


@pytest.mark.parametrize(
	'provider,auth_type',
	[
		('anyrouter', 'system_token'),
		('agentrouter', 'cookie'),
		('agentrouter', 'system_token'),
		('anyrouter', 'github'),
		('anyrouter', 'linuxdo'),
		('custom', 'cookie'),
		('https://anyrouter.top', 'cookie'),
	],
)
def test_provider_and_authentication_combinations_are_restricted(provider, auth_type):
	config = default_config()
	config['accounts'] = [{'id': 'x', 'provider': provider, 'auth_type': auth_type, 'enabled': False}]
	with pytest.raises(ConfigError):
		validate_config(config)


@pytest.mark.parametrize(
	'field,value',
	[('identities', {}), ('providers', {}), ('browser', {}), ('schema_version', 1), ('schema_version', True)],
)
def test_legacy_settings_are_rejected_in_new_documents(field, value):
	config = default_config()
	config[field] = value
	with pytest.raises(ConfigError):
		validate_config(config)


@pytest.mark.parametrize('account', [cookie_account(), agent_account(), password_account()])
def test_enabled_account_requires_complete_credentials_and_disabled_can_be_incomplete(account):
	config = default_config()
	secret = {'cookie': 'cookies', 'password': 'password'}[account['auth_type']]
	account.pop(secret)
	config['accounts'] = [account]
	with pytest.raises(ConfigError):
		validate_config(config)
	account['enabled'] = False
	assert validate_config(config)['accounts'][0]['enabled'] is False


@pytest.mark.parametrize('api_user', [None, '', '9', 9])
def test_agent_password_authentication_accepts_optional_api_user(api_user):
	account = agent_account()
	if api_user is not None:
		account['api_user'] = api_user
	config = {**default_config(), 'accounts': [account]}
	validated = validate_config(config)['accounts'][0]
	assert validated['auth_type'] == 'password' and validated['enabled']
	assert validated.get('api_user') == (None if api_user is None else str(api_user))


@pytest.mark.parametrize('field', ['username', 'password'])
def test_enabled_agent_password_authentication_requires_both_fields(field):
	account = agent_account()
	account.pop(field)
	with pytest.raises(ConfigError, match='username and password'):
		validate_config({**default_config(), 'accounts': [account]})


@pytest.mark.parametrize('field,value', [('cookies', 'session=synthetic'), ('system_access_token', 'synthetic-token')])
def test_agent_password_authentication_rejects_incompatible_credentials(field, value):
	with pytest.raises(ConfigError, match='cannot combine'):
		validate_config({**default_config(), 'accounts': [{**agent_account(), field: value}]})


@pytest.mark.parametrize(
	'cookies',
	[
		'session=x\r\nInjected:y',
		'session=x; malformed',
		'session=x; session=y',
		{'bad name': 'x'},
		{'session': 'x;y'},
		{'session': 'non ascii é'},
		{'session': 1},
		[],
	],
)
def test_cookie_headers_reject_ambiguous_or_injected_data(cookies):
	config = default_config()
	config['accounts'] = [{**cookie_account(), 'cookies': cookies}]
	with pytest.raises(ConfigError):
		validate_config(config)


def test_cookie_and_numeric_binding_are_normalized_without_mutating_input():
	config = default_config()
	config['accounts'] = [{**cookie_account(), 'api_user': 7, 'cookies': ' session=abc== ; other=x; '}]
	before = copy.deepcopy(config)
	assert validate_config(config)['accounts'][0]['cookies'] == 'session=abc==; other=x'
	assert validate_config(config)['accounts'][0]['api_user'] == '7'
	assert config == before


@pytest.mark.parametrize('value', ['x\r\nAuthorization:x', 'Bearer token', ' token ', 'é', SECRET_KEEP, {}, None])
def test_system_access_token_rejects_invalid_values_without_reflection(value):
	config = default_config()
	config['accounts'] = [{**agent_account(), 'system_access_token': value}]
	with pytest.raises(ConfigError) as error:
		validate_config(config)
	assert 'Authorization' not in str(error.value)


@pytest.mark.parametrize(
	'change',
	[
		lambda config: config.update(unknown='secret-value'),
		lambda config: config.update(accounts=[password_account(), password_account()]),
		lambda config: config.update(accounts=[{'id': 'x', 'email': 'x', 'password': 'secret-value'}]),
		lambda config: config['schedule'].update(enabled=True),
		lambda config: config['schedule'].update(interval_minutes=29),
		lambda config: config['http'].update(timeout_seconds=0),
		lambda config: config.update(proxy_url='http://user:secret-value@proxy.test:99999'),
		lambda config: config.update(proxy_url='socks5://user@proxy.test:88'),
		lambda config: config.update(accounts=[{**cookie_account(), 'password': 'secret-value'}]),
		lambda config: config.update(accounts=[{**agent_account(), 'api_user': 'x\r\nx'}]),
	],
)
def test_invalid_values_rejected_without_reflecting_credentials(change):
	config = default_config()
	change(config)
	with pytest.raises(ConfigError) as error:
		validate_config(config)
	assert 'secret-value' not in str(error.value)


@pytest.mark.parametrize('value', [None, [], {}, False, 0, 1])
def test_invalid_global_proxy_types_are_not_silently_treated_as_empty(value):
	config = default_config()
	config['proxy_url'] = value
	with pytest.raises(ConfigError):
		validate_config(config)


@pytest.mark.parametrize(
	'proxy',
	[
		'socks5://user:synthetic-proxy-password@proxy.example.test:1080',
		'socks5://user%40department:synthetic%3Aproxy%2Fpassword%23%25@127.0.0.1:1080',
		'socks5://%E7%94%A8%E6%88%B7:synthetic%20password@[::1]:1080',
		'socks5://' + 'u' * 255 + ':' + 'p' * 255 + '@proxy.example.test:1080',
	],
)
def test_authenticated_socks5_is_valid_for_global_and_account_routes(proxy):
	config = default_config()
	config['proxy_url'] = proxy
	config['accounts'] = [{**agent_account(), 'proxy': proxy}]
	assert validate_config(config)['proxy_url'] == proxy
	assert validate_config(config)['accounts'][0]['proxy'] == proxy


@pytest.mark.parametrize(
	'userinfo',
	[
		'synthetic-user',
		':synthetic-password',
		'user:',
		':',
		'user:%ZZ',
		'%FF:synthetic-password',
		'user:synthetic%0Apassword',
		'user:synthetic%00password',
		'user:synthetic%7Fpassword',
		'u' * 256 + ':synthetic-password',
		'user:' + 'p' * 256,
		'%E7%94%A8' * 86 + ':synthetic-password',
	],
)
@pytest.mark.parametrize('target', ['global', 'account'])
def test_socks5_rejects_invalid_auth_without_reflecting_secrets(userinfo, target):
	proxy = f'socks5://{userinfo}@proxy.example.test:1080'
	config = default_config()
	if target == 'global':
		config['proxy_url'] = proxy
	else:
		config['accounts'] = [{**agent_account(), 'proxy': proxy}]
	with pytest.raises(ConfigError) as error:
		validate_config(config)
	assert userinfo not in str(error.value)
	assert 'synthetic-password' not in str(error.value)


def test_socks5_proxy_credentials_are_encrypted_and_preserved_as_secrets(tmp_path):
	path, key = tmp_path / 'proxy.sqlite3', os.urandom(32)
	proxy = 'socks5://synthetic-user:synthetic%40proxy%3Apassword@127.0.0.1:1080'
	config = default_config()
	config['proxy_url'] = proxy
	config['accounts'] = [{**agent_account(), 'proxy': proxy}]
	store = ConfigStore(path, key)
	try:
		public = store.save(config, 0)
		assert public['config']['proxy_url'] == SECRET_KEEP
		assert public['config']['accounts'][0]['proxy'] == SECRET_KEEP
		store.save(public['config'], public['revision'])
		assert store.load()[0]['proxy_url'] == proxy
		assert store.load()[0]['accounts'][0]['proxy'] == proxy
		assert 'synthetic' not in json.dumps(store.public())
	finally:
		store.close()
	assert proxy.encode() not in path.read_bytes()
	assert b'synthetic%40proxy%3Apassword' not in path.read_bytes()


@pytest.mark.parametrize(
	'value', ['https://webui.example.test/', 'http://127.0.0.1:18765', 'http://[::1]:18765', 'http://localhost:18765']
)
def test_webui_url_allows_https_and_loopback(value):
	config = {**default_config(), 'webui_url': value}
	assert validate_config(config)['webui_url'] == value.rstrip('/')


@pytest.mark.parametrize(
	'value',
	[
		'http://server.example.test',
		'https://user:secret@webui.test',
		'https://webui.test/path',
		'https://webui.test/?secret=x',
		'javascript:alert(1)',
		None,
	],
)
def test_webui_url_rejects_insecure_or_credential_urls(value):
	with pytest.raises(ConfigError):
		validate_config({**default_config(), 'webui_url': value})


def test_migration_archives_original_ciphertext_and_disables_unsupported_accounts(tmp_path):
	path, key = tmp_path / 'config.db', os.urandom(32)
	legacy = {
		'accounts': [
			{'id': 'password', 'email': 'name@example.test', 'password': 'synthetic-old-password'},
			{'id': 'cookie', 'cookies': {'session': 'synthetic-old-cookie'}, 'api_user': 7},
			{'id': 'oauth', 'provider': 'anyrouter', 'auth': {'type': 'github', 'identity': 'main'}, 'api_user': '8'},
			{
				'id': 'agent',
				'provider': 'agentrouter',
				'cookies': 'session=old',
				'api_user': '9',
				'system_access_token': 'synthetic-legacy-token',
				'username': 'legacy-agent',
				'password': 'synthetic-legacy-agent-password',
			},
			{'id': 'custom', 'provider': 'custom', 'cookies': 'session=old', 'api_user': '10'},
		],
		'identities': {'main': {'type': 'github'}},
		'providers': {},
		'proxy_url': '',
		'notifications': {'FY1PUSH_TOKEN': 'synthetic-old-notify'},
		'browser': {'engine': 'chrome'},
		'schedule': {'enabled': True, 'interval_minutes': 60},
	}
	original = legacy_database(path, key, legacy)
	store = ConfigStore(path, key)
	try:
		config, revision = store.load()
		assert revision == 5 and config['schema_version'] == 2
		assert config['schedule'] == {'enabled': False, 'interval_minutes': 60}
		by_id = {account['id']: account for account in config['accounts']}
		assert by_id['password']['username'] == 'name@example.test'
		assert by_id['password']['password'] == 'synthetic-old-password'
		assert by_id['cookie']['cookies'] == 'session=synthetic-old-cookie'
		assert by_id['password']['enabled'] and by_id['cookie']['enabled']
		assert by_id['oauth']['auth_type'] == 'cookie' and not by_id['oauth']['enabled']
		assert not by_id['oauth']['cookies']
		assert by_id['agent']['auth_type'] == 'password' and not by_id['agent']['enabled']
		assert not {'cookies', 'system_access_token', 'username', 'password'} & by_id['agent'].keys()
		assert 'custom' not in by_id
		assert store.migration_info() == {
			'from_schema': 1,
			'source_revision': 4,
			'converted_accounts': 4,
			'disabled_accounts': 2,
			'omitted_accounts': 1,
			'schedule_disabled': True,
		}
		assert 'synthetic-' not in json.dumps(store.migration_info())
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT source_revision, document FROM config_archive').fetchall() == [(4, original)]
		assert store.load() == (config, 5)
	finally:
		store.close()
	reopened = ConfigStore(path, key)
	try:
		assert reopened.load() == (config, 5)
		assert reopened.save(reopened.public()['config'], 5)['revision'] == 6
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT count(*) FROM config_archive').fetchone() == (1,)
	finally:
		reopened.close()


def test_schema2_agent_token_migration_preserves_other_configuration_history_and_ciphertext(tmp_path):
	path, key = tmp_path / 'config.db', os.urandom(32)
	document = validate_config(populated_config())
	document['schedule'] = {'enabled': True, 'interval_minutes': 60}
	document['accounts'][2] = {
		**token_account('agent'),
		'name': 'Agent account',
		'proxy': 'socks5://proxy:synthetic-agent-proxy@proxy.example.test:1080',
		'expected_username': 'agent-identity',
		'username': 'obsolete-agent-name',
		'password': 'synthetic-obsolete-password',
		'cookies': 'session=synthetic-obsolete-cookie',
		'enabled': True,
	}
	original = legacy_database(path, key, document)
	store = ConfigStore(path, key)
	prior_archive = (1, b'synthetic-prior-ciphertext', '{}')
	try:
		with sqlite3.connect(path) as db:
			db.execute('CREATE TABLE run_history (id INTEGER PRIMARY KEY, result TEXT NOT NULL)')
			db.execute('INSERT INTO run_history VALUES (1, ?)', ('synthetic-past-result',))
			db.execute('INSERT INTO config_archive VALUES (?, ?, ?)', prior_archive)
		config, revision = store.load()
		assert revision == 5 and config['schema_version'] == 2
		assert config['accounts'][:2] == document['accounts'][:2]
		assert {key: value for key, value in config.items() if key != 'accounts'} == {
			key: value for key, value in document.items() if key != 'accounts'
		}
		assert config['accounts'][2] == {
			'id': 'agent',
			'name': 'Agent account',
			'provider': 'agentrouter',
			'auth_type': 'password',
			'api_user': '8',
			'proxy': document['accounts'][2]['proxy'],
			'expected_username': 'agent-identity',
			'enabled': False,
		}
		assert store.migration_info() == {
			'from_schema': 2,
			'source_revision': 4,
			'converted_accounts': 1,
			'disabled_accounts': 1,
			'omitted_accounts': 0,
			'schedule_disabled': False,
		}
		for secret in ('synthetic-system-token', 'synthetic-obsolete-password', 'synthetic-obsolete-cookie'):
			assert secret not in json.dumps(store.public())
			assert secret.encode() not in path.read_bytes()
		assert store.load() == (config, 5)
		with pytest.raises(ConflictError):
			store.save(config, 4)
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT id, result FROM run_history').fetchall() == [(1, 'synthetic-past-result')]
			rows = db.execute(
				'SELECT source_revision, document, migration FROM config_archive ORDER BY source_revision'
			).fetchall()
			assert rows[0] == prior_archive and rows[1][:2] == (4, original)
			assert len(rows) == 2
	finally:
		store.close()
	reopened = ConfigStore(path, key)
	try:
		assert reopened.load() == (config, 5)
		account = config['accounts'][2]
		account.update(enabled=True, username='new-agent-name', password='synthetic-new-agent-password')
		account.pop('api_user')
		assert reopened.save(config, 5)['revision'] == 6
		assert reopened.load()[0]['accounts'][2]['enabled']
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT count(*) FROM config_archive').fetchone() == (2,)
	finally:
		reopened.close()


@pytest.mark.parametrize('schedule_enabled', [False, True])
def test_agent_token_migration_disables_schedule_only_when_no_enabled_accounts_remain(tmp_path, schedule_enabled):
	path, key = tmp_path / 'config.db', os.urandom(32)
	document = default_config()
	document['accounts'] = [token_account()]
	document['schedule']['enabled'] = schedule_enabled
	legacy_database(path, key, document)
	store = ConfigStore(path, key)
	try:
		config, revision = store.load()
		assert revision == 5 and config['schedule']['enabled'] is False
		assert config['accounts'][0]['auth_type'] == 'password'
		assert config['accounts'][0]['enabled'] is False
		information = store.migration_info()
		assert information is not None and information['schedule_disabled'] is schedule_enabled
	finally:
		store.close()


def test_stale_save_cannot_bypass_agent_migration_or_reintroduce_token(tmp_path):
	path, key = tmp_path / 'config.db', os.urandom(32)
	document = {**default_config(), 'accounts': [token_account()]}
	original = legacy_database(path, key, document)
	store = ConfigStore(path, key)
	try:
		with pytest.raises(ConflictError):
			store.save(document, 4)
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT revision, document FROM config').fetchone() == (4, original)
			assert db.execute('SELECT count(*) FROM config_archive').fetchone() == (0,)
		assert store.public()['revision'] == 5
		with pytest.raises(ConfigError):
			store.save(document, 5)
		assert store.load()[1] == 5
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT count(*) FROM config_archive').fetchone() == (1,)
	finally:
		store.close()


def test_migration_never_relabels_custom_origin_as_fixed_provider(tmp_path):
	path, key = tmp_path / 'config.db', os.urandom(32)
	legacy_database(
		path,
		key,
		{
			'accounts': [
				{'id': 'overridden', 'provider': 'anyrouter', 'cookies': 'session=synthetic', 'api_user': '7'}
			],
			'providers': {'anyrouter': {'domain': 'https://custom.example.test'}},
		},
	)
	store = ConfigStore(path, key)
	try:
		assert store.load()[0]['accounts'] == []
		information = store.migration_info()
		assert information is not None and information['omitted_accounts'] == 1
	finally:
		store.close()


@pytest.mark.parametrize('schema', [1, 2])
def test_failed_migration_is_atomic_and_preserves_original(tmp_path, schema):
	path, key = tmp_path / 'config.db', os.urandom(32)
	document: dict = {'accounts': [], 'notifications': {'PATH': 'synthetic-secret'}}
	if schema == 2:
		document.update(schema_version=2, accounts=[token_account()])
	original = legacy_database(path, key, document)
	store = ConfigStore(path, key)
	try:
		with pytest.raises(ConfigError):
			store.load()
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT revision, document FROM config').fetchone() == (4, original)
			assert db.execute('SELECT count(*) FROM config_archive').fetchone() == (0,)
	finally:
		store.close()


@pytest.mark.parametrize('schema', [1, 2])
def test_migration_archive_and_rewrite_share_one_transaction(tmp_path, monkeypatch, schema):
	path, key = tmp_path / 'config.db', os.urandom(32)
	document = {'accounts': []} if schema == 1 else {**default_config(), 'accounts': [token_account()]}
	original = legacy_database(path, key, document)
	store = ConfigStore(path, key)
	try:

		def fail_write(document, revision):
			raise sqlite3.OperationalError('synthetic write failure')

		monkeypatch.setattr(store, '_write', fail_write)
		with pytest.raises(sqlite3.OperationalError, match='synthetic write failure'):
			store.load()
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT revision, document FROM config').fetchone() == (4, original)
			assert db.execute('SELECT count(*) FROM config_archive').fetchone() == (0,)
	finally:
		store.close()


@pytest.mark.parametrize('schema', [1, 2])
def test_two_connections_migrate_only_once(tmp_path, schema):
	path, key = tmp_path / 'config.db', os.urandom(32)
	document = {'accounts': []} if schema == 1 else {**default_config(), 'accounts': [token_account()]}
	legacy_database(path, key, document)
	first, second = ConfigStore(path, key), ConfigStore(path, key)
	try:
		config, revision = first.load()
		assert revision == 5 and second.load() == (config, revision)
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT count(*) FROM config_archive').fetchone() == (1,)
	finally:
		first.close()
		second.close()


@pytest.mark.parametrize('schema', [1, 2])
def test_migration_does_not_overflow_revision_or_archive_without_rewrite(tmp_path, schema):
	path, key = tmp_path / 'config.db', os.urandom(32)
	document = {'accounts': []} if schema == 1 else {**default_config(), 'accounts': [token_account()]}
	revision = 2**63 - 1
	original = legacy_database(path, key, document, revision)
	store = ConfigStore(path, key)
	try:
		with pytest.raises(ConfigError):
			store.load()
		with sqlite3.connect(path) as db:
			assert db.execute('SELECT revision, document FROM config').fetchone() == (revision, original)
			assert db.execute('SELECT count(*) FROM config_archive').fetchone() == (0,)
	finally:
		store.close()


def test_failed_validation_rolls_back_and_preserves_previous_config(tmp_path):
	store = ConfigStore(tmp_path / 'config.db', os.urandom(32))
	try:
		store.save(populated_config(), 0)
		before = store.load()
		with pytest.raises(ConfigError):
			store.save({'schedule': {'enabled': True}}, 1)
		assert store.load() == before
		assert store.save(before[0], 1)['revision'] == 2
	finally:
		store.close()


@pytest.mark.parametrize('revision', [-1, True, '0', 2**63])
def test_invalid_revision_is_rejected(tmp_path, revision):
	store = ConfigStore(tmp_path / 'config.db', os.urandom(32))
	try:
		with pytest.raises(ConfigError, match='revision'):
			store.save(default_config(), revision)
	finally:
		store.close()
