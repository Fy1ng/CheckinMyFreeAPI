"""Selected browser storage, status, and alias binding stay isolated and consistent."""

import base64
import hmac
import os

import pytest

import server.identity_state as state_module
import utils.browser_backend as backend
import utils.identity_login as identity_module
from server.config_store import default_config
from server.identity_state import IdentityStateReader
from utils.auth_runtime import AuthenticationRuntime
from utils.config import AppConfig
from utils.identity_login import IdentityLoginRuntime
from utils.oauth import AuthError
from utils.secure_state import SnapshotStore, state_key


def seed_snapshot(root, cache, secret, engine, user_id):
	root, cache = backend.browser_storage_paths(root, cache, engine)
	store = SnapshotStore(root, cache, secret, scope='checkin-server-v1', compatibility='test-' + engine)
	try:
		store.write_record(
			'metadata',
			state_key('identity:linuxdo:main'),
			{
				'identity_login': {
					'type': 'linuxdo',
					'user_id': user_id,
					'username': 'fixture-' + engine,
					'verified_at': '2026-10-19T10:00:00+00:00',
				},
			},
		)
		store.save()
	finally:
		store.close()
	return cache


def fake_compatibility(monkeypatch):
	for module in (backend, state_module, identity_module):
		monkeypatch.setattr(module, 'browser_compatibility', lambda engine: 'test-' + engine)


@pytest.mark.parametrize('conflicting_subject', [False, True])
def test_reader_uses_selected_engine_and_keeps_shared_subject_binding(tmp_path, monkeypatch, conflicting_subject):
	fake_compatibility(monkeypatch)
	key = os.urandom(32)
	secret = base64.urlsafe_b64encode(hmac.digest(key, b'checkin-server-login-state-v1', 'sha256')).decode()
	cache = tmp_path / 'auth-cache' / 'auth-state.enc'
	legacy = seed_snapshot(tmp_path / 'fixture', cache, secret, 'cloakbrowser', '42')
	chrome = seed_snapshot(tmp_path / 'fixture', cache, secret, 'chrome', '7' if conflicting_subject else '42')
	before = {file: file.read_bytes() for file in (legacy, chrome, legacy.parent / 'ready', chrome.parent / 'ready')}
	config = default_config()
	config['identities'] = {'main': {'type': 'linuxdo'}}
	reader = IdentityStateReader(tmp_path, key)
	assert reader.read(config)['main']['username'] == 'fixture-cloakbrowser'
	config['browser']['engine'] = 'chrome'
	assert reader.read(config)['main']['username'] == 'fixture-chrome'
	if conflicting_subject:
		with pytest.raises(AuthError, match='IDENTITY_ACCOUNT_MISMATCH'):
			reader.bound_subjects(config)
	else:
		assert reader.bound_subjects(config) == {'main': '42'}
	assert all(file.read_bytes() == content for file, content in before.items())


@pytest.mark.parametrize('engine', ['cloakbrowser', 'chrome'])
def test_both_runtimes_restore_same_selected_snapshot(tmp_path, monkeypatch, engine):
	fake_compatibility(monkeypatch)
	secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
	cache = tmp_path / 'auth-cache' / 'auth-state.enc'
	root = tmp_path / 'state'
	for selected in ('cloakbrowser', 'chrome'):
		seed_snapshot(root, cache, secret, selected, '42')
	monkeypatch.setenv('CHECKIN_BROWSER_ENGINE', engine)
	monkeypatch.setenv('CHECKIN_AUTH_ROOT', str(root))
	monkeypatch.setenv('CHECKIN_AUTH_CACHE_FILE', str(cache))
	monkeypatch.setenv('CHECKIN_STATE_SCOPE', 'checkin-server-v1')
	monkeypatch.setenv('CHECKIN_STATE_KEY', secret)
	config = AppConfig(providers={}, identities={})
	expected_root, expected_cache = backend.browser_storage_paths(root, cache, engine)
	for factory in (
		lambda: IdentityLoginRuntime.from_environment(config),
		lambda: AuthenticationRuntime.from_environment([], config),
	):
		runtime = factory()
		try:
			assert runtime.store.root == expected_root.resolve()
			assert runtime.store.cache_file == expected_cache.resolve()
			metadata = runtime.store.read_record('metadata', state_key('identity:linuxdo:main'))
			assert metadata['identity_login']['username'] == 'fixture-' + engine
		finally:
			runtime.close()
