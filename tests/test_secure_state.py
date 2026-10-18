import base64
import io
import json
import os
import zipfile
from pathlib import Path

import pytest

from utils.secure_state import MAGIC, SnapshotStore, StateError, remove_owned_tree, state_key


@pytest.fixture
def state_secret():
	return base64.urlsafe_b64encode(os.urandom(32)).decode()


def store_at(tmp_path, state_secret, *, suffix='first', scope='owner/repo', compatibility='test-browser-1'):
	return SnapshotStore(
		tmp_path / suffix, tmp_path / 'cache' / 'auth-state.enc', state_secret, scope=scope, compatibility=compatibility
	)


def commit_demo(store, content='synthetic-session-material'):
	profile_key = state_key('linuxdo-main')
	profile = store.prepare_profile(profile_key)
	(profile / 'Cookies').write_text(content)
	(profile / 'Cache').mkdir(exist_ok=True)
	(profile / 'Cache' / 'entry').write_text('do not persist')
	(profile / 'History').write_text('old callback URL')
	store.commit_profile(profile_key, profile)
	store.write_record('accounts', state_key('account-one'), {'api_user': '7', 'cookies': content})
	assert store.save() is True
	return profile_key


def test_encrypted_round_trip_on_fresh_runtime(tmp_path, state_secret):
	first = store_at(tmp_path, state_secret)
	assert first.restore() == 'missing'
	profile_key = commit_demo(first)
	ciphertext = first.cache_file.read_bytes()
	assert b'synthetic-session-material' not in ciphertext
	assert b'Cookies' not in ciphertext
	assert first.save() is False
	first.close()
	assert not first.saved.exists()
	second = store_at(tmp_path, state_secret, suffix='second')
	assert second.restore() == 'restored'
	profile = second.prepare_profile(profile_key)
	assert (profile / 'Cookies').read_text() == 'synthetic-session-material'
	assert not (profile / 'Cache').exists()
	assert not (profile / 'History').exists()
	assert second.read_record('accounts', state_key('account-one'))['api_user'] == '7'


@pytest.mark.parametrize('change', ['key', 'scope', 'compatibility', 'tamper'])
def test_rejects_unauthenticated_or_incompatible_snapshots(tmp_path, state_secret, change):
	first = store_at(tmp_path, state_secret)
	commit_demo(first)
	first.close()
	secret = base64.urlsafe_b64encode(os.urandom(32)).decode() if change == 'key' else state_secret
	if change == 'tamper':
		content = bytearray(first.cache_file.read_bytes())
		content[-1] ^= 1
		first.cache_file.write_bytes(content)
	second = store_at(
		tmp_path,
		secret,
		suffix='second',
		scope='other/repo' if change == 'scope' else 'owner/repo',
		compatibility='other' if change == 'compatibility' else 'test-browser-1',
	)
	before = second.cache_file.read_bytes()
	with pytest.raises(StateError, match='No valid'):
		second.restore()
	assert second.cache_file.read_bytes() == before
	assert not list(second.saved.iterdir())


def test_falls_back_to_previous_authenticated_snapshot(tmp_path, state_secret):
	first = store_at(tmp_path, state_secret)
	profile_key = commit_demo(first, 'first-valid-state')
	commit_demo(first, 'second-valid-state')
	first.cache_file.write_bytes(b'corrupted')
	first.close()
	second = store_at(tmp_path, state_secret, suffix='second')
	assert second.restore() == 'previous'
	assert (second.prepare_profile(profile_key) / 'Cookies').read_text() == 'first-valid-state'


def test_failed_live_profile_does_not_replace_last_known_good(tmp_path, state_secret):
	store = store_at(tmp_path, state_secret)
	profile_key = commit_demo(store, 'valid-state')
	previous = store.cache_file.read_bytes()
	live = store.prepare_profile(profile_key)
	(live / 'Cookies').write_text('failed-login-state')
	assert not store.save()
	assert store.cache_file.read_bytes() == previous
	assert (store.saved / 'profiles' / profile_key / 'Cookies').read_text() == 'valid-state'


@pytest.mark.parametrize(
	'name',
	['../../outside', '/absolute', 'profiles/../../outside', 'profiles\\..\\outside', 'C:/outside', 'unknown/file'],
)
def test_rejects_unsafe_archive_entries_even_if_authenticated(tmp_path, state_secret, name):
	store = store_at(tmp_path, state_secret)
	archive_bytes = io.BytesIO()
	with zipfile.ZipFile(archive_bytes, 'w') as archive:
		archive.writestr('manifest.json', json.dumps({'schema': 1, 'compatibility': 'test-browser-1'}))
		archive.writestr(name, 'injected')
	nonce = os.urandom(12)
	store.cache_file.parent.mkdir(exist_ok=True)
	store.cache_file.write_bytes(MAGIC + nonce + store._cipher.encrypt(nonce, archive_bytes.getvalue(), store.aad))
	with pytest.raises(StateError):
		store.restore()
	assert not (tmp_path / 'outside').exists()


def test_refuses_unsafe_profile_identifiers_and_cleanup(tmp_path, state_secret):
	store = store_at(tmp_path, state_secret)
	for invalid in ['..', '/tmp', 'a' * 63, 'G' * 64]:
		with pytest.raises(StateError):
			store.prepare_profile(invalid)
	with pytest.raises(StateError):
		remove_owned_tree(tmp_path, store.root)
	with pytest.raises(StateError):
		remove_owned_tree(store.root, store.root)


def test_profile_outside_owned_runtime_cannot_be_committed(tmp_path, state_secret):
	store = store_at(tmp_path, state_secret)
	with pytest.raises(StateError):
		store.commit_profile(state_key('identity'), Path(tmp_path))


@pytest.mark.parametrize('key', ['', 'short', 'not-base64!!!', '非ASCII', base64.urlsafe_b64encode(b'short').decode()])
def test_invalid_keys_fail_without_echoing_key(tmp_path, key):
	with pytest.raises(StateError) as error:
		store_at(tmp_path, key)
	if key:
		assert key not in str(error.value)
