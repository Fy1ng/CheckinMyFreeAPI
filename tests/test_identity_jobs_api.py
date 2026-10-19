"""Identity management API integration with encrypted fixtures and no real browser or network."""

import asyncio
import base64
import hmac
import json
import os
import sqlite3
from importlib.metadata import version

import pytest
import pytest_asyncio
from aiohttp import CookieJar
from aiohttp.test_utils import TestClient, TestServer
from cloakbrowser.config import get_chromium_version

import server.jobs as jobs_module
from server.app import SERVICE, create_app
from server.config_store import ConfigStore, default_config
from server.jobs import JobManager
from utils.secure_state import SnapshotStore, state_key

PASSWORD = 'synthetic-identity-api-password'
ALIAS = 'linuxdo-main'
VERIFIED_AT = '2026-10-19T00:00:00+00:00'


class FakeInput:
	def __init__(self):
		self.data = bytearray()
		self.closed = False

	def write(self, data):
		self.data.extend(data)

	async def drain(self):
		return None

	def close(self):
		self.closed = True


class FakeProcess:
	def __init__(self):
		self.stdin = FakeInput()
		self.returncode = None
		self.exited = asyncio.Event()

	async def wait(self):
		await self.exited.wait()
		return self.returncode

	def finish(self, code):
		self.returncode = code
		self.exited.set()

	def terminate(self):
		self.finish(-15)

	def kill(self):
		self.finish(-9)


@pytest.fixture
def fake_worker(monkeypatch):
	processes = []
	calls = []

	async def launch(*args, **kwargs):
		process = FakeProcess()
		processes.append(process)
		calls.append((args, kwargs))
		return process

	async def terminate(process):
		process.terminate()
		await process.wait()

	monkeypatch.setattr(jobs_module.asyncio, 'create_subprocess_exec', launch)
	monkeypatch.setattr(jobs_module, 'terminate_windows_tree', terminate)
	return processes, calls


@pytest_asyncio.fixture
async def identity_client(tmp_path, fake_worker):
	key = os.urandom(32)
	app = create_app(tmp_path, key, PASSWORD, scheduler=False)
	client = TestClient(TestServer(app), cookie_jar=CookieJar(unsafe=True))
	await client.start_server()
	try:
		yield app[SERVICE], client, key
	finally:
		await client.close()


async def login(client):
	origin = str(client.make_url('')).rstrip('/')
	response = await client.post('/api/login', json={'password': PASSWORD}, headers={'Origin': origin})
	assert response.status == 200
	return {'Origin': origin, 'X-CSRF-Token': (await response.json())['csrf']}


def save_identity(service, *, accounts=False):
	config = default_config()
	config['identities'] = {ALIAS: {'type': 'linuxdo', 'proxy': 'direct'}}
	if accounts:
		config['accounts'] = [
			{'id': 'site-main', 'email': 'synthetic@example.test', 'password': 'synthetic-site-password'}
		]
	service.store.save(config, 0)
	return config


async def worker_started(fake_worker):
	processes, _ = fake_worker
	for _ in range(20):
		if processes:
			return processes[-1]
		await asyncio.sleep(0)
	raise AssertionError('Fake worker did not start')


def write_snapshot(service, key, tmp_path, records, *, compatibility=None, secret=None):
	state_secret = (
		secret or base64.urlsafe_b64encode(hmac.digest(key, b'checkin-server-login-state-v1', 'sha256')).decode()
	)
	store = SnapshotStore(
		tmp_path / 'fixture-snapshot',
		service.jobs.data_dir / 'auth-cache' / 'auth-state.enc',
		state_secret,
		scope='checkin-server-v1',
		compatibility=compatibility or f'{os.name}:{version("cloakbrowser")}:{get_chromium_version()}',
	)
	try:
		for alias, kind, metadata in records:
			store.write_record('metadata', state_key(f'identity:{kind}:{alias}'), metadata)
		store.write_record('accounts', state_key('synthetic-site'), {'cookies': 'synthetic-private-cookie'})
		store.save()
	finally:
		store.close()


def verified_metadata(kind='linuxdo'):
	return {
		'fingerprint': 'synthetic-private-fingerprint',
		'identity_login': {
			'type': kind,
			'user_id': '42',
			'username': 'synthetic-user',
			'verified_at': VERIFIED_AT,
		},
	}


@pytest.mark.asyncio
async def test_identity_endpoints_require_session_origin_and_csrf(identity_client):
	service, client, _ = identity_client
	save_identity(service)
	origin = str(client.make_url('')).rstrip('/')
	assert (await client.get('/api/identities')).status == 401
	assert (
		await client.post('/api/identities/login', json={'identity': ALIAS, 'revision': 1}, headers={'Origin': origin})
	).status == 401
	headers = await login(client)
	for rejected_headers in ({}, {'Origin': origin}, {**headers, 'Origin': 'https://attacker.test'}):
		response = await client.post(
			'/api/identities/login', json={'identity': ALIAS, 'revision': 1}, headers=rejected_headers
		)
		assert response.status == 403
	assert service.jobs.history() == []
	response = await client.get('/api/identities')
	assert response.status == 200
	assert response.headers['Cache-Control'] == 'no-store'
	await client.post('/api/logout', json={}, headers=headers)
	assert (await client.get('/api/identities')).status == 401


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'payload',
	[
		[],
		{},
		{'identity': ALIAS},
		{'identity': ALIAS, 'revision': True},
		{'identity': ALIAS, 'revision': '1'},
		{'identity': None, 'revision': 1},
		{'identity': [], 'revision': 1},
		{'identity': '', 'revision': 1},
	],
)
async def test_identity_start_rejects_invalid_request(identity_client, payload):
	service, client, _ = identity_client
	save_identity(service)
	headers = await login(client)
	response = await client.post('/api/identities/login', json=payload, headers=headers)
	assert response.status == 400
	assert service.jobs.history() == []


@pytest.mark.asyncio
async def test_identity_login_uses_saved_revision_without_accounts_and_private_payload(identity_client, fake_worker):
	service, client, key = identity_client
	save_identity(service)
	headers = await login(client)
	for alias, revision in ((ALIAS, 0), ('unsaved-identity', 1)):
		response = await client.post(
			'/api/identities/login', json={'identity': alias, 'revision': revision}, headers=headers
		)
		assert response.status in {400, 409}
	assert service.jobs.history() == []
	response = await client.post('/api/identities/login', json={'identity': ALIAS, 'revision': 1}, headers=headers)
	assert response.status == 202
	run = (await response.json())['run']
	assert run['kind'] == 'identity_login'
	assert run['identity'] == ALIAS
	assert run['revision'] == 1
	process = await worker_started(fake_worker)
	payload = json.loads(bytes(process.stdin.data))
	assert payload['kind'] == 'identity_login'
	assert payload['identity'] == ALIAS
	assert payload['config']['accounts'] == []
	assert payload['config']['identities'][ALIAS]['type'] == 'linuxdo'
	assert process.stdin.closed
	args, options = fake_worker[1][0]
	assert args[1:] == ('-m', 'server.worker')
	assert options['stdin'] is asyncio.subprocess.PIPE
	assert payload['manual_session'] not in json.dumps(args)
	assert base64.b64encode(key).decode() not in json.dumps(args)
	assert service.store.load()[1] == 1
	assert len(service.jobs.history()) == 1
	assert (await client.post('/api/runs/stop', json={}, headers=headers)).status == 200
	assert service.jobs.task is not None
	await service.jobs.task
	assert service.jobs.history()[0]['state'] == 'cancelled'
	assert service.store.load()[1] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('first_kind', ['identity_login', 'checkin'])
async def test_identity_and_checkin_share_one_active_job(identity_client, fake_worker, first_kind):
	service, client, _ = identity_client
	save_identity(service, accounts=True)
	headers = await login(client)
	identity_request = ('/api/identities/login', {'identity': ALIAS, 'revision': 1})
	checkin_request = ('/api/runs', {'revision': 1})
	first, second = (
		(identity_request, checkin_request)
		if first_kind == 'identity_login'
		else (
			checkin_request,
			identity_request,
		)
	)
	assert (await client.post(first[0], json=first[1], headers=headers)).status == 202
	await worker_started(fake_worker)
	assert (await client.post(second[0], json=second[1], headers=headers)).status == 409
	assert (await client.post(first[0], json=first[1], headers=headers)).status == 409
	assert len(service.jobs.history()) == 1
	assert service.jobs.history()[0]['kind'] == first_kind
	response = await client.post('/api/runs/stop', json={}, headers=headers)
	assert (await response.json())['stopping'] is True
	assert service.jobs.task is not None
	await service.jobs.task
	assert service.jobs.status()['running'] is False
	assert service.jobs.history()[0]['state'] == 'cancelled'


@pytest.mark.asyncio
async def test_identity_status_reads_only_safe_metadata_without_mutating_cache_or_live_profile(
	identity_client, tmp_path, monkeypatch
):
	service, client, key = identity_client
	config = save_identity(service)
	config['identities']['legacy'] = {'type': 'github', 'proxy': 'direct'}
	service.store.save(config, 1)
	write_snapshot(
		service,
		key,
		tmp_path,
		[(ALIAS, 'linuxdo', verified_metadata()), ('legacy', 'github', {'fingerprint': 'synthetic-private-old'})],
	)
	live = tmp_path / 'live-root' / 'live' / 'browser-profile'
	live.mkdir(parents=True)
	profile_marker = live / 'Cookies'
	profile_marker.write_bytes(b'synthetic-private-live-cookie')
	monkeypatch.setenv('CHECKIN_AUTH_ROOT', str(tmp_path / 'live-root'))
	cache = service.jobs.data_dir / 'auth-cache'
	before = {path.name: path.read_bytes() for path in cache.iterdir() if path.is_file()}
	before_revision = service.store.load()[1]
	await login(client)
	for _ in range(2):
		response = await client.get('/api/identities')
		assert response.status == 200
		payload = await response.json()
		assert payload['identities'][ALIAS] == {
			'state': 'verified',
			'username': 'synthetic-user',
			'user_id': '42',
			'verified_at': VERIFIED_AT,
		}
		assert payload['identities']['legacy']['state'] == 'unverified'
		serialized = json.dumps(payload)
		for secret in ('synthetic-private', 'fingerprint', 'cookies', base64.b64encode(key).decode()):
			assert secret not in serialized
	assert profile_marker.read_bytes() == b'synthetic-private-live-cookie'
	assert {path.name: path.read_bytes() for path in cache.iterdir() if path.is_file()} == before
	assert service.store.load()[1] == before_revision
	assert service.jobs.history() == []


@pytest.mark.asyncio
async def test_identity_status_does_not_carry_state_across_changed_type_or_removed_alias(identity_client, tmp_path):
	service, client, key = identity_client
	config = save_identity(service)
	write_snapshot(service, key, tmp_path, [(ALIAS, 'linuxdo', verified_metadata())])
	await login(client)
	config['identities'][ALIAS]['type'] = 'github'
	service.store.save(config, 1)
	response = await client.get('/api/identities')
	assert response.status == 200
	assert (await response.json())['identities'][ALIAS]['state'] == 'unverified'
	config['identities'] = {}
	service.store.save(config, 2)
	response = await client.get('/api/identities')
	assert (await response.json())['identities'] == {}


@pytest.mark.asyncio
async def test_reading_status_during_identity_login_preserves_previous_verified_metadata(
	identity_client, tmp_path, fake_worker
):
	service, client, key = identity_client
	save_identity(service)
	write_snapshot(service, key, tmp_path, [(ALIAS, 'linuxdo', verified_metadata())])
	cache = service.jobs.data_dir / 'auth-cache'
	before = {path.name: path.read_bytes() for path in cache.iterdir() if path.is_file()}
	headers = await login(client)
	assert (
		await client.post('/api/identities/login', json={'identity': ALIAS, 'revision': 1}, headers=headers)
	).status == 202
	await worker_started(fake_worker)
	response = await client.get('/api/identities')
	assert response.status == 200
	identity = (await response.json())['identities'][ALIAS]
	assert identity['state'] == 'verified'
	assert identity['user_id'] == '42'
	assert identity['verified_at'] == VERIFIED_AT
	assert service.jobs.status()['running'] is True
	assert {path.name: path.read_bytes() for path in cache.iterdir() if path.is_file()} == before
	assert service.store.load()[1] == 1
	assert (await client.post('/api/runs/stop', json={}, headers=headers)).status == 200
	assert service.jobs.task is not None
	await service.jobs.task


@pytest.mark.asyncio
@pytest.mark.parametrize('invalid_snapshot', ['key', 'compatibility'])
async def test_invalid_encrypted_identity_state_is_never_reported_verified(identity_client, tmp_path, invalid_snapshot):
	service, client, key = identity_client
	save_identity(service)
	options = (
		{'secret': base64.urlsafe_b64encode(os.urandom(32)).decode()}
		if invalid_snapshot == 'key'
		else {'compatibility': 'different-platform-browser'}
	)
	write_snapshot(service, key, tmp_path, [(ALIAS, 'linuxdo', verified_metadata())], **options)
	await login(client)
	response = await client.get('/api/identities')
	assert response.status in {200, 400, 503}
	payload = await response.json()
	if response.status == 200:
		assert payload['identities'][ALIAS]['state'] != 'verified'
	assert 'synthetic-user' not in json.dumps(payload)
	assert 'synthetic-private' not in json.dumps(payload)
	assert service.jobs.history() == []


@pytest.mark.asyncio
async def test_existing_run_schema_migrates_to_checkin_without_losing_history(tmp_path):
	key = os.urandom(32)
	database = tmp_path / 'webui.sqlite3'
	with sqlite3.connect(database) as connection:
		connection.execute(
			'CREATE TABLE runs (id INTEGER PRIMARY KEY, state TEXT NOT NULL, started_at REAL NOT NULL, '
			'finished_at REAL, error TEXT, summary TEXT, revision INTEGER NOT NULL)'
		)
		connection.execute("INSERT INTO runs VALUES (1,'succeeded',1,2,NULL,?,7)", ('{"success_count":1}',))
	store = ConfigStore(database, key)
	manager = JobManager(store, tmp_path, key)
	try:
		run = manager.history()[0]
		assert run['id'] == 1
		assert run['state'] == 'succeeded'
		assert run['kind'] == 'checkin'
		assert run['identity'] is None
		assert run['summary'] == {'success_count': 1}
		assert run['revision'] == 7
	finally:
		await manager.close()
		store.close()
