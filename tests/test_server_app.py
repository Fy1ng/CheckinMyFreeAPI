import os
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from aiohttp import CookieJar
from aiohttp.test_utils import TestClient, TestServer

from server.app import SERVICE, create_app
from server.config_store import default_config

PASSWORD = 'synthetic-webui-password'


@pytest_asyncio.fixture
async def web_client(tmp_path):
	app = create_app(tmp_path, os.urandom(32), PASSWORD, scheduler=False)
	client = TestClient(TestServer(app), cookie_jar=CookieJar(unsafe=True))
	await client.start_server()
	try:
		yield app[SERVICE], client
	finally:
		await client.close()


async def login(client):
	origin = str(client.make_url('')).rstrip('/')
	response = await client.post('/api/login', json={'password': PASSWORD}, headers={'Origin': origin})
	assert response.status == 200
	payload = await response.json()
	return {'Origin': origin, 'X-CSRF-Token': payload['csrf']}


@pytest.mark.asyncio
async def test_configuration_requires_session_origin_and_csrf(web_client):
	service, client = web_client
	assert (await client.get('/api/config')).status == 401
	assert (await client.get('/api/runs')).status == 401
	assert (await client.get('/api/status')).status == 401
	assert (await client.get('/manual/1/')).status == 401
	assert (await client.get('/api/session')).status == 200
	headers = await login(client)
	assert (await client.put('/api/config', json={})).status == 403
	assert (await client.put('/api/config', json={}, headers={'Origin': 'https://attacker.test'})).status == 403
	assert (await client.get('/api/config', headers={'Host': 'attacker.test'})).status == 403
	response = await client.get('/api/config')
	assert response.headers['Cache-Control'] == 'no-store'
	assert (await response.json())['revision'] == 0
	response = await client.put('/api/config', json={'revision': 0, 'config': default_config()}, headers=headers)
	assert response.status == 200
	assert (
		await client.put('/api/config', json={'revision': 0, 'config': default_config()}, headers=headers)
	).status == 409
	assert (await client.post('/api/runs', json={'revision': 1}, headers=headers)).status == 409
	await client.post('/api/logout', json={}, headers=headers)
	assert (await client.get('/api/config')).status == 401
	assert not service.sessions


@pytest.mark.asyncio
async def test_login_cookie_and_limits(web_client):
	service, client = web_client
	origin = str(client.make_url('')).rstrip('/')
	assert (await client.post('/api/login', json=[], headers={'Origin': origin})).status == 400
	service.attempts.clear()
	for _ in range(5):
		assert (await client.post('/api/login', json={'password': 'wrong'}, headers={'Origin': origin})).status == 401
	assert (await client.post('/api/login', json={'password': PASSWORD}, headers={'Origin': origin})).status == 429
	service.attempts.clear()
	response = await client.post('/api/login', json={'password': PASSWORD}, headers={'Origin': origin})
	assert 'HttpOnly' in response.headers['Set-Cookie']
	assert 'SameSite=Strict' in response.headers['Set-Cookie']
	assert PASSWORD not in await response.text()
	assert PASSWORD.encode() not in (service.jobs.data_dir / 'webui.sqlite3').read_bytes()


@pytest.mark.asyncio
async def test_start_run_single_account_contract_requires_valid_scope_and_csrf(web_client, monkeypatch):
	service, client = web_client
	headers = await login(client)
	start = AsyncMock(return_value={'id': 7, 'state': 'running'})
	monkeypatch.setattr(service.jobs, 'start', start)
	assert (await client.post('/api/runs', json={'revision': 1, 'account_id': 'first'})).status == 403
	invalid_scopes: tuple[object, ...] = (None, '', 1, True, [], {}, 'x' * 129)
	for account_id in invalid_scopes:
		assert (
			await client.post('/api/runs', json={'revision': 1, 'account_id': account_id}, headers=headers)
		).status == 400
	assert (
		await client.post('/api/runs', json={'revision': 1, 'account_ids': ['first']}, headers=headers)
	).status == 400
	start.assert_not_called()
	response = await client.post('/api/runs', json={'revision': 1, 'account_id': 'first'}, headers=headers)
	assert response.status == 202
	start.assert_awaited_once_with(1, account_id='first')
	assert (await client.post('/api/runs', json={'revision': 1}, headers=headers)).status == 202
	start.assert_awaited_with(1, account_id=None)


@pytest.mark.asyncio
async def test_removed_browser_identity_and_custom_provider_routes_are_unavailable(web_client):
	_, client = web_client
	headers = await login(client)
	assert (await client.get('/api/identities')).status == 404
	assert (await client.post('/api/identities/login', json={}, headers=headers)).status == 404
	assert (await client.get('/manual/1/')).status == 404


@pytest.mark.asyncio
async def test_pause_resolution_requires_auth_csrf_revision_and_saved_account(web_client):
	service, client = web_client
	headers = await login(client)
	config = default_config()
	config['accounts'] = [
		{
			'id': 'fixture',
			'provider': 'agentrouter',
			'auth_type': 'system_token',
			'system_access_token': 'synthetic-token',
			'api_user': '42',
		}
	]
	service.store.save(config, 0)
	assert (await client.post('/api/accounts/resolve', json={'revision': 1, 'account_id': 'fixture'})).status == 403
	assert (
		await client.post('/api/accounts/resolve', json={'revision': 0, 'account_id': 'fixture'}, headers=headers)
	).status == 409
	assert (
		await client.post('/api/accounts/resolve', json={'revision': 1, 'account_id': 'fixture'}, headers=headers)
	).status == 200


def test_busy_instance_cannot_migrate_legacy_database(tmp_path):
	import json
	import sqlite3

	from cryptography.hazmat.primitives.ciphers.aead import AESGCM

	from server.jobs import BusyError, acquire_file_lock

	key, nonce = os.urandom(32), os.urandom(12)
	document = nonce + AESGCM(key).encrypt(
		nonce, json.dumps({'accounts': []}).encode(), b'anyrouter.server.configuration.v1:1'
	)
	db = sqlite3.connect(tmp_path / 'webui.sqlite3')
	db.execute('CREATE TABLE config (id INTEGER PRIMARY KEY,revision INTEGER NOT NULL,document BLOB NOT NULL)')
	db.execute('INSERT INTO config VALUES (1,1,?)', (document,))
	db.commit()
	lease = acquire_file_lock(tmp_path / 'service.lock')
	try:
		with pytest.raises(BusyError):
			create_app(tmp_path, key, PASSWORD, scheduler=False)
		assert db.execute('SELECT revision,document FROM config').fetchone() == (1, document)
		assert not db.execute("SELECT name FROM sqlite_master WHERE name='config_archive'").fetchall()
	finally:
		lease.close()
		db.close()
