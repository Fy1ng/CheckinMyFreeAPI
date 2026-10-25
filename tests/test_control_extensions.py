"""Authenticated automation controls and destructive restore against disposable data."""

import os
from unittest.mock import AsyncMock

import pytest_asyncio
from aiohttp import CookieJar, FormData
from aiohttp.test_utils import TestClient, TestServer

from server.app import SERVICE, create_app
from server.config_store import default_config

PASSWORD = 'synthetic-current-admin'
RECOVERY = 'synthetic-recovery-password'


@pytest_asyncio.fixture
async def control_client(tmp_path):
	app = create_app(tmp_path, os.urandom(32), PASSWORD, scheduler=False)
	client = TestClient(TestServer(app), cookie_jar=CookieJar(unsafe=True))
	await client.start_server()
	try:
		yield app[SERVICE], client, tmp_path
	finally:
		await client.close()


async def login(client):
	origin = str(client.make_url('')).rstrip('/')
	response = await client.post('/api/login', json={'password': PASSWORD}, headers={'Origin': origin})
	assert response.status == 200
	return {'Origin': origin, 'X-CSRF-Token': (await response.json())['csrf']}


def saved_config(service):
	config = default_config()
	config['webui_url'] = 'https://current.example'
	config['backups']['password'] = RECOVERY
	config['accounts'] = [
		{
			'id': 'one',
			'name': 'Before',
			'provider': 'anyrouter',
			'auth_type': 'cookie',
			'cookies': 'session=synthetic-cookie',
			'api_user': '42',
			'enabled': True,
		}
	]
	return service.store.save(config, 0)['revision']


def upload(data, revision, password=RECOVERY):
	body = FormData()
	body.add_field('revision', str(revision))
	body.add_field('password', password)
	body.add_field('file', data, filename='restore.nab', content_type='application/octet-stream')
	return body


async def backup_and_change(service, client, headers):
	revision = saved_config(service)
	response = await client.post('/api/backups', json={'revision': revision}, headers=headers)
	assert response.status == 201
	backup_id = (await response.json())['backup']['id']
	response = await client.get('/api/backups/' + backup_id)
	assert response.status == 200 and 'attachment' in response.headers['Content-Disposition']
	data = await response.read()
	assert RECOVERY.encode() not in data and b'synthetic-cookie' not in data
	config, revision = service.store.load()
	config['accounts'][0]['name'] = 'After'
	revision = service.store.save(config, revision)['revision']
	return data, revision


async def test_new_controls_require_session_and_csrf_and_reads_do_not_send(control_client, monkeypatch):
	service, client, _ = control_client
	assert (await client.get('/backups')).status == 200
	for path in ('/api/automation', '/api/backups'):
		assert (await client.get(path)).status == 401
	headers = await login(client)
	start = AsyncMock(return_value={'id': 9, 'kind': 'summary', 'state': 'running'})
	monkeypatch.setattr(service.jobs, 'start_summary', start)
	assert (await client.get('/api/automation')).status == 200
	assert (await client.get('/api/backups')).status == 200
	start.assert_not_called()
	assert (await client.post('/api/automation/summary', json={'revision': 0})).status == 403
	assert (await client.post('/api/automation/summary', json={'revision': True}, headers=headers)).status == 400
	response = await client.post('/api/automation/summary', json={'revision': 0}, headers=headers)
	assert response.status == 202
	start.assert_awaited_once_with(0)
	assert (await client.post('/api/backups', json={'revision': 0})).status == 403
	assert (await client.post('/api/backups', json={'revision': 0}, headers=headers)).status == 409


async def test_restore_requires_preview_reauthentication_and_preserves_live_admin(control_client):
	service, client, root = control_client
	headers = await login(client)
	data, revision = await backup_and_change(service, client, headers)
	response = await client.post('/api/backups/preview', data=upload(data, revision), headers=headers)
	assert response.status == 200
	preview = await response.json()
	assert preview['accounts'] == 1
	assert service.store.load()[0]['accounts'][0]['name'] == 'After'
	body = {'revision': revision, 'ticket': preview['ticket'], 'admin_password': 'incorrect'}
	assert (await client.post('/api/backups/restore', json=body, headers=headers)).status == 400
	body['admin_password'] = PASSWORD
	response = await client.post('/api/backups/restore', json=body, headers=headers)
	assert response.status == 200
	assert (await response.json())['automatic_tasks_disabled']
	assert (await client.get('/api/config')).status == 401
	await login(client)
	config, restored_revision = service.store.load()
	assert config['accounts'][0]['name'] == 'Before' and restored_revision > revision
	assert config['webui_url'] == 'https://current.example'
	assert not config['schedule']['enabled'] and not config['monitoring']['enabled']
	assert not config['backups']['enabled']
	assert all(not settings['enabled'] for settings in config['automation'].values())
	assert len(service.backups.manager.list()) == 2
	assert not list(root.glob('.restore-rollback-*'))


async def test_reopen_failure_rolls_back_original_data_and_keeps_service_usable(control_client, monkeypatch):
	service, client, _ = control_client
	headers = await login(client)
	data, revision = await backup_and_change(service, client, headers)
	response = await client.post('/api/backups/preview', data=upload(data, revision), headers=headers)
	preview = await response.json()
	original_open = service.open_restored
	calls = 0

	async def fail_once(lease):
		nonlocal calls
		calls += 1
		if calls == 1:
			raise OSError('synthetic-open-failure')
		await original_open(lease)

	monkeypatch.setattr(service, 'open_restored', fail_once)
	response = await client.post(
		'/api/backups/restore',
		json={
			'revision': revision,
			'ticket': preview['ticket'],
			'admin_password': PASSWORD,
		},
		headers=headers,
	)
	assert response.status == 400
	assert '已恢复替换前的数据' in (await response.json())['error']
	assert (await client.get('/healthz')).status == 200
	assert service.store.load()[0]['accounts'][0]['name'] == 'After'
	assert not service.maintenance
	await login(client)
	assert (await client.get('/api/config')).status == 200


async def test_restore_upload_rejects_corrupt_files_and_stale_revisions(control_client):
	service, client, _ = control_client
	headers = await login(client)
	revision = saved_config(service)
	response = await client.post('/api/backups/preview', data=upload(b'invalid backup', revision), headers=headers)
	assert response.status == 400
	assert RECOVERY not in await response.text()
	response = await client.post('/api/backups', json={'revision': revision - 1}, headers=headers)
	assert response.status == 409
	assert (await client.get('/api/backups/../../master.key')).status in {400, 404}


async def test_recovery_password_is_encrypted_redacted_and_preserved_on_unrelated_save(control_client):
	service, client, root = control_client
	headers = await login(client)
	revision = saved_config(service)
	response = await client.get('/api/config')
	public = await response.json()
	assert public['config']['backups']['password'] == '__UNCHANGED_SECRET__'
	assert RECOVERY not in str(public)
	assert RECOVERY.encode() not in (root / 'webui.sqlite3').read_bytes()
	public['config']['http']['timeout_seconds'] = 45
	response = await client.put('/api/config', json={'revision': revision, 'config': public['config']}, headers=headers)
	assert response.status == 200
	assert service.store.load()[0]['backups']['password'] == RECOVERY
