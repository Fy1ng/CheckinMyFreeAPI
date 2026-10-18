import asyncio
import os

import pytest
import pytest_asyncio
from aiohttp import CookieJar, WSServerHandshakeError, web
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
async def test_manual_proxy_requires_current_run_and_keeps_gateway_token_private(web_client):
	service, client = web_client
	await login(client)
	assert (await client.get('/manual/1/')).status == 410
	service.jobs.active_id = 1
	service.jobs.manual = {'transport': 'desktop'}
	assert (await client.get('/manual/1/')).status == 410
	service.jobs.active_id = None
	service.jobs.manual = None

	async def viewer(request):
		assert request.headers['Cookie'] == 'checkin_session=synthetic-gateway-session'
		assert request.headers['Origin'].startswith('http://127.0.0.1:')
		return web.Response(text='<script src="/viewer.js"></script>', content_type='text/html')

	upstream = web.Application()
	upstream.router.add_get('/', viewer)
	async with TestServer(upstream) as gateway:
		service.jobs.active_id = 1
		service.jobs.manual = {'url': str(gateway.make_url('')).rstrip('/'), 'session': 'synthetic-gateway-session'}
		assert (await client.get('/manual/2/')).status == 410
		response = await client.get('/manual/1/')
		assert response.status == 200
		assert '/manual/1/viewer.js' in await response.text()
		assert 'synthetic-gateway-session' not in str(response.headers)
		service.jobs.stopping = True
		assert (await client.get('/manual/1/')).status == 410
		service.jobs.active_id = None


@pytest.mark.asyncio
async def test_manual_websocket_is_authenticated_and_logout_closes_it(web_client):
	service, client = web_client
	with pytest.raises(WSServerHandshakeError):
		await client.ws_connect('/manual/1/websockify', headers={'Origin': str(client.make_url('')).rstrip('/')})
	headers = await login(client)
	closed = asyncio.Event()

	async def websocket(request):
		connection = web.WebSocketResponse()
		await connection.prepare(request)
		try:
			async for message in connection:
				await connection.send_bytes(message.data)
		finally:
			closed.set()
		return connection

	upstream = web.Application()
	upstream.router.add_get('/websockify', websocket)
	async with TestServer(upstream) as gateway:
		service.jobs.active_id = 1
		service.jobs.manual = {'url': str(gateway.make_url('')).rstrip('/'), 'session': 'synthetic-session'}
		with pytest.raises(WSServerHandshakeError):
			await client.ws_connect('/manual/1/websockify', headers={'Origin': 'https://attacker.test'})
		connection = await client.ws_connect('/manual/1/websockify', headers={'Origin': headers['Origin']})
		await connection.send_bytes(b'fixture-vnc')
		assert (await connection.receive(timeout=2)).data == b'fixture-vnc'
		# Refreshing progress must not disconnect a live browser session.
		service.jobs.manual = dict(service.jobs.manual)
		await asyncio.sleep(0.6)
		await connection.send_bytes(b'still-open')
		assert (await connection.receive(timeout=2)).data == b'still-open'
		await client.post('/api/logout', json={}, headers=headers)
		await asyncio.wait_for(closed.wait(), timeout=2)
		service.jobs.active_id = None
