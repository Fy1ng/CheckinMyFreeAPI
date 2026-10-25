import asyncio
import os
import threading
import time
from unittest.mock import Mock

import pytest
import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer

from server.app import SERVICE, create_app
from server.web_access import WebAccess

PASSWORD = 'synthetic-public-web-password'
PUBLIC = 'https://free.example.test'


@pytest_asyncio.fixture
async def public_client(tmp_path):
	app = create_app(
		tmp_path, os.urandom(32), PASSWORD, scheduler=False, public_origin=PUBLIC, trusted_proxy_ips=('127.0.0.1',)
	)
	client = TestClient(TestServer(app))
	await client.start_server()
	try:
		yield app[SERVICE], client
	finally:
		await client.close()


def public_headers(**extra):
	return {
		'Host': 'free.example.test',
		'Origin': PUBLIC,
		'X-Forwarded-Proto': 'https',
		'X-Forwarded-For': '203.0.113.7',
		**extra,
	}


@pytest.mark.parametrize(
	'origin',
	[
		'http://free.example.test',
		'https://free.example.test/',
		'https://free.example.test/path',
		'https://user:pass@free.example.test',
		'https://free.example.test?token=hidden',
		'https://free.example.test#token',
		'https://free.example.test:',
		'https://free.example.test:70000',
		'https://free.example.test\\@attacker.test',
		'https://localhost',
		'https://free.example.test\n',
	],
)
def test_public_configuration_rejects_ambiguous_or_non_https_origins(tmp_path, origin):
	with pytest.raises(ValueError, match='CHECKIN_WEB_PUBLIC_URL'):
		create_app(tmp_path / 'must-not-create', os.urandom(32), PASSWORD, scheduler=False, public_origin=origin)
	assert not (tmp_path / 'must-not-create').exists()


@pytest.mark.parametrize('peers', [('0.0.0.0/0',), ('localhost',), ('127.0.0.1:80',), ('',), ('127.0.0.1',) * 33])
def test_trusted_proxies_require_bounded_explicit_ip_addresses(peers):
	with pytest.raises(ValueError, match='CHECKIN_WEB_TRUSTED_PROXY_IPS'):
		WebAccess(PUBLIC, peers)


def test_forwarded_client_ip_uses_only_explicit_proxy_and_single_valid_address():
	access = WebAccess(PUBLIC, ('127.0.0.1',))
	request = Mock(remote='127.0.0.1', headers={'X-Forwarded-For': '203.0.113.7'})
	assert access.client_ip(request) == '203.0.113.7'
	request.headers['X-Forwarded-For'] = '203.0.113.7, 203.0.113.8'
	assert access.client_ip(request) == '127.0.0.1'
	request.remote = '192.0.2.1'
	request.headers['X-Forwarded-For'] = '203.0.113.7'
	assert access.client_ip(request) == '192.0.2.1'
	assert WebAccess(PUBLIC, ('::ffff:127.0.0.1',)).trusted_peer(Mock(remote='127.0.0.1'))


@pytest.mark.asyncio
async def test_public_cookie_csrf_host_and_logout_contract(public_client):
	service, client = public_client
	assert (await client.get('/api/config', headers=public_headers())).status == 401
	response = await client.post('/api/login', json={'password': PASSWORD}, headers=public_headers())
	assert response.status == 200
	assert response.headers['Cache-Control'] == 'no-store'
	assert response.headers['Strict-Transport-Security'] == 'max-age=31536000'
	cookie = response.cookies['checkin_web_session']
	assert cookie['secure'] and cookie['httponly'] and cookie['samesite'] == 'Strict'
	csrf = (await response.json())['csrf']
	headers = public_headers(Cookie=f'checkin_web_session={cookie.value}')
	assert (await client.get('/api/config', headers=headers)).status == 200
	assert (await client.post('/api/logout', json={}, headers=headers)).status == 403
	assert (
		await client.post(
			'/api/logout', json={}, headers={**headers, 'X-CSRF-Token': csrf, 'Origin': 'http://free.example.test'}
		)
	).status == 403
	assert (await client.get('/api/config', headers={**headers, 'Host': 'attacker.test'})).status == 403
	assert (
		await client.get(
			'/api/config', headers={**headers, 'Host': 'attacker.test', 'X-Forwarded-Host': 'free.example.test'}
		)
	).status == 403
	assert (await client.get('/api/config', headers={'Cookie': headers['Cookie']})).status == 401
	assert cookie.value in service.sessions
	response = await client.post('/api/logout', json={}, headers={**headers, 'X-CSRF-Token': csrf})
	assert response.status == 200
	deleted = response.cookies['checkin_web_session']
	assert deleted['secure'] and deleted['httponly'] and deleted['samesite'] == 'Strict' and deleted['max-age'] == '0'
	assert (await client.get('/api/config', headers=headers)).status == 401


@pytest.mark.asyncio
async def test_public_requires_trusted_https_ingress_and_retains_local_health(public_client):
	service, client = public_client
	for protocol in ('http', 'https,http', ''):
		assert (await client.get('/', headers=public_headers(**{'X-Forwarded-Proto': protocol}))).status == 403
	service.access = WebAccess(PUBLIC)
	assert (await client.get('/', headers=public_headers())).status == 403
	assert (await client.get('/healthz')).status == 200
	origin = str(client.make_url('')).rstrip('/')
	response = await client.post('/api/login', json={'password': PASSWORD}, headers={'Origin': origin})
	assert response.status == 200
	assert not response.cookies['checkin_web_session']['secure']
	assert 'Strict-Transport-Security' not in response.headers


@pytest.mark.asyncio
async def test_public_access_disabled_by_default_and_proxy_headers_cannot_enable_it(tmp_path):
	app = create_app(tmp_path, os.urandom(32), PASSWORD, scheduler=False)
	async with TestClient(TestServer(app)) as client:
		assert (await client.get('/', headers=public_headers())).status == 403
		assert (await client.get('/healthz', headers={'Forwarded': 'host=free.example.test;proto=https'})).status == 200


@pytest.mark.asyncio
async def test_login_limits_per_client_and_globally_without_trusting_spoofed_ip(public_client):
	service, client = public_client
	for _ in range(5):
		assert (await client.post('/api/login', json={'password': 'wrong'}, headers=public_headers())).status == 401
	response = await client.post('/api/login', json={'password': PASSWORD}, headers=public_headers())
	assert response.status == 429 and response.headers['Retry-After'] == '60'
	assert (
		await client.post(
			'/api/login', json={'password': 'wrong'}, headers=public_headers(**{'X-Forwarded-For': '203.0.113.8'})
		)
	).status == 401
	service.access = WebAccess(PUBLIC)
	origin = str(client.make_url('')).rstrip('/')
	for count in range(5):
		assert (
			await client.post(
				'/api/login',
				json={'password': 'wrong'},
				headers={'Origin': origin, 'X-Forwarded-For': f'192.0.2.{count}'},
			)
		).status == 401
	assert (
		await client.post(
			'/api/login', json={'password': PASSWORD}, headers={'Origin': origin, 'X-Forwarded-For': '192.0.2.42'}
		)
	).status == 429
	service.attempts = [time.monotonic()] * 30
	service.client_attempts.clear()
	assert (await client.post('/api/login', json={'password': PASSWORD}, headers={'Origin': origin})).status == 429


@pytest.mark.asyncio
async def test_simultaneous_logins_run_at_most_one_password_hash(public_client, monkeypatch):
	service, client = public_client
	entered, release = threading.Event(), threading.Event()
	checks = []

	def password_hash(*args, **kwargs):
		checks.append(1)
		entered.set()
		assert release.wait(5)
		return service.digest

	monkeypatch.setattr('server.app.hashlib.scrypt', password_hash)
	first = asyncio.create_task(client.post('/api/login', json={'password': PASSWORD}, headers=public_headers()))
	try:
		assert await asyncio.to_thread(entered.wait, 3)
		assert (await client.post('/api/login', json={'password': PASSWORD}, headers=public_headers())).status == 429
		assert len(checks) == 1
	finally:
		release.set()
		response = await first
	assert response.status == 200
