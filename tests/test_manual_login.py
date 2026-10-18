import asyncio
import json
import os
import platform
import subprocess
import sys
import time

import pytest
import pytest_asyncio
from aiohttp import CookieJar, WSServerHandshakeError
from aiohttp.test_utils import TestClient, TestServer

from utils.manual_login import (
	DesktopGateway,
	ManualGateway,
	ManualLoginError,
	ManualTakeover,
	child_environment,
	desktop_manual_available,
)

REMOTE_PASSWORD = 'synthetic-remote-password-for-tests'


@pytest_asyncio.fixture
async def gateway_client(tmp_path):
	assets = tmp_path / 'novnc'
	(assets / 'core').mkdir(parents=True)
	(assets / 'core' / 'rfb.js').write_text('export default class RFB {}')
	gateway = ManualGateway(REMOTE_PASSWORD, assets, 5900, 60, secure_cookie=False)
	client = TestClient(TestServer(gateway.app), cookie_jar=CookieJar(unsafe=True))
	await client.start_server()
	gateway.origin = str(client.make_url('')).rstrip('/')
	try:
		yield gateway, client
	finally:
		await gateway.revoke()
		await client.close()


async def sign_in(gateway, client):
	return await client.post(
		'/login', data={'password': REMOTE_PASSWORD}, headers={'Origin': gateway.origin}, allow_redirects=False
	)


@pytest.mark.asyncio
async def test_public_gateway_exposes_only_login_page(gateway_client):
	gateway, client = gateway_client
	response = await client.get('/', allow_redirects=False)
	assert response.status == 302
	assert response.headers['Location'] == '/login'
	assert (await client.get('/viewer.js')).status == 401
	assert (await client.get('/assets/core/rfb.js')).status == 401
	page = await client.get('/login')
	assert REMOTE_PASSWORD not in await page.text()
	assert page.headers['Cache-Control'] == 'no-store'
	assert page.headers['Referrer-Policy'] == 'no-referrer'
	assert page.headers['X-Frame-Options'] == 'DENY'


@pytest.mark.asyncio
async def test_login_requires_same_origin_and_sets_protected_cookie(gateway_client):
	gateway, client = gateway_client
	assert (
		await client.post('/login', data={'password': REMOTE_PASSWORD}, headers={'Origin': 'https://attacker.test'})
	).status == 403
	response = await sign_in(gateway, client)
	assert response.status == 303
	assert 'HttpOnly' in response.headers['Set-Cookie']
	assert 'SameSite=Strict' in response.headers['Set-Cookie']
	assert REMOTE_PASSWORD not in response.headers['Set-Cookie']
	assert (await client.get('/')).status == 200
	assert (await client.get('/assets/core/rfb.js')).status == 200
	assert (await client.get('/assets/core/../../outside')).status == 404
	assert (await client.post('/resume', headers={'Origin': gateway.origin})).status == 200
	assert gateway.resume.is_set()


@pytest.mark.asyncio
async def test_websocket_requires_both_authentication_and_origin(gateway_client):
	gateway, client = gateway_client
	with pytest.raises(WSServerHandshakeError) as error:
		await client.ws_connect('/websockify', headers={'Origin': gateway.origin})
	assert error.value.status == 401
	await sign_in(gateway, client)
	with pytest.raises(WSServerHandshakeError) as error:
		await client.ws_connect('/websockify', headers={'Origin': 'https://attacker.test'})
	assert error.value.status == 403


@pytest.mark.asyncio
async def test_authentication_rate_limit(gateway_client):
	gateway, client = gateway_client
	for attempt in range(5):
		response = await client.post('/login', data={'password': 'wrong'}, headers={'Origin': gateway.origin})
		assert response.status == 401
	response = await sign_in(gateway, client)
	assert response.status == 429
	assert response.headers['Retry-After'] == '60'


@pytest.mark.asyncio
async def test_logout_and_deadline_revoke_access(gateway_client):
	gateway, client = gateway_client
	await sign_in(gateway, client)
	assert (await client.post('/logout', headers={'Origin': gateway.origin})).status == 200
	assert (await client.get('/viewer.js')).status == 401
	await sign_in(gateway, client)
	gateway.deadline = time.monotonic() - 1
	assert (await client.get('/')).status == 410
	assert (await client.get('/login')).status == 410


@pytest.mark.asyncio
async def test_binary_websocket_bridge_and_revocation(gateway_client):
	gateway, client = gateway_client

	async def echo(reader, writer):
		try:
			while content := await reader.read(4096):
				writer.write(content)
				await writer.drain()
		finally:
			writer.close()
			await writer.wait_closed()

	server = await asyncio.start_server(echo, '127.0.0.1', 0)
	gateway.vnc_port = server.sockets[0].getsockname()[1]
	try:
		await sign_in(gateway, client)
		connection = await client.ws_connect('/websockify', headers={'Origin': gateway.origin})
		await connection.send_bytes(b'RFB 003.008\n')
		assert (await connection.receive(timeout=2)).data == b'RFB 003.008\n'
		await gateway.revoke()
		await connection.receive(timeout=2)
		await connection.close()
	finally:
		server.close()
		await server.wait_closed()


def test_short_remote_password_is_rejected(tmp_path):
	with pytest.raises(ManualLoginError):
		ManualGateway('short', tmp_path, 5900, 60)


def test_browser_children_do_not_inherit_account_or_repository_secrets(monkeypatch):
	monkeypatch.setenv('CHECKIN_STATE_KEY', 'secret')
	monkeypatch.setenv('GITHUB_TOKEN', 'secret')
	monkeypatch.setenv('ANYROUTER_ACCOUNTS', 'secret')
	monkeypatch.setenv('HTTPS_PROXY', 'http://credentials@example.test:8080')
	environment = child_environment()
	assert not {'CHECKIN_STATE_KEY', 'GITHUB_TOKEN', 'ANYROUTER_ACCOUNTS', 'HTTPS_PROXY'} & environment.keys()


def test_child_environment_preserves_windows_architecture_without_secrets(monkeypatch):
	monkeypatch.setenv('PROCESSOR_ARCHITECTURE', 'AMD64')
	monkeypatch.setenv('PROCESSOR_ARCHITEW6432', 'ARM64')
	monkeypatch.setenv('CHECKIN_WEB_PASSWORD', 'synthetic-private-password')
	monkeypatch.setenv('CHECKIN_WEB_KEY_FILE', 'synthetic-private-key-path')
	environment = child_environment()
	assert environment['PROCESSOR_ARCHITECTURE'] == 'AMD64'
	assert environment['PROCESSOR_ARCHITEW6432'] == 'ARM64'
	assert 'CHECKIN_WEB_PASSWORD' not in environment
	assert 'CHECKIN_WEB_KEY_FILE' not in environment


@pytest.mark.skipif(os.name != 'nt', reason='Windows child process platform detection')
def test_isolated_windows_worker_can_detect_cloakbrowser_platform():
	result = subprocess.run(
		[
			sys.executable,
			'-c',
			'import json,platform; from cloakbrowser.config import get_chromium_version; print(json.dumps({"machine":platform.machine(),"chromium":get_chromium_version()}))',
		],
		env=child_environment(),
		capture_output=True,
		text=True,
		timeout=15,
		check=True,
	)
	payload = json.loads(result.stdout)
	assert payload['machine'] == platform.machine()
	assert payload['machine']
	assert payload['chromium']


@pytest.mark.asyncio
async def test_disabled_takeover_does_not_start_processes(monkeypatch):
	monkeypatch.setenv('CHECKIN_MANUAL_LOGIN', 'false')
	with pytest.raises(ManualLoginError, match='disabled'):
		async with ManualTakeover(60):
			pytest.fail('Disabled takeover must not start')


def test_desktop_manual_availability_is_windows_only():
	assert desktop_manual_available() is (sys.platform == 'win32')


@pytest.mark.asyncio
async def test_local_desktop_takeover_waits_without_processes_or_ports(monkeypatch):
	monkeypatch.setenv('CHECKIN_MANUAL_LOGIN', 'true')
	monkeypatch.setenv('CHECKIN_MANUAL_TRANSPORT', 'local')
	monkeypatch.setenv('CHECKIN_MANUAL_HEADLESS', 'false')
	monkeypatch.delenv('DISPLAY', raising=False)
	monkeypatch.delenv('CHECKIN_REMOTE_PASSWORD', raising=False)
	monkeypatch.delenv('CHECKIN_MANUAL_SESSION', raising=False)
	monkeypatch.setattr('utils.manual_login.desktop_manual_available', lambda: True)

	def unexpected_resource(*args, **kwargs):
		pytest.fail('Local desktop waiting must not start network or subprocess resources')

	monkeypatch.setattr('utils.manual_login.asyncio.create_subprocess_exec', unexpected_resource)
	monkeypatch.setattr('utils.manual_login.unused_local_port', unexpected_resource)
	monkeypatch.setattr('utils.manual_login.shutil.which', unexpected_resource)
	monkeypatch.setattr('utils.manual_login.web.AppRunner', unexpected_resource)
	takeover = ManualTakeover(60)
	assert takeover.transport == 'remote'
	started = time.monotonic()
	async with takeover as active:
		assert active is takeover
		assert active.transport == 'desktop'
		assert active.url == ''
		assert isinstance(active.gateway, DesktopGateway)
		assert started + 60 <= active.gateway.deadline <= time.monotonic() + 60
		assert not active.gateway.resume.is_set()
		active.gateway.resume.set()
		assert active.gateway.resume.is_set()
		assert active._processes == []
		assert active._runner is None
	assert takeover.gateway is not None
	assert takeover.gateway.deadline == 0
	assert not takeover.gateway.resume.is_set()
	await takeover.close()
	assert takeover.gateway.deadline == 0


@pytest.mark.asyncio
@pytest.mark.parametrize('disabled', ['false', ''])
async def test_local_desktop_takeover_still_requires_manual_login_enabled(monkeypatch, disabled):
	monkeypatch.setenv('CHECKIN_MANUAL_LOGIN', disabled)
	monkeypatch.setenv('CHECKIN_MANUAL_TRANSPORT', 'local')
	monkeypatch.setenv('CHECKIN_MANUAL_HEADLESS', 'false')
	monkeypatch.setattr('utils.manual_login.desktop_manual_available', lambda: True)
	takeover = ManualTakeover(60)
	with pytest.raises(ManualLoginError, match='disabled'):
		await takeover.__aenter__()
	assert takeover.gateway is None


@pytest.mark.asyncio
async def test_local_desktop_takeover_rejects_headless_browser(monkeypatch):
	monkeypatch.setenv('CHECKIN_MANUAL_LOGIN', 'true')
	monkeypatch.setenv('CHECKIN_MANUAL_TRANSPORT', 'local')
	monkeypatch.setenv('CHECKIN_MANUAL_HEADLESS', 'true')
	monkeypatch.setattr('utils.manual_login.desktop_manual_available', lambda: True)
	takeover = ManualTakeover(60)
	with pytest.raises(ManualLoginError, match='headless mode to be disabled'):
		await takeover.__aenter__()
	assert takeover.gateway is None


@pytest.mark.asyncio
async def test_desktop_takeover_is_not_used_for_other_transports(monkeypatch):
	monkeypatch.setenv('CHECKIN_MANUAL_LOGIN', 'true')
	monkeypatch.setenv('CHECKIN_MANUAL_TRANSPORT', 'remote')
	monkeypatch.setenv('CHECKIN_MANUAL_HEADLESS', 'false')
	monkeypatch.delenv('DISPLAY', raising=False)
	monkeypatch.setattr('utils.manual_login.desktop_manual_available', lambda: True)
	takeover = ManualTakeover(60)
	with pytest.raises(ManualLoginError, match='Linux/Xvfb'):
		await takeover.__aenter__()
	assert takeover.gateway is None
	assert takeover.transport == 'remote'


@pytest.mark.parametrize('timeout', [29, 1801])
def test_desktop_takeover_preserves_timeout_bounds(timeout):
	with pytest.raises(ManualLoginError, match='between 30 and 1800'):
		ManualTakeover(timeout)
