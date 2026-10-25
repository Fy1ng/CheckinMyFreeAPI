"""Public password and Passkey modes enforce the same policy at every API."""

import os
from unittest.mock import Mock

import pytest_asyncio
from aiohttp.test_utils import TestClient, TestServer
from test_passkey_crypto import Authenticator

from server.app import SERVICE, create_app
from server.web_access import WebAccess

ORIGIN = 'https://checkin.example.test'
PASSWORD = 'synthetic-passkey-admin-password'


@pytest_asyncio.fixture
async def admin(tmp_path):
	app = create_app(
		tmp_path, os.urandom(32), PASSWORD, scheduler=False, public_origin=ORIGIN, trusted_proxy_ips=('127.0.0.1',)
	)
	client = TestClient(TestServer(app))
	await client.start_server()
	state: dict = {'cookie': {}, 'csrf': ''}

	async def request(method, path, body=None, *, authenticate=True, extra=None):
		headers = {
			'Host': 'checkin.example.test',
			'Origin': ORIGIN,
			'X-Forwarded-Proto': 'https',
			'X-Forwarded-For': '203.0.113.7',
		}
		if authenticate:
			headers['Cookie'] = '; '.join(name + '=' + value for name, value in state['cookie'].items())
			headers['X-CSRF-Token'] = state['csrf']
		headers.update(extra or {})
		response = await client.request(method, path, json=body, headers=headers)
		for name, value in response.cookies.items():
			state['cookie'][name] = value.value
		payload = await response.json()
		if payload.get('csrf'):
			state['csrf'] = payload['csrf']
		return response, payload

	try:
		yield app[SERVICE], client, request, state
	finally:
		await client.close()


async def setup_key(request, device):
	response, _ = await request('POST', '/api/login', {'password': PASSWORD})
	assert response.status == 200
	response, proof = await request('POST', '/api/security/reauth', {'password': PASSWORD})
	assert response.status == 200
	response, options = await request(
		'POST', '/api/security/register/options', {'label': 'Synthetic key', 'reauth_token': proof['reauth_token']}
	)
	assert response.status == 200
	response, registered = await request(
		'POST',
		'/api/security/register/verify',
		{'ticket': options['ticket'], 'credential': device.response(options, registration=True)},
	)
	assert response.status == 200 and registered['registered']
	return registered['credential_id']


async def assertion(request, device):
	response, options = await request('POST', '/api/security/reauth/options', {})
	assert response.status == 200
	device.counter += 1
	response, proof = await request(
		'POST', '/api/security/reauth/verify', {'ticket': options['ticket'], 'credential': device.response(options)}
	)
	assert response.status == 200
	return proof['reauth_token']


async def enable(request, device):
	proof = await assertion(request, device)
	_, status = await request('GET', '/api/security')
	response, switched = await request(
		'POST', '/api/security/mode', {'mode': 'passkey', 'revision': status['revision'], 'reauth_token': proof}
	)
	assert response.status == 200 and switched['auth_mode'] == 'passkey'
	return switched


async def test_default_password_mode_is_compatible_and_public_ceremonies_require_origin(admin):
	_, client, request, _ = admin
	response, status = await request('GET', '/api/session')
	assert response.status == 200 and status['auth_mode'] == 'password'
	assert not status['passkey_available'] and status['passkey_origin_allowed']
	assert (await client.post('/api/passkey/login/options', json={})).status == 403
	response, _ = await request('POST', '/api/passkey/login/options', {})
	assert response.status == 400
	response, _ = await request('POST', '/api/login', {'password': PASSWORD})
	assert response.status == 200
	response, status = await request('GET', '/api/security')
	assert status['mode'] == 'password' and status['passkeys'] == []


async def test_enrollment_needs_recent_password_then_real_assertion_before_enabling(admin):
	_, _, request, state = admin
	device = Authenticator()
	identifier = await setup_key(request, device)
	_, status = await request('GET', '/api/security')
	assert status['passkeys'][0]['id'] == identifier and not status['passkeys'][0]['verified']
	_, proof = await request('POST', '/api/security/reauth', {'password': PASSWORD})
	response, _ = await request(
		'POST',
		'/api/security/mode',
		{'mode': 'passkey', 'revision': status['revision'], 'reauth_token': proof['reauth_token']},
	)
	assert response.status == 400
	old = state['cookie']['checkin_web_session']
	await enable(request, device)
	assert state['cookie']['checkin_web_session'] != old
	response, _ = await request('GET', '/api/config', extra={'Cookie': 'checkin_web_session=' + old})
	assert response.status == 401


async def test_passkey_mode_rejects_public_password_login_and_all_password_reauth_backdoors(admin, monkeypatch):
	service, _, request, _ = admin
	device = Authenticator()
	await setup_key(request, device)
	await enable(request, device)
	checker = Mock(side_effect=AssertionError('Password hashing must not be reached'))
	monkeypatch.setattr('server.app.hashlib.scrypt', checker)
	for path, payload in [
		('/api/login', {'password': PASSWORD}),
		('/api/security/reauth', {'password': PASSWORD}),
		('/api/backups/restore', {'revision': 0, 'ticket': 'invalid', 'admin_password': PASSWORD}),
	]:
		response, _ = await request('POST', path, payload)
		assert response.status == 403
	checker.assert_not_called()


async def test_passkey_login_is_browser_bound_secure_and_last_key_cannot_be_removed(admin):
	_, _, request, state = admin
	device = Authenticator()
	identifier = await setup_key(request, device)
	await enable(request, device)
	await request('POST', '/api/logout', {})
	response, options = await request('POST', '/api/passkey/login/options', {})
	assert response.status == 200
	assert response.cookies['checkin_passkey_challenge']['secure']
	device.counter += 1
	response, session = await request(
		'POST', '/api/passkey/login/verify', {'ticket': options['ticket'], 'credential': device.response(options)}
	)
	assert response.status == 200 and session['authenticated']
	assert response.cookies['checkin_web_session']['secure']
	assert session['reauth_method'] == 'passkey'
	proof = await assertion(request, device)
	_, status = await request('GET', '/api/security')
	response, _ = await request(
		'DELETE', '/api/security/passkeys/' + identifier, {'revision': status['revision'], 'reauth_token': proof}
	)
	assert response.status == 400
	proof = await assertion(request, device)
	response, _ = await request(
		'POST', '/api/security/mode', {'mode': 'password', 'revision': status['revision'], 'reauth_token': proof}
	)
	assert response.status == 200
	response, _ = await request('POST', '/api/login', {'password': PASSWORD})
	assert response.status == 200
	assert state['csrf']


async def test_unknown_cookie_cannot_redeem_another_browsers_login_challenge(admin):
	_, _, request, _ = admin
	device = Authenticator()
	await setup_key(request, device)
	_, options = await request('POST', '/api/passkey/login/options', {})
	response, _ = await request(
		'POST',
		'/api/passkey/login/verify',
		{'ticket': options['ticket'], 'credential': device.response(options)},
		extra={'Cookie': 'checkin_passkey_challenge=other-browser'},
	)
	assert response.status == 400


async def test_ssh_recovery_requires_actual_local_peer_and_no_forwarded_headers(admin):
	service, client, request, _ = admin
	device = Authenticator()
	await setup_key(request, device)
	await enable(request, device)
	origin = str(client.make_url('')).rstrip('/')
	response = await client.post('/api/login', json={'password': PASSWORD}, headers={'Origin': origin})
	assert response.status == 200
	response = await client.post(
		'/api/login', json={'password': PASSWORD}, headers={'Origin': origin, 'X-Forwarded-For': '127.0.0.1'}
	)
	assert response.status == 403
	service.access = WebAccess(ORIGIN)
	request_mock = Mock(remote='192.0.2.9', headers={})
	request_mock.__getitem__ = Mock(return_value='http://localhost')
	assert not service.private_recovery(request_mock)


async def test_security_revision_change_invalidates_sessions_and_registration_csrf_is_mandatory(admin):
	service, _, request, _ = admin
	await request('POST', '/api/login', {'password': PASSWORD})
	response, _ = await request(
		'POST',
		'/api/security/register/options',
		{'label': 'Key', 'reauth_token': 'invalid'},
		extra={'X-CSRF-Token': ''},
	)
	assert response.status == 403
	service.security.reset()
	response, _ = await request('GET', '/api/config')
	assert response.status == 401
