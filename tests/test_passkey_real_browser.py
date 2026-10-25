"""Real WebAuthn ceremonies use a disposable Chrome virtual authenticator.

Browser plugin not available. The flow under test is an isolated HTTPS origin
forwarded to a local aiohttp server, with actual browser-generated keys and
signatures. Neither the user's browser profile nor an external service is used.
"""

import base64
import hashlib
import json
import os
import secrets
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

import pytest
from aiohttp.test_utils import TestServer
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from playwright.async_api import async_playwright

from server.app import SERVICE, create_app

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in virtual WebAuthn browser')

ORIGIN = 'https://security.example.test'
PASSWORD = 'synthetic-passkey-browser-password'


def decode(value):
	return base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))


def encode(value):
	return base64.urlsafe_b64encode(value).rstrip(b'=').decode()


async def api(page, path, *, method='GET', body=None, csrf=None):
	return await page.evaluate(
		"""async ({path, method, body, csrf}) => {
            const headers = {'Accept': 'application/json'};
            if (body !== null) headers['Content-Type'] = 'application/json';
            if (csrf) headers['X-CSRF-Token'] = csrf;
            const response = await fetch(path, {
                method, headers, credentials: 'same-origin', cache: 'no-store',
                ...(body !== null ? {body: JSON.stringify(body)} : {}),
            });
            const text = await response.text();
            let payload;
            try { payload = JSON.parse(text); } catch (_) { payload = {error: text}; }
            return {status: response.status, body: payload};
        }""",
		{'path': path, 'method': method, 'body': body, 'csrf': csrf},
	)


async def ceremony(page, public_key, *, create=False):
	return await page.evaluate(
		"""async ({publicKey, create}) => {
            const bytes = (value) => {
                const raw = atob(value.replaceAll('-', '+').replaceAll('_', '/') + '='.repeat((4 - value.length % 4) % 4));
                return Uint8Array.from(raw, (char) => char.charCodeAt(0));
            };
            const encoded = (value) => {
                if (value == null) return null;
                return btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
            };
            const options = structuredClone(publicKey);
            options.challenge = bytes(options.challenge);
            if (options.user) options.user.id = bytes(options.user.id);
            for (const name of ['allowCredentials', 'excludeCredentials']) {
                if (options[name]) options[name] = options[name].map((entry) => ({...entry, id: bytes(entry.id)}));
            }
            const credential = await navigator.credentials[create ? 'create' : 'get']({publicKey: options});
            const result = {
                id: credential.id, rawId: encoded(credential.rawId), type: credential.type,
                authenticatorAttachment: credential.authenticatorAttachment,
                clientExtensionResults: credential.getClientExtensionResults(),
                response: {clientDataJSON: encoded(credential.response.clientDataJSON)},
            };
            for (const name of ['attestationObject', 'authenticatorData', 'signature', 'userHandle']) {
                if (name in credential.response) result.response[name] = encoded(credential.response[name]);
            }
            if (credential.response.getTransports) result.response.transports = credential.response.getTransports();
            return result;
        }""",
		{'publicKey': public_key, 'create': create},
	)


@asynccontextmanager
async def virtual_browser(tmp_path):
	app = create_app(
		tmp_path,
		os.urandom(32),
		PASSWORD,
		scheduler=False,
		public_origin=ORIGIN,
		trusted_proxy_ips=('127.0.0.1',),
	)
	blocked, errors = [], []
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None,
			headless=True,
		)
		context = await browser.new_context()

		async def forward(route):
			request = route.request
			if not request.url.startswith(ORIGIN + '/'):
				blocked.append(request.url)
				await route.abort()
				return
			path = urlsplit(request.url).path
			if path == '/':
				await route.fulfill(content_type='text/html', body='<title>Isolated WebAuthn fixture</title>')
				return
			headers = await request.all_headers()
			headers.update(
				{
					'host': 'security.example.test',
					'x-forwarded-proto': 'https',
					'x-forwarded-for': '203.0.113.8',
				}
			)
			response = await route.fetch(url=str(server.make_url(path)), headers=headers)
			await route.fulfill(response=response)

		await context.route('**/*', forward)
		page = await context.new_page()
		page.on('pageerror', lambda error: errors.append(type(error).__name__))
		cdp = await context.new_cdp_session(page)
		await cdp.send('WebAuthn.enable')
		authenticator = await cdp.send(
			'WebAuthn.addVirtualAuthenticator',
			{
				'options': {
					'protocol': 'ctap2',
					'transport': 'internal',
					'hasResidentKey': True,
					'hasUserVerification': True,
					'isUserVerified': True,
					'automaticPresenceSimulation': True,
				}
			},
		)
		await page.goto(ORIGIN + '/')
		assert await page.evaluate('isSecureContext && !!navigator.credentials')
		try:
			yield page, cdp, authenticator['authenticatorId'], app[SERVICE]
			assert not blocked and not errors
		finally:
			await browser.close()


async def password_login(page):
	response = await api(page, '/api/login', method='POST', body={'password': PASSWORD})
	assert response['status'] == 200, response
	return response['body']['csrf']


async def register(page, csrf):
	reauth = await api(page, '/api/security/reauth', method='POST', body={'password': PASSWORD}, csrf=csrf)
	assert reauth['status'] == 200, reauth
	options = await api(
		page,
		'/api/security/register/options',
		method='POST',
		body={
			'label': 'Isolated Chrome virtual key',
			'reauth_token': reauth['body']['reauth_token'],
		},
		csrf=csrf,
	)
	assert options['status'] == 200, options
	credential = await ceremony(page, options['body']['publicKey'], create=True)
	body = {'ticket': options['body']['ticket'], 'credential': credential}
	response = await api(page, '/api/security/register/verify', method='POST', body=body, csrf=csrf)
	assert response['status'] == 200, response
	return response['body'].get('csrf', csrf), body


async def passkey_reauth(page, csrf):
	options = await api(page, '/api/security/reauth/options', method='POST', body={}, csrf=csrf)
	assert options['status'] == 200, options
	credential = await ceremony(page, options['body']['publicKey'])
	response = await api(
		page,
		'/api/security/reauth/verify',
		method='POST',
		body={
			'ticket': options['body']['ticket'],
			'credential': credential,
		},
		csrf=csrf,
	)
	assert response['status'] == 200, response
	return response['body']['reauth_token'], response['body'].get('csrf', csrf)


async def test_real_passkey_registration_login_modes_and_no_password_backdoors(tmp_path):
	async with virtual_browser(tmp_path) as (page, _, _, _):
		csrf = await password_login(page)
		csrf, registration = await register(page, csrf)
		replay = await api(page, '/api/security/register/verify', method='POST', body=registration, csrf=csrf)
		assert replay['status'] in {400, 403, 409}
		security = (await api(page, '/api/security'))['body']
		assert len(security['passkeys']) == 1 and not security['passkeys'][0]['verified']
		password_token = await api(page, '/api/security/reauth', method='POST', body={'password': PASSWORD}, csrf=csrf)
		response = await api(
			page,
			'/api/security/mode',
			method='POST',
			body={
				'mode': 'passkey',
				'revision': security['revision'],
				'reauth_token': password_token['body']['reauth_token'],
			},
			csrf=csrf,
		)
		assert response['status'] in {400, 403, 409}
		token, csrf = await passkey_reauth(page, csrf)
		security = (await api(page, '/api/security'))['body']
		assert security['passkeys'][0]['verified']
		response = await api(
			page,
			'/api/security/mode',
			method='POST',
			body={
				'mode': 'passkey',
				'revision': security['revision'],
				'reauth_token': token,
			},
			csrf=csrf,
		)
		assert response['status'] == 200, response
		csrf = response['body']['csrf']
		assert response['body']['auth_mode'] == 'passkey'
		assert (await api(page, '/api/login', method='POST', body={'password': PASSWORD}))['status'] == 403
		assert (await api(page, '/api/security/reauth', method='POST', body={'password': PASSWORD}, csrf=csrf))[
			'status'
		] == 403
		restore = await api(
			page,
			'/api/backups/restore',
			method='POST',
			body={
				'revision': 0,
				'ticket': 'synthetic-invalid-ticket',
				'admin_password': PASSWORD,
			},
			csrf=csrf,
		)
		assert restore['status'] in {400, 403}
		token, csrf = await passkey_reauth(page, csrf)
		security = (await api(page, '/api/security'))['body']
		response = await api(
			page,
			'/api/security/passkeys/' + security['passkeys'][0]['id'],
			method='DELETE',
			body={
				'revision': security['revision'],
				'reauth_token': token,
			},
			csrf=csrf,
		)
		assert response['status'] in {400, 409}
		assert (await api(page, '/api/logout', method='POST', body={}, csrf=csrf))['status'] == 200
		assert (await api(page, '/api/config'))['status'] == 401
		options = await api(page, '/api/passkey/login/options', method='POST', body={})
		assert options['status'] == 200, options
		credential = await ceremony(page, options['body']['publicKey'])
		assertion = {'ticket': options['body']['ticket'], 'credential': credential}
		response = await api(page, '/api/passkey/login/verify', method='POST', body=assertion)
		assert response['status'] == 200, response
		csrf = response['body']['csrf']
		assert (await api(page, '/api/config'))['status'] == 200
		assert (await api(page, '/api/passkey/login/verify', method='POST', body=assertion))['status'] in {400, 403}
		token, csrf = await passkey_reauth(page, csrf)
		security = (await api(page, '/api/security'))['body']
		response = await api(
			page,
			'/api/security/mode',
			method='POST',
			body={
				'mode': 'password',
				'revision': security['revision'],
				'reauth_token': token,
			},
			csrf=csrf,
		)
		assert response['status'] == 200, response
		csrf = response['body']['csrf']
		assert response['body']['auth_mode'] == 'password'
		password_token = await api(page, '/api/security/reauth', method='POST', body={'password': PASSWORD}, csrf=csrf)
		security = (await api(page, '/api/security'))['body']
		deleted = await api(
			page,
			'/api/security/passkeys/' + security['passkeys'][0]['id'],
			method='DELETE',
			body={'revision': security['revision'], 'reauth_token': password_token['body']['reauth_token']},
			csrf=csrf,
		)
		assert deleted['status'] == 200, deleted
		csrf = deleted['body'].get('csrf', csrf)
		assert (await api(page, '/api/security'))['body']['passkeys'] == []
		assert (await api(page, '/api/logout', method='POST', body={}, csrf=csrf))['status'] == 200
		await password_login(page)


def resign(credential, private_key, *, flags=None, counter=None):
	data = bytearray(decode(credential['response']['authenticatorData']))
	if flags is not None:
		data[32] = flags
	if counter is not None:
		data[33:37] = counter.to_bytes(4, 'big')
	signature = private_key.sign(
		bytes(data) + hashlib.sha256(decode(credential['response']['clientDataJSON'])).digest(),
		ec.ECDSA(hashes.SHA256()),
	)
	credential['response']['authenticatorData'] = encode(data)
	credential['response']['signature'] = encode(signature)
	return credential


async def test_real_key_rejects_valid_signatures_without_user_verification_and_counter_rollback(tmp_path):
	async with virtual_browser(tmp_path) as (page, cdp, authenticator_id, _):
		csrf = await password_login(page)
		csrf, _ = await register(page, csrf)
		_, csrf = await passkey_reauth(page, csrf)
		credentials = await cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator_id})
		assert len(credentials['credentials']) == 1
		private_key = serialization.load_der_private_key(
			base64.b64decode(credentials['credentials'][0]['privateKey']), password=None
		)
		assert isinstance(private_key, ec.EllipticCurvePrivateKey)
		assert (await api(page, '/api/logout', method='POST', body={}, csrf=csrf))['status'] == 200
		for attack in ('missing_uv', 'counter_rollback', 'unknown_key'):
			options = await api(page, '/api/passkey/login/options', method='POST', body={})
			assert options['status'] == 200, options
			credential = await ceremony(page, options['body']['publicKey'])
			if attack == 'missing_uv':
				flags = decode(credential['response']['authenticatorData'])[32] & ~0x04
				credential = resign(credential, private_key, flags=flags)
			elif attack == 'counter_rollback':
				credential = resign(credential, private_key, counter=1)
			else:
				credential['id'] = credential['rawId'] = encode(secrets.token_bytes(32))
			response = await api(
				page,
				'/api/passkey/login/verify',
				method='POST',
				body={
					'ticket': options['body']['ticket'],
					'credential': credential,
				},
			)
			assert response['status'] in {400, 403}, (attack, response)
			assert (await api(page, '/api/config'))['status'] == 401


async def test_real_assertions_remain_bound_to_browser_origin_context_and_user_handle(tmp_path):
	async with virtual_browser(tmp_path) as (page, cdp, authenticator_id, _):
		csrf = await password_login(page)
		csrf, _ = await register(page, csrf)
		_, csrf = await passkey_reauth(page, csrf)
		credentials = await cdp.send('WebAuthn.getCredentials', {'authenticatorId': authenticator_id})
		private_key = serialization.load_der_private_key(
			base64.b64decode(credentials['credentials'][0]['privateKey']), password=None
		)
		assert isinstance(private_key, ec.EllipticCurvePrivateKey)
		assert (await api(page, '/api/logout', method='POST', body={}, csrf=csrf))['status'] == 200
		for attack in (
			'different_browser',
			'wrong_origin',
			'cross_origin',
			'raw_id_mismatch',
			'wrong_user',
			'invalid_backup_state',
		):
			options = await api(page, '/api/passkey/login/options', method='POST', body={})
			assert options['status'] == 200, options
			credential = await ceremony(page, options['body']['publicKey'])
			if attack == 'different_browser':
				await page.context.clear_cookies(name='checkin_passkey_challenge')
			elif attack in {'wrong_origin', 'cross_origin'}:
				client_data = json.loads(decode(credential['response']['clientDataJSON']))
				if attack == 'wrong_origin':
					client_data['origin'] = 'https://attacker.example.test'
				else:
					client_data.update(crossOrigin=True, topOrigin='https://attacker.example.test')
				credential['response']['clientDataJSON'] = encode(json.dumps(client_data).encode())
				credential = resign(credential, private_key)
			elif attack == 'raw_id_mismatch':
				credential['rawId'] = encode(secrets.token_bytes(32))
			elif attack == 'wrong_user':
				credential['response']['userHandle'] = encode(secrets.token_bytes(32))
			else:
				flags = (decode(credential['response']['authenticatorData'])[32] | 0x10) & ~0x08
				credential = resign(credential, private_key, flags=flags)
			response = await api(
				page,
				'/api/passkey/login/verify',
				method='POST',
				body={
					'ticket': options['body']['ticket'],
					'credential': credential,
				},
			)
			assert response['status'] in {400, 403}, (attack, response)
			assert (await api(page, '/api/config'))['status'] == 401
		options = await api(page, '/api/passkey/login/options', method='POST', body={})
		credential = await ceremony(page, options['body']['publicKey'])
		response = await api(
			page,
			'/api/passkey/login/verify',
			method='POST',
			body={
				'ticket': options['body']['ticket'],
				'credential': credential,
			},
		)
		assert response['status'] == 200, response
