"""Passkey UI flows use synthetic credentials and mocked HTTP endpoints.

Browser plugin not available. The flow under test is login policy -> device
prompt -> key registration/verification -> deliberate mode switch/revocation.
No real authenticator, production account or notification channel is used.
"""

import copy
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import STATIC_ROOT
from server.config_store import default_config

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixtures')

ADMIN_PASSWORD = 'synthetic-passkey-admin-password'

MOCK_AUTHENTICATOR = """
window.__credentialCalls = {get: 0, create: 0};
window.__cancelPasskey = false;
function syntheticCredential(registration) {
  const response = {clientDataJSON: new Uint8Array([4, 5]).buffer};
  if (registration) {
    response.attestationObject = new Uint8Array([6, 7]).buffer;
    response.getTransports = () => ['internal'];
  } else {
    response.authenticatorData = new Uint8Array([8, 9]).buffer;
    response.signature = new Uint8Array([10, 11]).buffer;
    response.userHandle = null;
  }
  return {id: 'AQID', rawId: new Uint8Array([1, 2, 3]).buffer, type: 'public-key',
    response, authenticatorAttachment: 'platform', getClientExtensionResults: () => ({})};
}
Object.defineProperty(navigator, 'credentials', {configurable: true, value: {
  get: async (options) => {
    window.__credentialCalls.get++;
    if (!(options.publicKey.challenge instanceof Uint8Array)) throw new Error('Challenge not decoded');
    if (options.publicKey.allowCredentials && !(options.publicKey.allowCredentials[0].id instanceof Uint8Array)) throw new Error('Credential not decoded');
    if (window.__cancelPasskey) throw new DOMException('Cancelled', 'NotAllowedError');
    return syntheticCredential(false);
  },
  create: async (options) => {
    window.__credentialCalls.create++;
    if (!(options.publicKey.user.id instanceof Uint8Array)) throw new Error('User handle not decoded');
    if (window.__cancelPasskey) throw new DOMException('Cancelled', 'NotAllowedError');
    return syntheticCredential(true);
  },
}});
"""


@asynccontextmanager
async def passkey_ui(tmp_path, *, authenticated=False, mode='password', keys=None, view='security', mobile=False):
	app = web.Application()
	for path, filename in [
		('/', 'index.html'),
		('/security', 'security.html'),
		('/app.js', 'app.js'),
		('/passkeys.js', 'passkeys.js'),
		('/security.js', 'security.js'),
		('/style.css', 'style.css'),
	]:

		async def static(_, filename=filename):
			return web.FileResponse(STATIC_ROOT / filename)

		app.router.add_get(path, static)
	fixture = {
		'authenticated': authenticated,
		'mode': mode,
		'csrf': 'synthetic-initial-csrf',
		'revision': 1,
		'keys': copy.deepcopy(keys or []),
		'calls': [],
		'labels': [],
		'delete_error': False,
		'mode_unknown': False,
	}
	errors, blocked, console = [], [], []
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		context = await browser.new_context(
			viewport={'width': 390, 'height': 844} if mobile else {'width': 1440, 'height': 1080}
		)
		await context.add_init_script(MOCK_AUTHENTICATOR)
		origin = str(server.make_url('')).rstrip('/')

		def policy():
			return {
				'authenticated': fixture['authenticated'],
				'csrf': fixture['csrf'],
				'auth_mode': fixture['mode'],
				'passkey_available': any(item['verified'] for item in fixture['keys']),
				'password_login_allowed': fixture['mode'] == 'password',
				'passkey_origin_allowed': True,
				'reauth_method': 'passkey' if fixture['mode'] == 'passkey' else 'password',
			}

		def security():
			return {
				**policy(),
				'mode': fixture['mode'],
				'revision': fixture['revision'],
				'passkeys': fixture['keys'],
				'can_register': True,
			}

		async def guard(route):
			request = route.request
			if not request.url.startswith(origin + '/'):
				blocked.append(request.url)
				await route.abort()
				return
			path = request.url.removeprefix(origin)
			if not path.startswith('/api/'):
				await route.continue_()
				return
			body: dict = json.loads(request.post_data) if request.post_data else {}
			fixture['calls'].append((request.method, path, body))
			if (
				request.method not in {'GET', 'HEAD'}
				and path != '/api/login'
				and not path.startswith('/api/passkey/login/')
			):
				assert request.headers.get('x-csrf-token') == fixture['csrf']
			if path == '/api/session':
				await route.fulfill(json=policy())
			elif path == '/api/login':
				fixture['authenticated'] = fixture['mode'] == 'password' and body['password'] == ADMIN_PASSWORD
				await route.fulfill(
					status=200 if fixture['authenticated'] else 401,
					json=policy() if fixture['authenticated'] else {'error': '管理员密码错误'},
				)
			elif path == '/api/passkey/login/options' or path == '/api/security/reauth/options':
				await route.fulfill(
					json={
						'ticket': 'synthetic-auth-ticket',
						'publicKey': {
							'challenge': 'AQID',
							'rpId': 'localhost',
							'allowCredentials': [{'type': 'public-key', 'id': 'AQID'}],
							'userVerification': 'required',
						},
					}
				)
			elif path == '/api/passkey/login/verify':
				assert body['credential']['response']['signature'] == 'Cgs'
				assert body['credential']['response']['userHandle'] is None
				fixture['authenticated'] = True
				await route.fulfill(json=policy())
			elif not fixture['authenticated']:
				await route.fulfill(status=401, json={'error': '请先登录'})
			elif path == '/api/security':
				await route.fulfill(json=security())
			elif path == '/api/security/reauth':
				await route.fulfill(
					status=200 if body['password'] == ADMIN_PASSWORD else 400,
					json={'reauth_token': 'synthetic-password-reauth'}
					if body['password'] == ADMIN_PASSWORD
					else {'error': '当前管理员密码错误'},
				)
			elif path == '/api/security/reauth/verify':
				for key in fixture['keys']:
					key['verified'] = True
				await route.fulfill(json={'reauth_token': 'synthetic-passkey-reauth'})
			elif path == '/api/security/register/options':
				fixture['labels'].append(body['label'])
				assert body['reauth_token']
				await route.fulfill(
					json={
						'ticket': 'synthetic-register-ticket',
						'publicKey': {
							'challenge': 'AQID',
							'rp': {'id': 'localhost', 'name': 'Example'},
							'user': {'id': 'BAUG', 'name': 'admin', 'displayName': 'Admin'},
							'pubKeyCredParams': [{'type': 'public-key', 'alg': -7}],
						},
					}
				)
			elif path == '/api/security/register/verify':
				assert body['credential']['response']['attestationObject'] == 'Bgc'
				assert body['credential']['response']['transports'] == ['internal']
				fixture['keys'].append(
					{
						'id': 'AQID',
						'label': fixture['labels'][-1],
						'verified': False,
						'created_at': '2026-10-25T08:00:00Z',
						'last_used_at': None,
					}
				)
				fixture['revision'] += 1
				await route.fulfill(json={'registered': True})
			elif path == '/api/security/mode':
				assert body['revision'] == fixture['revision']
				if fixture['mode_unknown']:
					await route.abort()
					return
				fixture['mode'] = body['mode']
				fixture['revision'] += 1
				fixture['csrf'] = 'synthetic-rotated-csrf'
				await route.fulfill(json={**policy(), 'mode': fixture['mode'], 'revision': fixture['revision']})
			elif path.startswith('/api/security/passkeys/'):
				if fixture['delete_error']:
					await route.fulfill(status=400, json={'error': '必须保留最后一把已验证的 Passkey'})
					return
				fixture['keys'] = [key for key in fixture['keys'] if key['id'] != path.rsplit('/', 1)[-1]]
				fixture['revision'] += 1
				await route.fulfill(json={'deleted': True})
			elif path == '/api/logout':
				fixture['authenticated'] = False
				await route.fulfill(json={'authenticated': False})
			elif path == '/api/config':
				await route.fulfill(json={'config': default_config(), 'revision': 1})
			elif path == '/api/status':
				await route.fulfill(json={'running': False, 'run': None, 'attention': {}, 'next_run_at': None})
			elif path == '/api/runs':
				await route.fulfill(json={'runs': []})
			else:
				await route.fulfill(status=404, json={'error': 'Unexpected mock endpoint'})

		await context.route('**/*', guard)
		page = await context.new_page()
		page.set_default_timeout(5000)
		page.on('pageerror', lambda error: errors.append(str(error)))
		page.on(
			'console',
			lambda item: console.append(item.text)
			if item.type == 'error' and 'Failed to load resource' not in item.text
			else None,
		)
		try:
			await page.goto(origin + ('/security' if view == 'security' else '/'))
			yield page, fixture
			assert not errors and not blocked and not console
		finally:
			await browser.close()


def key(key_id='AQID', label='My computer', verified=True):
	return {
		'id': key_id,
		'label': label,
		'verified': verified,
		'created_at': '2026-10-25T08:00:00Z',
		'last_used_at': None,
	}


async def test_main_password_mode_keeps_existing_login_and_security_link(tmp_path):
	async with passkey_ui(tmp_path, view='main') as (page, fixture):
		await expect(page.locator('#password-login-controls')).to_be_visible()
		await expect(page.locator('#passkey-login-button')).to_be_hidden()
		await page.get_by_label('管理密码', exact=True).fill(ADMIN_PASSWORD)
		await page.get_by_role('button', name='登录', exact=True).click()
		await expect(page.locator('#workspace')).to_be_visible()
		await expect(page.get_by_role('link', name='登录与安全')).to_have_attribute('href', '/security')
		assert sum(path == '/api/login' for _, path, _ in fixture['calls']) == 1


async def test_main_passkey_mode_hides_password_and_cancellation_never_falls_back(tmp_path):
	async with passkey_ui(tmp_path, view='main', mode='passkey', keys=[key()]) as (page, fixture):
		await expect(page.locator('#password-login-controls')).to_be_hidden()
		await page.evaluate('window.__cancelPasskey = true')
		await page.get_by_role('button', name='使用 Passkey 登录').click()
		await expect(page.locator('#login-message')).to_contain_text('已取消或未完成')
		assert not any(path in {'/api/login', '/api/passkey/login/verify'} for _, path, _ in fixture['calls'])
		assert await page.evaluate('window.__credentialCalls.get') == 1
		await page.evaluate('window.__cancelPasskey = false')
		await page.get_by_role('button', name='使用 Passkey 登录').click()
		await expect(page.locator('#workspace')).to_be_visible()
		assert sum(path == '/api/passkey/login/verify' for _, path, _ in fixture['calls']) == 1


async def test_registration_verification_and_mode_switch_rotate_csrf(tmp_path):
	async with passkey_ui(tmp_path, authenticated=True) as (page, fixture):
		await expect(page.locator('#security-workspace')).to_be_visible()
		await expect(page.locator('#enable-passkey-mode')).to_be_disabled()
		await page.get_by_label('密钥名称', exact=True).fill('My computer')
		await page.get_by_label('当前管理密码', exact=True).fill(ADMIN_PASSWORD)
		await page.get_by_role('button', name='添加 Passkey', exact=True).click()
		await expect(page.locator('#security-keys')).to_contain_text('待验证')
		await expect(page.locator('#enable-passkey-mode')).to_be_disabled()
		await page.get_by_role('button', name='验证 Passkey', exact=True).click()
		await expect(page.locator('#security-keys')).to_contain_text('已验证')
		await expect(page.locator('#enable-passkey-mode')).to_be_enabled()
		await page.get_by_role('button', name='启用 Passkey 版', exact=True).click()
		await expect(page.locator('#security-mode-badge')).to_have_text('Passkey 版')
		await expect(page.locator('#security-password-reauth')).to_be_hidden()
		assert fixture['csrf'] == 'synthetic-rotated-csrf'
		assert fixture['mode'] == 'passkey'
		page.on('dialog', lambda dialog: dialog.accept())
		await page.get_by_role('button', name='切换为密码版', exact=True).click()
		await expect(page.locator('#security-mode-badge')).to_have_text('密码版')
		await expect(page.locator('#security-password-reauth')).to_be_visible()


async def test_last_verified_key_is_preserved_and_server_errors_are_visible(tmp_path):
	async with passkey_ui(tmp_path, authenticated=True, mode='passkey', keys=[key(), key('BAUG', 'Backup', False)]) as (
		page,
		fixture,
	):
		await expect(page.get_by_role('button', name='删除 Passkey My computer', exact=True)).to_be_disabled()
		fixture['delete_error'] = True
		page.on('dialog', lambda dialog: dialog.accept())
		await page.get_by_role('button', name='删除 Passkey Backup', exact=True).click()
		await expect(page.locator('#security-message')).to_contain_text('必须保留最后一把')
		assert len(fixture['keys']) == 2


async def test_uncertain_mode_change_locks_writes_until_readback(tmp_path):
	async with passkey_ui(tmp_path, authenticated=True, keys=[key()]) as (page, fixture):
		fixture['mode_unknown'] = True
		await page.get_by_role('button', name='启用 Passkey 版', exact=True).click()
		await expect(page.locator('#security-message')).to_contain_text('操作结果尚未确认')
		await expect(page.locator('#enable-passkey-mode')).to_be_disabled()
		await page.get_by_role('button', name='重新读取', exact=True).click()
		await expect(page.locator('#enable-passkey-mode')).to_be_enabled()
		assert sum(path == '/api/security/mode' for _, path, _ in fixture['calls']) == 1


async def test_security_login_uses_passkey_and_mobile_fits_with_draft_preserved(tmp_path):
	async with passkey_ui(tmp_path, mode='passkey', keys=[key()], mobile=True) as (page, _):
		await expect(page.locator('#security-password-login')).to_be_hidden()
		await page.get_by_role('button', name='使用 Passkey 登录', exact=True).click()
		await expect(page.locator('#security-workspace')).to_be_visible()
		await page.get_by_label('密钥名称', exact=True).fill('Backup phone')
		await page.get_by_role('button', name='重新读取', exact=True).click()
		await expect(page.get_by_label('密钥名称', exact=True)).to_have_value('Backup phone')
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		folder = os.getenv('CHECKIN_UI_SCREENSHOT_DIR')
		if folder:
			root = Path(folder)
			root.mkdir(parents=True, exist_ok=True)
			await page.screenshot(path=str(root / 'passkey-security-mobile.png'), full_page=True)


async def test_security_desktop_screenshot_and_no_key_cannot_enable_passkey_mode(tmp_path):
	async with passkey_ui(tmp_path, authenticated=True) as (page, _):
		await expect(page.locator('#security-mode-badge')).to_have_text('密码版')
		await expect(page.locator('#enable-passkey-mode')).to_be_disabled()
		await expect(page.locator('#security-keys')).to_contain_text('尚未绑定')
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		folder = os.getenv('CHECKIN_UI_SCREENSHOT_DIR')
		if folder:
			root = Path(folder)
			root.mkdir(parents=True, exist_ok=True)
			await page.screenshot(path=str(root / 'passkey-security-desktop.png'), full_page=True)
