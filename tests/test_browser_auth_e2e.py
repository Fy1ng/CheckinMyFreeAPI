"""Opt-in native Chromium fixtures using offline test origins and a loopback HTTP server."""

import asyncio
import base64
import json
import os
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright

from utils.auth_runtime import AuthenticationRuntime
from utils.config import AccountConfig, AppConfig, IdentityConfig, ProviderConfig
from utils.oauth import OAuthAttempt, OAuthFlow
from utils.secure_state import SnapshotStore

pytestmark = pytest.mark.skipif(
	os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Set CHECKIN_BROWSER_TESTS=1 for isolated native browser fixtures'
)


@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['linuxdo', 'github'])
async def test_native_oauth_cookie_state_manual_recovery_and_second_run(monkeypatch, tmp_path, kind):
	authorize_path = '/oauth2/authorize' if kind == 'linuxdo' else '/login/oauth/authorize'
	origins = {'anyrouter': 'https://anyrouter.fixture.test', 'agentrouter': 'https://agentrouter.fixture.test'}
	users = {
		name: {'id': index + 7, 'username': name, 'quota': 5_000_000, 'used_quota': 0}
		for index, name in enumerate(origins)
	}
	accounts = [
		AccountConfig(
			None,
			id=name,
			name=name,
			provider=name,
			expected_username=name,
			auth={'type': kind, 'identity': 'shared'},
		)
		for name in origins
	]
	config = AppConfig(
		providers={
			name: ProviderConfig(
				name=name, domain=origin, sign_in_path='/api/user/sign_in' if name == 'anyrouter' else None
			)
			for name, origin in origins.items()
		},
		identities={'shared': IdentityConfig(kind, proxy='direct')},
	)
	exchanges = []
	state_requests: list[str] = []
	blocked_requests = []
	contexts = []
	manual_count = 0
	manual_tasks = []
	states = {}
	codes: dict[str, str] = {}

	async def fixture_route(route):
		request = route.request
		parsed = urlsplit(request.url)
		query = parse_qs(parsed.query)
		origin = f'{parsed.scheme}://{parsed.netloc}'
		headers = await request.all_headers()
		cookies = headers.get('cookie', '')
		provider = next((name for name, url in origins.items() if url == origin), None)

		async def respond(payload, headers=None):
			await route.fulfill(
				status=200, content_type='application/json', body=json.dumps(payload), headers=headers or {}
			)

		async def redirect(url, headers=None):
			# HTTP redirect chains bypass Playwright routing. New document navigations stay intercepted.
			await route.fulfill(
				status=200,
				content_type='text/html',
				headers=headers or {},
				body='<script>location.replace(' + json.dumps(url) + ')</script>',
			)

		if provider:
			user = users[provider]
			if parsed.path in {'/', '/login'}:
				await route.fulfill(
					status=200,
					content_type='text/html',
					body='<html><meta charset="utf-8"><link rel="icon" href="data:,"><h1>Synthetic provider</h1><button>Login</button><button>Help</button></html>',
				)
			elif parsed.path == '/api/status':
				await respond({'success': True, 'data': {f'{kind}_client_id': provider}})
			elif parsed.path == '/api/oauth/state':
				state = f'fixture-state-{provider}-{len(state_requests)}'
				state_requests.append(state)
				states[state] = provider
				await respond(
					{'success': True, 'data': state},
					{'Set-Cookie': f'csrf={state}; Path=/; HttpOnly; Secure; SameSite=Lax'},
				)
			elif parsed.path == f'/api/oauth/{kind}':
				state, code = query.get('state', [''])[0], query.get('code', [''])[0]
				assert f'csrf={state}' in cookies
				assert codes.pop(code) == state
				assert states[state] == provider
				exchanges.append(provider)
				await respond(
					{'success': True, 'data': user},
					{'Set-Cookie': f'session={provider}; Path=/; HttpOnly; Secure; Max-Age=3600; SameSite=Lax'},
				)
			elif parsed.path == '/api/user/self':
				if f'session={provider}' in cookies and headers.get('new-api-user') == str(user['id']):
					await respond({'success': True, 'data': user})
				else:
					await route.fulfill(status=401, content_type='application/json', body='{"success":false}')
			elif parsed.path == '/api/user/sign_in':
				assert request.method == 'POST'
				assert f'session={provider}' in cookies
				await respond({'success': True})
			else:
				await route.fulfill(status=404, body='Fixture route not found')
			return
		if parsed.netloc == 'identity.fixture.test':
			if parsed.path not in {authorize_path, '/fixture-verification', '/fixture-login', '/oauth2/approve'}:
				await route.fulfill(status=404, body='Fixture route not found')
				return
			if kind == 'github' and parsed.path == authorize_path and request.method == 'POST':
				query = parse_qs(request.post_data or '')
			provider = query.get('client_id', [''])[0]
			state = query.get('state', [''])[0]
			assert provider in origins and states[state] == provider
			parameters = urlencode({'client_id': provider, 'state': state})
			approve = parsed.path == '/oauth2/approve' or (parsed.path == authorize_path and request.method == 'POST')
			if parsed.path == authorize_path and not approve:
				if 'idp_session=fixture' in cookies:
					if kind == 'linuxdo':
						body = f'<html><link rel="icon" href="data:,"><h1>Synthetic authorization</h1><a href="/oauth2/approve?{parameters}">Approve fixture</a></html>'
					else:
						body = f'<html><link rel="icon" href="data:,"><h1>Synthetic authorization</h1><form action="/login/oauth/authorize" method="post"><input type="hidden" name="client_id" value="{provider}"><input type="hidden" name="state" value="{state}"><button name="authorize" value="1">Approve fixture</button></form></html>'
				elif 'fixture_clearance=complete' not in cookies:
					body = f'<html><link rel="icon" href="data:,"><h1>Synthetic verification</h1><form action="/fixture-verification?{parameters}" method="post"><button>Continue fixture verification</button></form></html>'
				else:
					body = f'<html><link rel="icon" href="data:,"><h1>Synthetic identity login</h1><form action="/fixture-login?{parameters}" method="post"><input name="username"><input name="password" type="password"><button type="submit">Sign in fixture</button></form></html>'
				await route.fulfill(status=200, content_type='text/html', body=body)
			elif parsed.path == '/fixture-verification':
				assert request.method == 'POST'
				await redirect(
					authorize_path + '?' + parameters,
					headers={
						'Set-Cookie': 'fixture_clearance=complete; Path=/; HttpOnly; Secure; Max-Age=3600; SameSite=Lax'
					},
				)
			elif parsed.path == '/fixture-login':
				assert request.method == 'POST'
				await redirect(
					authorize_path + '?' + parameters,
					headers={
						'Set-Cookie': 'idp_session=fixture; Path=/; HttpOnly; Secure; Max-Age=3600; SameSite=Lax',
					},
				)
			elif approve:
				assert 'idp_session=fixture' in cookies
				code = 'fixture-code-' + str(len(codes)) + '-' + state
				codes[code] = state
				await redirect(origins[provider] + f'/oauth/{kind}?' + urlencode({'code': code, 'state': state}))
			else:
				await route.fulfill(status=404, body='Fixture route not found')
			return
		blocked_requests.append(request.url)
		await route.abort()

	async with asyncio.timeout(90), async_playwright() as playwright:

		async def launch(settings, **kwargs):
			context = await playwright.chromium.launch_persistent_context(
				str(settings.profile_dir),
				channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None,
				headless=True,
				viewport={'width': 1024, 'height': 768},
				service_workers='block',
			)
			await context.route('**/*', fixture_route)
			await context.set_offline(True)
			contexts.append(context)
			return context

		class SyntheticTakeover:
			def __init__(self, timeout):
				self.transport = 'desktop'
				self.url = ''
				self.gateway = SimpleNamespace(resume=asyncio.Event())

			async def __aenter__(self):
				nonlocal manual_count
				manual_count += 1

				async def user_interaction():
					page = contexts[-1].pages[-1]
					context = contexts[-1]
					assert not page.is_closed()
					await page.get_by_role('button', name='Continue fixture verification').click()
					assert contexts[-1] is context and page in context.pages and not page.is_closed()
					await page.locator('input[name="username"]').fill('synthetic-user')
					await page.locator('input[name="password"]').fill('synthetic-password')
					await page.get_by_role('button', name='Sign in fixture').click()
					await page.get_by_role('link' if kind == 'linuxdo' else 'button', name='Approve fixture').click(
						timeout=5000
					)

				manual_tasks.append(asyncio.create_task(user_interaction()))
				return self

			async def __aexit__(self, *args):
				await asyncio.gather(*manual_tasks)

		original_wait = OAuthFlow.wait

		async def fast_wait(self, page, seconds, *, automatic):
			result = await original_wait(self, page, min(seconds, 1) if automatic else seconds, automatic=automatic)
			for task in manual_tasks:
				if task.done():
					task.result()
			return result

		monkeypatch.setattr('utils.auth_runtime.launch_login_context', launch)
		monkeypatch.setattr('utils.auth_runtime.ManualTakeover', SyntheticTakeover)
		monkeypatch.setattr(OAuthFlow, 'wait', fast_wait)
		original_authorization_url = vars(OAuthAttempt)['authorization_url'].fget
		monkeypatch.setattr(
			OAuthAttempt,
			'authorization_url',
			property(
				lambda attempt: original_authorization_url(attempt)
				.replace('connect.linux.do', 'identity.fixture.test')
				.replace('github.com', 'identity.fixture.test')
			),
		)
		monkeypatch.setenv('CHECKIN_SECURE_MODE', 'true')
		secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
		cache_file = tmp_path / 'cache' / 'auth-state.enc'
		first_store = SnapshotStore(
			tmp_path / 'first', cache_file, secret, scope='fixture', compatibility='chromium-test'
		)
		first = AuthenticationRuntime(accounts, config, first_store)
		try:
			for index, account in enumerate(accounts):
				assert (await first.execute(account, index, allow_manual=True))[0]
		finally:
			first.close()
		assert manual_count == 1
		assert len(contexts) == len(accounts)
		assert len(state_requests) == len(accounts)
		assert exchanges == ['anyrouter', 'agentrouter']
		assert not blocked_requests
		second_store = SnapshotStore(
			tmp_path / 'second', cache_file, secret, scope='fixture', compatibility='chromium-test'
		)
		assert second_store.restore() == 'restored'
		second = AuthenticationRuntime(accounts, config, second_store)
		try:
			for index, account in enumerate(accounts):
				assert (await second.execute(account, index, allow_manual=False))[0]
		finally:
			second.close()
		assert manual_count == 1
		assert exchanges == ['anyrouter', 'agentrouter']
		assert b'idp_session' not in cache_file.read_bytes()


@pytest.mark.asyncio
@pytest.mark.parametrize('callback_path', ['/oauth/linuxdo', '/api/oauth/linuxdo'])
@pytest.mark.parametrize('callback_state', ['fixture-state', 'wrong-state'])
async def test_callback_intercepts_real_http_redirect_before_provider_exchange(
	monkeypatch, callback_path, callback_state
):
	callback_reached_server = False

	async def authorize(request):
		raise web.HTTPFound(callback_path + '?' + urlencode({'code': 'fixture-code', 'state': callback_state}))

	async def provider_callback(request):
		nonlocal callback_reached_server
		callback_reached_server = True
		return web.Response(text='Callback escaped interception')

	app = web.Application()
	app.router.add_get('/authorize', authorize)
	app.router.add_get(callback_path, provider_callback)
	async with asyncio.timeout(30), TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None,
			headless=True,
			args=['--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1'],
		)
		try:
			context = await browser.new_context(service_workers='block')
			origin = str(server.make_url('')).rstrip('/')
			monkeypatch.setattr(OAuthAttempt, 'authorization_url', property(lambda attempt: origin + '/authorize'))
			flow = OAuthFlow(context, OAuthAttempt('linuxdo', origin, 'fixture-client', 'fixture-state'))
			page = await context.new_page()
			await flow.install(page)
			await flow.open(page)
			assert await flow.wait(page, 1, automatic=False)
			code, error = flow.completed.result()
			if callback_state == 'fixture-state':
				assert (code, error) == ('fixture-code', None)
			else:
				assert code is None and error is not None
				assert error.reason == 'OAUTH_STATE_MISMATCH'
			assert not callback_reached_server
			await flow.close()
		finally:
			await browser.close()
