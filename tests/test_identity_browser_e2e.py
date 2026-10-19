"""Independent identity login against offline synthetic pages in a native browser."""

import asyncio
import base64
import html
import json
import os
from types import SimpleNamespace
from urllib.parse import urlsplit

import pytest
from playwright.async_api import async_playwright

from utils.config import AppConfig, IdentityConfig
from utils.identity_login import IdentityLoginRuntime, probe_identity_user
from utils.secure_state import SnapshotStore, state_key

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in offline Chromium fixture')


def discourse_bootstrap(*, attribute=False):
	data = json.dumps({'currentUser': json.dumps({'id': 42, 'username': 'fixture-user'})})
	if attribute:
		preload = f'<div id="data-preloaded" data-preloaded="{html.escape(data, quote=True)}"></div>'
	else:
		preload = f'<script id="data-preloaded" type="application/json">{data}</script>'
	return preload + '<button id="current-user">Current user</button>'


@pytest.mark.asyncio
@pytest.mark.parametrize(
	'kind,anonymous_status,initial_challenge',
	[('linuxdo', 404, True), ('linuxdo', 403, True), ('linuxdo', 403, False), ('github', 302, True)],
)
async def test_verification_identity_login_and_fresh_profile_restore(
	monkeypatch, tmp_path, kind, anonymous_status, initial_challenge
):
	origin = 'https://identity.fixture.test'
	monkeypatch.setitem(
		__import__('utils.identity_login', fromlist=['IDENTITY_ORIGINS']).IDENTITY_ORIGINS, kind, origin
	)
	config = AppConfig(providers={}, identities={'main': IdentityConfig(kind, proxy='direct')})
	secret = base64.urlsafe_b64encode(os.urandom(32)).decode()
	cache = tmp_path / 'cache' / 'auth-state.enc'
	contexts = []
	manual_count = 0
	blocked = []

	async def route(request_route):
		request = request_route.request
		parsed = urlsplit(request.url)
		if not request.url.startswith(origin + '/'):
			blocked.append(request.url)
			await request_route.abort()
			return
		cookies = (await request.all_headers()).get('cookie', '')
		if parsed.path == '/login':
			if initial_challenge and 'fixture_clearance=complete' not in cookies:
				body = '<script src="/cdn-cgi/challenge-platform/fixture.js"></script><h1>Synthetic verification</h1><form id="challenge-form" method="post" action="/clearance"><button>Continue fixture</button></form>'
			elif 'identity_session=valid' not in cookies:
				body = '<h1>Synthetic login</h1><form method="post" action="/sign-in"><input aria-label="Username"><input aria-label="Password" type="password"><button>Sign in fixture</button></form>'
			else:
				body = '<h1>Synthetic signed-in identity</h1>'
				if kind == 'linuxdo':
					body += discourse_bootstrap()
			await request_route.fulfill(content_type='text/html', body='<link rel="icon" href="data:,">' + body)
		elif parsed.path in {'/clearance', '/sign-in'}:
			assert request.method == 'POST'
			cookie = 'fixture_clearance=complete' if parsed.path == '/clearance' else 'identity_session=valid'
			await request_route.fulfill(
				content_type='text/html',
				headers={'Set-Cookie': cookie + '; Path=/; HttpOnly; Secure; Max-Age=3600; SameSite=Lax'},
				body='<script>location.replace("/login")</script>',
			)
		elif parsed.path == '/session/current.json':
			headers = await request.all_headers()
			assert headers.get('accept') == 'application/json'
			assert headers.get('x-requested-with') == 'XMLHttpRequest'
			payload: dict[str, object] = (
				{'current_user': {'id': 42, 'username': 'fixture-user'}}
				if 'identity_session=valid' in cookies
				else {'error_type': 'not_logged_in', 'errors': ['You need to be logged in to do that.']}
			)
			await request_route.fulfill(
				status=200 if 'identity_session=valid' in cookies else anonymous_status,
				json=payload,
			)
		elif parsed.path == '/settings/profile':
			if 'identity_session=valid' not in cookies:
				await request_route.fulfill(status=302, headers={'Location': '/login'})
			else:
				await request_route.fulfill(
					content_type='text/html',
					body='<meta name="user-login" content="fixture-user"><meta name="octolytics-actor-login" content="fixture-user"><meta name="octolytics-actor-id" content="42">',
				)
		elif parsed.path.startswith('/cdn-cgi/challenge-platform/'):
			await request_route.fulfill(content_type='application/javascript', body='')
		else:
			await request_route.fulfill(status=404, body='No fixture route')

	async with asyncio.timeout(30), async_playwright() as playwright:

		async def launch(settings, **kwargs):
			context = await playwright.chromium.launch_persistent_context(
				str(settings.profile_dir),
				channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None,
				headless=True,
				service_workers='block',
			)
			await context.route('**/*', route)
			await context.set_offline(True)
			contexts.append(context)
			return context

		class Takeover:
			url = ''
			transport = 'desktop'

			async def __aenter__(self):
				nonlocal manual_count
				manual_count += 1
				page = contexts[-1].pages[-1]
				if initial_challenge:
					await page.get_by_role('button', name='Continue fixture', exact=True).click()
				assert len(contexts) == 1 and not page.is_closed()
				await page.get_by_label('Username').fill('fixture-user')
				assert await probe_identity_user(page, kind) is None
				assert not page.is_closed()
				await page.get_by_label('Password').fill('synthetic-password')
				await page.get_by_role('button', name='Sign in fixture', exact=True).click()
				return SimpleNamespace(url='')

			async def __aexit__(self, *args):
				pass

		monkeypatch.setattr('utils.identity_login.launch_login_context', launch)
		monkeypatch.setattr('utils.identity_login.ManualTakeover', lambda seconds: Takeover())
		first_store = SnapshotStore(
			tmp_path / 'first', cache, secret, scope='fixture', compatibility='chromium-fixture'
		)
		first = IdentityLoginRuntime(config, first_store)
		try:
			result = await first.execute('main')
			assert result['user_id'] == '42' and result['username'] == 'fixture-user'
			metadata = first_store.read_record('metadata', state_key(f'identity:{kind}:main'))
			assert metadata is not None
			assert metadata['identity_login']['type'] == kind
		finally:
			first.close()
		second_store = SnapshotStore(
			tmp_path / 'second', cache, secret, scope='fixture', compatibility='chromium-fixture'
		)
		assert second_store.restore() == 'restored'
		second = IdentityLoginRuntime(config, second_store)
		try:
			assert (await second.execute('main'))['user_id'] == '42'
		finally:
			second.close()
		assert manual_count == 1 and len(contexts) == 2
		assert b'identity_session' not in cache.read_bytes()
		assert not blocked


@pytest.mark.asyncio
@pytest.mark.parametrize('attribute', [False, True])
async def test_linuxdo_confirms_page_identity_without_opening_challenged_api(monkeypatch, tmp_path, attribute):
	origin = 'https://identity.fixture.test'
	monkeypatch.setitem(
		__import__('utils.identity_login', fromlist=['IDENTITY_ORIGINS']).IDENTITY_ORIGINS, 'linuxdo', origin
	)
	contexts = []
	probes = []
	blocked = []
	human_task = None

	async def route(request_route):
		request = request_route.request
		if not request.url.startswith(origin + '/'):
			blocked.append(request.url)
			await request_route.abort()
			return
		path = urlsplit(request.url).path
		cookies = (await request.all_headers()).get('cookie', '')
		if path == '/login':
			await request_route.fulfill(
				content_type='text/html',
				body='<link rel="icon" href="data:,"><form id="login-form" method="post" action="/sign-in"><input id="login-account-name" aria-label="Username"><input id="login-account-password" type="password" aria-label="Password"><button>Sign in fixture</button></form>',
			)
		elif path == '/sign-in':
			assert request.method == 'POST'
			await request_route.fulfill(
				content_type='text/html',
				headers={'Set-Cookie': 'identity_session=valid; Path=/; HttpOnly; Secure; SameSite=Lax'},
				body='<script>location.replace("/")</script>',
			)
		elif path == '/':
			assert 'identity_session=valid' in cookies
			await request_route.fulfill(content_type='text/html', body=discourse_bootstrap(attribute=attribute))
		elif path == '/session/current.json':
			probes.append(request.is_navigation_request())
			await request_route.fulfill(
				status=403,
				headers={'cf-mitigated': 'challenge'},
				content_type='text/html',
				body='<title>Just a moment</title><form id="challenge-form">Verification</form>',
			)
		else:
			await request_route.fulfill(status=404)

	async with asyncio.timeout(25), async_playwright() as playwright:

		async def launch(settings, **kwargs):
			context = await playwright.chromium.launch_persistent_context(
				str(settings.profile_dir),
				channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None,
				headless=True,
				service_workers='block',
			)
			await context.route('**/*', route)
			await context.set_offline(True)
			contexts.append(context)
			return context

		async def human():
			page = contexts[0].pages[-1]
			assert await probe_identity_user(page, 'linuxdo') is None
			assert probes == []
			await page.get_by_label('Username').fill('fixture-user')
			await page.get_by_label('Password').fill('synthetic-password')
			await page.get_by_role('button', name='Sign in fixture').click()
			await page.wait_for_url(origin + '/')

		class Takeover:
			async def __aenter__(self):
				nonlocal human_task
				human_task = asyncio.create_task(human())
				return SimpleNamespace(url='')

			async def __aexit__(self, *args):
				if human_task is not None:
					try:
						await asyncio.wait_for(human_task, timeout=5)
					finally:
						if not human_task.done():
							human_task.cancel()
							await asyncio.gather(human_task, return_exceptions=True)

		monkeypatch.setattr('utils.identity_login.launch_login_context', launch)
		monkeypatch.setattr('utils.identity_login.ManualTakeover', lambda seconds: Takeover())
		store = SnapshotStore(
			tmp_path / 'state',
			tmp_path / 'cache' / 'auth-state.enc',
			base64.urlsafe_b64encode(os.urandom(32)).decode(),
			scope='fixture',
			compatibility='browser',
		)
		runtime = IdentityLoginRuntime(
			AppConfig(providers={}, identities={'main': IdentityConfig('linuxdo', proxy='direct')}), store
		)
		try:
			result = await runtime.execute('main')
			assert result['user_id'] == '42'
			assert store.cache_file.exists()
			assert len(contexts) == 1
			assert probes == []
			assert not blocked
		finally:
			runtime.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('variant', ['valid', 'denied', 'public_user', 'duplicate', 'no_actor', 'challenge'])
async def test_linuxdo_bootstrap_requires_authenticated_page_and_never_queries_api(monkeypatch, variant):
	origin = 'https://identity.fixture.test'
	monkeypatch.setitem(
		__import__('utils.identity_login', fromlist=['IDENTITY_ORIGINS']).IDENTITY_ORIGINS, 'linuxdo', origin
	)
	body = discourse_bootstrap()
	if variant == 'public_user':
		body = '<script id="data-preloaded" type="application/json">{"user":{"id":42,"username":"public"}}</script><button id="current-user">User</button>'
	elif variant == 'duplicate':
		body += discourse_bootstrap()
	elif variant == 'no_actor':
		body = body.split('<button')[0]
	elif variant == 'challenge':
		body += '<form id="challenge-form">Verification pending</form>'
	requests = []
	async with async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		try:
			page = await browser.new_page()

			async def route(request_route):
				requests.append(request_route.request.url)
				await request_route.fulfill(
					content_type='text/html', body=body, status=403 if variant == 'denied' else 200
				)

			await page.route('**/*', route)
			await page.goto(origin + '/')
			result = await probe_identity_user(page, 'linuxdo', allow_fetch=False)
			assert result == ({'user_id': '42', 'username': 'fixture-user'} if variant == 'valid' else None)
			assert requests == [origin + '/']
		finally:
			await browser.close()
