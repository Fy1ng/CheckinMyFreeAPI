"""HTTP-only form and request safety, using synthetic local fixtures."""

import os
import re
from contextlib import asynccontextmanager

import pytest
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import SERVICE, create_app
from server.config_store import SECRET_KEEP

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixtures')


@asynccontextmanager
async def local_ui(tmp_path, intercept=None):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		context = await browser.new_context(viewport={'width': 1440, 'height': 1080})
		origin = str(server.make_url('')).rstrip('/')
		requests, blocked, errors = [], [], []

		async def guard(route):
			request = route.request
			requests.append((request.method, request.url.removeprefix(origin)))
			if not request.url.startswith(origin + '/'):
				blocked.append(request.url)
				await route.abort()
			elif intercept and await intercept(route, origin):
				return
			else:
				await route.continue_()

		await context.route('**/*', guard)
		page = await context.new_page()
		page.set_default_timeout(5000)
		page.on('pageerror', lambda error: errors.append(str(error)))
		try:
			await page.goto(origin)
			await page.get_by_label('管理密码').fill('synthetic-webui-password')
			await page.get_by_role('button', name='登录', exact=True).click()
			await expect(page.locator('#workspace')).to_be_visible()
			yield page, service, requests
			assert not errors
			assert not blocked
			assert not any(path.startswith(('/api/identities', '/manual/')) for _, path in requests)
		finally:
			await browser.close()


@pytest.mark.asyncio
async def test_cookie_script_copy_is_local_and_only_available_for_cookie_auth(tmp_path):
	async with local_ui(tmp_path) as (page, service, requests):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.get_by_label('Cookie', exact=True).fill('session=synthetic-saved-secret')
		await page.get_by_label(re.compile('^目标站点用户 ID')).fill('17')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		await page.evaluate("""() => {
			Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
				writeText: async (value) => { window.copiedScript = value; }
			} });
		}""")
		request_count = len(requests)
		await page.get_by_role('button', name='复制提取脚本', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('已复制提取脚本')
		script = await page.evaluate('window.copiedScript')
		assert script == await page.get_by_label('Cookie 提取脚本', exact=True).input_value()
		assert 'synthetic-saved-secret' not in script and SECRET_KEEP not in script
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		await expect(page.locator('#save-button')).to_be_disabled()
		await page.get_by_label('Cookie', exact=True).fill('session=synthetic-draft-secret')
		await page.get_by_role('button', name='复制提取脚本', exact=True).click()
		assert await page.evaluate('window.copiedScript') == script
		await expect(page.get_by_label('Cookie', exact=True)).to_have_value('session=synthetic-draft-secret')
		assert not any(method != 'GET' for method, _ in requests[request_count:])
		assert not service.jobs.history()
		await expect(page.locator('.field-hint').filter(has_text='无法读取 HttpOnly Cookie')).to_be_visible()
		await page.get_by_label('认证方式').select_option('password')
		await expect(page.get_by_role('button', name='复制提取脚本', exact=True)).to_have_count(0)
		await page.get_by_label(re.compile('^目标站点(?!用户)')).select_option('agentrouter')
		await expect(page.get_by_role('button', name='复制提取脚本', exact=True)).to_have_count(0)


@pytest.mark.parametrize('clipboard_available', [False, True])
@pytest.mark.asyncio
async def test_cookie_script_copy_failure_exposes_readonly_selected_script(tmp_path, clipboard_available):
	async with local_ui(tmp_path) as (page, _, requests):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.evaluate(
			"""(available) => {
			Object.defineProperty(navigator, 'clipboard', { configurable: true, value: available
				? { writeText: async () => { throw new Error('synthetic permission denial'); } }
				: undefined });
		}""",
			clipboard_available,
		)
		request_count = len(requests)
		await page.get_by_role('button', name='复制提取脚本', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('请手动复制')
		script = page.get_by_label('Cookie 提取脚本', exact=True)
		await expect(script).to_be_visible()
		assert await script.evaluate(
			'(el) => el.readOnly && el.selectionStart === 0 && el.selectionEnd === el.value.length'
		)
		assert not any(method != 'GET' for method, _ in requests[request_count:])
		await page.set_viewport_size({'width': 390, 'height': 844})
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')


@pytest.mark.asyncio
async def test_cookie_extraction_script_on_isolated_target_origin(tmp_path):
	async with local_ui(tmp_path) as (page, _, _):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		script = await page.get_by_label('Cookie 提取脚本', exact=True).input_value()
		context = await page.context.browser.new_context()
		target_requests, logs = [], []

		async def synthetic_site(route):
			target_requests.append((route.request.method, route.request.url))
			if route.request.url == 'https://anyrouter.top/':
				await route.fulfill(content_type='text/html', body='<!doctype html><link rel="icon" href="data:,">')
			else:
				await route.abort()

		try:
			await context.route('**/*', synthetic_site)
			await context.add_cookies(
				[
					{
						'name': 'session',
						'value': 'synthetic-readable-cookie',
						'url': 'https://anyrouter.top/',
						'secure': True,
					},
					{
						'name': 'hidden',
						'value': 'synthetic-httponly-cookie',
						'url': 'https://anyrouter.top/',
						'httpOnly': True,
						'secure': True,
					},
				]
			)
			target = await context.new_page()
			target.on('console', lambda message: logs.append(message.text))
			await target.goto('https://anyrouter.top/')
			await target.evaluate('() => { window.copy = (value) => { window.copiedCookie = value; }; }')
			await target.evaluate(script)
			assert await target.evaluate('window.copiedCookie') == 'session=synthetic-readable-cookie'
			assert '不包含 HttpOnly Cookie' in logs[-1]
			await target.evaluate("""() => {
				delete window.copy;
				Object.defineProperty(navigator, 'clipboard', { configurable: true, value: {
					writeText: async (value) => { window.copiedCookie = value; }
				} });
				window.copiedCookie = 'preserved';
			}""")
			await target.evaluate(script)
			assert await target.evaluate('window.copiedCookie') == 'session=synthetic-readable-cookie'
			await target.evaluate("""() => {
				window.copiedCookie = 'preserved';
				navigator.clipboard.writeText = async () => { throw new Error('synthetic denial'); };
			}""")
			await target.evaluate(script)
			assert await target.evaluate('window.copiedCookie') == 'preserved'
			assert '无法写入剪贴板' in logs[-1]
			await context.clear_cookies(name='session')
			await target.evaluate(script)
			assert await target.evaluate('window.copiedCookie') == 'preserved'
			assert '未读取到 Cookie' in logs[-1]
			assert not any(
				'synthetic-readable-cookie' in entry or 'synthetic-httponly-cookie' in entry for entry in logs
			)
			assert target_requests == [('GET', 'https://anyrouter.top/')]
			page.on('console', lambda message: logs.append(message.text))
			await page.evaluate('() => { window.copy = () => { throw new Error("must not read WebUI cookies"); }; }')
			await page.evaluate(script)
			assert '请在已登录的 https://anyrouter.top 页面执行' in logs[-1]
		finally:
			await context.close()


@pytest.mark.asyncio
async def test_http_auth_choices_draft_switching_and_incomplete_disabled_account(tmp_path):
	async with local_ui(tmp_path) as (page, service, requests):
		assert await page.locator('[data-tab]').count() == 3
		assert await page.locator('[data-tab="identities"], [data-tab="providers"], #manual-link').count() == 0
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		assert await page.get_by_label('认证方式').locator('option').all_text_contents() == [
			'已有 Cookie',
			'站点账号密码',
		]
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('需要填写Cookie')
		assert not any(method == 'PUT' for method, _ in requests)
		await page.get_by_label('Cookie', exact=True).fill('session=synthetic-draft')
		await page.get_by_label(re.compile('^目标站点用户 ID')).fill('17')
		await page.get_by_label('认证方式').select_option('password')
		await expect(page.get_by_label(re.compile('^目标站点用户 ID'))).to_have_value('17')
		await page.get_by_label(re.compile('^站点登录账号')).fill('fixture-user')
		await page.get_by_label('站点密码', exact=True).fill('synthetic-draft-password')
		await page.get_by_label(re.compile('^目标站点(?!用户)')).select_option('agentrouter')
		assert await page.get_by_label('认证方式').locator('option').all_text_contents() == ['系统访问令牌']
		await expect(page.get_by_label('系统访问令牌', exact=True)).to_have_value('')
		await expect(page.get_by_label(re.compile('^目标站点用户 ID'))).to_have_value('')
		await page.get_by_label(re.compile('^目标站点(?!用户)')).select_option('anyrouter')
		await expect(page.get_by_label('Cookie', exact=True)).to_have_value('')
		await page.get_by_label('启用此账号', exact=True).uncheck()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
		account = service.store.load()[0]['accounts'][0]
		assert account['auth_type'] == 'cookie' and not account['enabled']
		assert not any(account.get(key) for key in ('password', 'username', 'cookies', 'system_access_token'))
		assert not service.jobs.history()


@pytest.mark.asyncio
async def test_http_account_secret_retention_clear_folded_draft_and_mobile(tmp_path):
	async with local_ui(tmp_path) as (page, service, _):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.get_by_label(re.compile('^目标站点(?!用户)')).select_option('agentrouter')
		await page.get_by_label('系统访问令牌', exact=True).fill('synthetic-system-access-token')
		await page.get_by_label(re.compile('^目标站点用户 ID')).fill('42')
		await page.get_by_label(re.compile('^账号名称')).fill('Agent fixture')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
		await expect(page.get_by_label('系统访问令牌', exact=True)).to_have_value('')
		assert service.store.public()['config']['accounts'][0]['system_access_token'] == SECRET_KEEP
		assert b'synthetic-system-access-token' not in (tmp_path / 'webui.sqlite3').read_bytes()
		await page.get_by_label(re.compile('^账号名称')).fill('草稿保持')
		toggle = page.locator('.card-toggle')
		await toggle.click()
		await expect(toggle).to_have_attribute('aria-expanded', 'false')
		await page.get_by_role('button', name='定时与网络', exact=True).click()
		assert await page.get_by_label(re.compile('^HTTP 超时')).count() == 1
		assert await page.get_by_label(re.compile('浏览器|无头')).count() == 0
		await page.get_by_role('button', name=re.compile('^账号')).click()
		await expect(toggle).to_have_attribute('aria-expanded', 'false')
		await toggle.focus()
		await page.keyboard.press('Enter')
		await expect(page.get_by_label(re.compile('^账号名称'))).to_have_value('草稿保持')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
		assert service.store.load()[0]['accounts'][0]['system_access_token'] == 'synthetic-system-access-token'
		await page.get_by_label('启用此账号', exact=True).uncheck()
		secret = page.get_by_label('系统访问令牌', exact=True).locator('..')
		await secret.get_by_role('button', name='清除', exact=True).click()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 3')
		assert service.store.load()[0]['accounts'][0]['system_access_token'] == ''
		await page.set_viewport_size({'width': 390, 'height': 844})
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		await page.reload()
		await expect(page.locator('.card-toggle')).to_have_attribute('aria-expanded', 'false')
		await page.goto(str(page.url).split('?')[0] + '?account=account-1')
		await expect(page.locator('.card-toggle')).to_have_attribute('aria-expanded', 'true')
		await expect(page.get_by_label(re.compile('^账号名称'))).to_have_value('草稿保持')


@pytest.mark.asyncio
async def test_unknown_config_save_locks_until_reload_without_losing_draft(tmp_path):
	writes = []

	async def intercept(route, origin):
		if route.request.url == origin + '/api/config' and route.request.method == 'PUT':
			writes.append(route.request.post_data_json)
			await route.abort('failed')
			return True
		return False

	async with local_ui(tmp_path, intercept) as (page, _, _):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.get_by_label('启用此账号', exact=True).uncheck()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('未能确认结果')
		await expect(page.locator('#save-button')).to_be_disabled()
		await expect(page.locator('#start-button')).to_be_disabled()
		assert len(writes) == 1
		await expect(page.locator('.config-card')).to_have_count(1)
		page.once('dialog', lambda dialog: dialog.accept())
		await page.get_by_role('button', name='重新读取确认', exact=True).click()
		await expect(page.locator('.config-card')).to_have_count(0)
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		assert len(writes) == 1


@pytest.mark.asyncio
async def test_unknown_job_start_is_not_repeated_and_results_are_actionable(tmp_path):
	starts = []
	running = False
	run = None

	async def intercept(route, origin):
		nonlocal running, run
		request = route.request
		if request.url == origin + '/api/runs' and request.method == 'POST':
			starts.append(request.post_data_json)
			running = True
			run = {'id': 7, 'state': 'running', 'started_at': '2026-10-20T00:00:00Z'}
			await route.abort('failed')
			return True
		if request.url == origin + '/api/status':
			await route.fulfill(json={'running': running, 'run': run, 'next_run_at': None})
			return True
		if request.url == origin + '/api/runs':
			await route.fulfill(json={'runs': [run] if run else []})
			return True
		return False

	async with local_ui(tmp_path, intercept) as (page, _, _):
		await expect(page.locator('#start-button')).to_be_enabled()
		await page.locator('#start-button').click()
		await expect(page.locator('#global-message')).to_contain_text('未能确认结果')
		await expect(page.locator('#start-button')).to_be_disabled()
		await expect(page.locator('#stop-button')).to_be_disabled()
		await page.get_by_role('button', name='重新读取确认', exact=True).click()
		await expect(page.locator('#stop-button')).to_be_enabled()
		assert len(starts) == 1

		running = False
		run = {
			'id': 7,
			'state': 'needs_attention',
			'started_at': '2026-10-20T00:00:00Z',
			'summary': {
				'accounts': [
					{
						'id': 'a',
						'name': 'Any fixture',
						'provider': 'anyrouter',
						'success': False,
						'outcome': 'blocked',
						'reason': 'interactive_verification_required',
					},
					{
						'id': 'b',
						'name': 'Agent fixture',
						'provider': 'agentrouter',
						'success': True,
						'outcome': 'success',
						'reason': 'user_info_requested_reward_unverified',
					},
					{
						'id': 'c',
						'name': 'Rate fixture',
						'success': False,
						'outcome': 'skipped',
						'reason': 'ACCOUNT_PAUSED',
						'pending_outcome': 'rate_limited',
						'pending_reason': 'rate_limited',
						'retry_after_seconds': 120,
					},
					{
						'id': 'd',
						'name': 'Unknown fixture',
						'success': False,
						'outcome': 'uncertain',
						'reason': 'request_result_unknown',
					},
				]
			},
		}
		await page.locator('#refresh-runs').click()
		await page.locator('.run-details summary').click()
		await expect(page.locator('#runs-list')).to_contain_text('请在本机处理或更新 Cookie')
		await expect(page.locator('#runs-list')).to_contain_text('奖励请以站点记录为准')
		await expect(page.locator('#runs-list')).to_contain_text('至少等待 120 秒')
		await expect(page.locator('#runs-list')).to_contain_text('请先到站点核对是否已执行')
		assert len(starts) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('unknown_result', [False, True])
async def test_uncertain_account_requires_explicit_confirmation_and_never_auto_runs(tmp_path, unknown_result):
	attention = {'saved': {'outcome': 'uncertain', 'reason': 'request_result_unknown', 'retry_at': None}}
	running = False
	resolved, confirmations = [], []

	async def intercept(route, origin):
		request = route.request
		if request.url == origin + '/api/status':
			await route.fulfill(json={'running': running, 'run': None, 'attention': attention})
			return True
		if request.url == origin + '/api/accounts/resolve':
			assert request.method == 'POST' and request.headers.get('x-csrf-token')
			resolved.append(request.post_data_json)
			attention.clear()
			if unknown_result:
				await route.abort('failed')
			else:
				await route.fulfill(json={'resolved': True})
			return True
		return False

	async with local_ui(tmp_path, intercept) as (page, service, requests):
		config, revision = service.store.load()
		config['accounts'] = [{'id': 'saved', 'provider': 'anyrouter', 'auth_type': 'cookie', 'enabled': False}]
		service.store.save(config, revision)
		await page.reload()
		await page.locator('.card-toggle').click()
		resolve = page.get_by_role('button', name='已核对结果, 解除暂停', exact=True)
		await expect(resolve).to_be_enabled()
		await page.get_by_label(re.compile('^账号名称')).fill('修改中的账号')
		await expect(resolve).to_be_disabled()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
		await expect(resolve).to_be_enabled()
		running = True
		await page.reload()
		await page.locator('.card-toggle').click()
		await expect(resolve).to_be_disabled()
		running = False
		await page.reload()
		await page.locator('.card-toggle').click()
		await expect(resolve).to_be_enabled()
		page.once('dialog', lambda dialog: dialog.dismiss())
		await resolve.click()
		assert not resolved

		async def confirm(dialog):
			confirmations.append(dialog.message)
			await dialog.accept()

		page.once('dialog', confirm)
		await resolve.click()
		assert confirmations and '上次写请求可能已经完成' in confirmations[0]
		assert resolved == [{'account_id': 'saved', 'revision': 2}]
		if unknown_result:
			await expect(page.locator('#global-message')).to_contain_text('未能确认结果')
			await expect(page.locator('#start-button')).to_be_disabled()
			await expect(resolve).to_be_disabled()
			await page.get_by_role('button', name='重新读取确认', exact=True).click()
			await expect(page.locator('#global-message')).to_contain_text('没有暂停记录')
		else:
			await expect(page.locator('#global-message')).to_contain_text('本次没有执行签到')
		await expect(resolve).to_be_hidden()
		assert len(resolved) == 1
		assert not any(method == 'POST' and path == '/api/runs' for method, path in requests)
