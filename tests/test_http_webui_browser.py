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
async def test_cookie_auth_only_accepts_manual_paste_and_keeps_login_guidance(tmp_path):
	async with local_ui(tmp_path) as (page, service, requests):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await expect(page.get_by_label('Cookie', exact=True)).to_be_visible()
		assert await page.get_by_role('button', name='复制提取脚本', exact=True).count() == 0
		assert await page.get_by_label('Cookie 提取脚本', exact=True).count() == 0
		await expect(page.locator('.field-hint').filter(has_text='Application -> Cookies')).to_contain_text(
			'session=复制的值'
		)
		await page.get_by_label('Cookie', exact=True).fill('session=synthetic-manual-cookie')
		await page.get_by_label(re.compile('^目标站点用户 ID')).fill('17')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		assert service.store.load()[0]['accounts'][0]['cookies'] == 'session=synthetic-manual-cookie'
		assert not any(method == 'POST' and path == '/api/runs' for method, path in requests)


@pytest.mark.parametrize('cookie', ['acw_sc__v2=synthetic-waf', 'acw_sc__v2=synthetic-waf; session='])
@pytest.mark.asyncio
async def test_cookie_draft_missing_session_is_actionable_and_never_saved(tmp_path, cookie):
	async with local_ui(tmp_path) as (page, _, requests):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.get_by_label('Cookie', exact=True).fill(cookie)
		await page.get_by_label(re.compile('^目标站点用户 ID')).fill('17')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('Cookie 缺少非空 session')
		await expect(page.get_by_label('Cookie', exact=True)).to_have_value(cookie)
		assert not any(method == 'PUT' for method, _ in requests)
		await page.get_by_label('Cookie', exact=True).fill('session=synthetic-login; acw_sc__v2=synthetic-waf')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')


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
async def test_authenticated_socks5_proxy_fields_save_and_keep_credentials_hidden(tmp_path):
	account_proxy = 'socks5://synthetic-user%40dept:synthetic%3Aproxy%40password@127.0.0.1:1080'
	global_proxy = 'socks5://synthetic-global:synthetic-global-password@127.0.0.1:1081'
	async with local_ui(tmp_path) as (page, service, requests):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.get_by_label('启用此账号', exact=True).uncheck()
		await page.get_by_text('账号代理', exact=True).click()
		await page.get_by_label('代理模式', exact=True).select_option('custom')
		proxy_input = page.locator('.proxy-control input')
		await proxy_input.fill(account_proxy)
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
		await page.get_by_text('账号代理', exact=True).click()
		await expect(proxy_input).to_have_value('')
		await expect(proxy_input).to_have_attribute('placeholder', '已设置, 留空保留')
		assert service.store.public()['config']['accounts'][0]['proxy'] == SECRET_KEEP
		await page.get_by_role('button', name='定时与网络', exact=True).click()
		await expect(page.locator('.field-hint').filter(has_text='认证格式: socks5://')).to_be_visible()
		await page.get_by_label('代理 URL', exact=True).fill(global_proxy)
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
		await expect(page.get_by_label('代理 URL', exact=True)).to_have_value('')
		assert service.store.public()['config']['proxy_url'] == SECRET_KEEP
		await page.get_by_role('button', name=re.compile('^账号')).click()
		await page.get_by_label(re.compile('^账号名称')).fill('代理凭据保留')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 3')
		config, _ = service.store.load()
		assert config['proxy_url'] == global_proxy and config['accounts'][0]['proxy'] == account_proxy
		assert account_proxy.encode() not in (tmp_path / 'webui.sqlite3').read_bytes()
		assert global_proxy.encode() not in (tmp_path / 'webui.sqlite3').read_bytes()
		assert not any(method == 'POST' and path == '/api/runs' for method, path in requests)


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
@pytest.mark.parametrize('single_account', [False, True])
async def test_unknown_job_start_is_not_repeated_and_results_are_actionable(tmp_path, single_account):
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

	async with local_ui(tmp_path, intercept) as (page, service, _):
		if single_account:
			config, revision = service.store.load()
			config['accounts'] = [
				{
					'id': 'a',
					'provider': 'anyrouter',
					'auth_type': 'cookie',
					'cookies': 'session=synthetic',
					'api_user': '17',
				}
			]
			service.store.save(config, revision)
			await page.reload()
		await expect(page.locator('#start-button')).to_be_enabled()
		start = page.locator('[data-account-run="a"]') if single_account else page.locator('#start-button')
		await start.click()
		await expect(page.locator('#global-message')).to_contain_text('未能确认结果')
		await expect(page.locator('#start-button')).to_be_disabled()
		await expect(page.locator('#stop-button')).to_be_disabled()
		await page.get_by_role('button', name='重新读取确认', exact=True).click()
		await expect(page.locator('#stop-button')).to_be_enabled()
		assert len(starts) == 1
		assert starts[0] == ({'revision': 1, 'account_id': 'a'} if single_account else {'revision': 0})

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
async def test_single_account_controls_require_saved_enabled_fresh_idle_configuration(tmp_path):
	starts = []
	running = False
	status_error = False
	attention = {'paused': {'outcome': 'uncertain', 'reason': 'request_result_unknown', 'retry_at': None}}

	async def intercept(route, origin):
		nonlocal running
		request = route.request
		if request.url == origin + '/api/status':
			if status_error:
				await route.abort('failed')
			else:
				await route.fulfill(json={'running': running, 'run': None, 'attention': attention})
			return True
		if request.url == origin + '/api/runs' and request.method == 'POST':
			starts.append(request.post_data_json)
			running = True
			await route.fulfill(json={'started': True})
			return True
		return False

	async with local_ui(tmp_path, intercept) as (page, service, _):
		config, revision = service.store.load()
		config['accounts'] = [
			{
				'id': account_id,
				'provider': 'anyrouter',
				'auth_type': 'cookie',
				'cookies': 'session=synthetic',
				'api_user': str(index + 17),
				'enabled': account_id != 'disabled',
			}
			for index, account_id in enumerate(['first', 'second', 'disabled', 'paused'])
		]
		service.store.save(config, revision)
		await page.reload()
		first = page.locator('[data-account-run="first"]')
		second = page.locator('[data-account-run="second"]')
		await expect(first).to_be_enabled()
		await expect(second).to_be_enabled()
		await expect(page.locator('[data-account-run="disabled"]')).to_be_disabled()
		await expect(page.locator('[data-account-run="paused"]')).to_be_disabled()
		await page.locator('[data-account-id="first"] .card-toggle').click()
		await page.locator('[data-account-id="first"]').get_by_label(re.compile('^账号名称')).fill('已保存账号')
		await expect(first).to_be_disabled()
		await expect(second).to_be_disabled()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
		await expect(first).to_be_enabled()
		await first.click()
		await expect(second).to_be_disabled()
		await expect(page.locator('#start-button')).to_be_disabled()
		assert starts == [{'revision': 2, 'account_id': 'first'}]
		running = False
		status_error = True
		await page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
		await expect(page.locator('#status-error')).to_be_visible()
		await expect(first).to_be_disabled()
		status_error = False
		await page.locator('#retry-status').click()
		await expect(first).to_be_enabled()
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await expect(page.locator('[data-account-run="account-1"]')).to_be_disabled()
		await expect(first).to_be_disabled()
		await page.set_viewport_size({'width': 390, 'height': 844})
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		assert len(starts) == 1


@pytest.mark.asyncio
async def test_run_progress_diagnostics_and_open_details_survive_poll_and_read_failure(tmp_path):
	run: dict = {
		'id': 37,
		'state': 'running',
		'started_at': '2026-10-20T00:00:00Z',
		'summary': {
			'progress': {
				'total': 2,
				'completed': 0,
				'active_account': {
					'id': 'first',
					'name': '首账号',
					'provider': 'anyrouter',
					'stage': 'checkin',
					'at': '2026-10-20T00:00:01Z',
					'method': 'POST',
					'path': '/api/user/sign_in',
				},
			},
			'accounts': [],
		},
	}
	read_error = False
	old_runs = [
		{'id': value, 'state': 'succeeded', 'started_at': '2026-10-19T00:00:00Z'} for value in range(36, 24, -1)
	]

	async def intercept(route, origin):
		if route.request.url == origin + '/api/status':
			await route.fulfill(json={'running': run['state'] == 'running', 'run': run, 'next_run_at': None})
			return True
		if route.request.url == origin + '/api/runs' and route.request.method == 'GET':
			if read_error:
				await route.abort('failed')
			else:
				await route.fulfill(json={'runs': [run, *old_runs]})
			return True
		return False

	async with local_ui(tmp_path, intercept) as (page, _, requests):
		await expect(page.locator('#task-progress')).to_contain_text('已处理 0 / 2 个账号')
		await expect(page.locator('#task-progress')).to_contain_text('首账号 / 发送签到请求 / POST / /api/user/sign_in')
		row = page.locator('[data-run-id="37"]')
		details = row.locator('.run-details')
		await details.locator('summary').click()
		await details.locator('summary').focus()
		scroll = await page.evaluate("""() => {
			window.savedRunRoot = document.querySelector('[data-run-id="37"]');
			window.savedRunSummary = window.savedRunRoot.querySelector('summary');
			const list = document.getElementById('runs-list');
			list.scrollTop = 30;
			return list.scrollTop;
		}""")
		run['summary']['progress']['completed'] = 1
		run['summary']['progress']['active_account'] = {
			'id': 'second',
			'name': '次账号',
			'stage': 'verify_identity',
			'at': '2026-10-20T00:00:03Z',
			'method': 'GET',
			'path': '/api/user/self',
		}
		run['summary']['accounts'] = [
			{
				'id': 'first',
				'name': '首账号',
				'outcome': 'uncertain',
				'reason': 'request_result_unknown',
				'verification_reason': 'network_error',
				'diagnostic': {
					'stage': 'checkin',
					'method': 'POST',
					'path': '/api/user/sign_in',
					'http_status': 503,
					'error_type': 'ReadTimeout',
					'timeout_seconds': 30,
				},
				'steps': [
					{'stage': 'verify_identity', 'at': '2026-10-20T00:00:01Z', 'state': 'completed'},
					{'stage': 'checkin', 'at': '2026-10-20T00:00:02Z', 'state': 'failed', 'error_type': 'ReadTimeout'},
				],
			}
		]
		await page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
		await expect(page.locator('#task-progress')).to_contain_text('已处理 1 / 2 个账号')
		await expect(details).to_have_attribute('open', '')
		await expect(details).to_contain_text('代码: request_result_unknown')
		await expect(details).to_contain_text('结果核验: 网络请求失败')
		await expect(details).to_contain_text(
			'诊断: 发送签到请求 / POST / /api/user/sign_in / HTTP 503 / ReadTimeout / 超时设置 30 秒'
		)
		await expect(details.locator('.run-steps')).to_contain_text('发送签到请求: 失败')
		assert await page.evaluate(
			'window.savedRunRoot === document.querySelector(\'[data-run-id="37"]\') && document.activeElement === window.savedRunSummary'
		)
		assert await page.locator('#runs-list').evaluate('(el) => el.scrollTop') == scroll
		read_error = True
		await page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
		await expect(page.locator('#runs-error')).to_contain_text('已保留上次读取的记录')
		await expect(details).to_have_attribute('open', '')
		assert await page.evaluate('document.activeElement === window.savedRunSummary')
		read_error = False
		await page.locator('#retry-runs').click()
		await expect(page.locator('#runs-error')).to_be_hidden()
		await details.locator('summary').click()
		await page.locator('#refresh-runs').click()
		await expect(details).not_to_have_attribute('open', '')
		await details.locator('summary').click()
		run['state'] = 'interrupted'
		await page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
		await expect(page.locator('#task-progress')).to_contain_text('最后阶段: 次账号')
		await expect(details.locator('.run-active')).to_contain_text('最后处理 次账号')
		await expect(details).to_have_attribute('open', '')
		await page.set_viewport_size({'width': 390, 'height': 844})
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		assert not any(method == 'POST' and path == '/api/runs' for method, path in requests)


@pytest.mark.asyncio
async def test_acw_progress_attempts_and_stop_reason_are_readable_without_cookie_values(tmp_path):
	step = {
		'stage': 'acw_verification',
		'state': 'failed',
		'request_attempt': 3,
		'max_attempts': 3,
		'acw_challenges': 3,
		'method': 'POST',
		'path': '/api/user/login',
		'http_status': 200,
		'cookie_value': 'synthetic-sensitive-cookie',
	}
	run = {
		'id': 38,
		'state': 'needs_attention',
		'summary': {
			'progress': {'total': 1, 'completed': 1, 'active_account': None},
			'accounts': [
				{
					'id': 'saved',
					'name': 'ACW fixture',
					'outcome': 'blocked',
					'reason': 'acw_challenge_limit',
					'diagnostic': step,
					'steps': [step],
				}
			],
		},
	}

	async def intercept(route, origin):
		if route.request.url == origin + '/api/runs' and route.request.method == 'GET':
			await route.fulfill(json={'runs': [run]})
			return True
		return False

	async with local_ui(tmp_path, intercept) as (page, _, _):
		details = page.locator('[data-run-id="38"] .run-details')
		await details.locator('summary').click()
		await expect(details).to_contain_text('达到 3 次请求上限')
		await expect(details).to_contain_text('处理 acw 访问验证')
		await expect(details).to_contain_text('请求 3 / 3')
		await expect(details).to_contain_text('acw 验证 3 次')
		await expect(details).not_to_contain_text('synthetic-sensitive-cookie')
		await expect(details.locator('.step-failed')).to_have_count(1)


@pytest.mark.parametrize('challenge_state', ['verification_required', 'failed'])
@pytest.mark.asyncio
async def test_acw_intermediate_status_is_clear_for_new_and_existing_records(tmp_path, challenge_state):
	request = {'method': 'POST', 'path': '/api/user/login', 'http_status': 200}
	run = {
		'id': 39,
		'state': 'needs_attention',
		'summary': {
			'accounts': [
				{
					'id': 'recovered',
					'name': '恢复成功',
					'success': True,
					'outcome': 'success',
					'reason': 'checkin_verified',
					'steps': [
						{**request, 'stage': 'password_login', 'state': challenge_state},
						{**request, 'stage': 'acw_verification', 'state': 'completed'},
						{**request, 'stage': 'password_login', 'state': 'completed'},
					],
				},
				{
					'id': 'wrong-password',
					'name': '密码错误',
					'success': False,
					'outcome': 'needs_credentials',
					'reason': 'credentials_rejected',
					'steps': [
						{**request, 'stage': 'password_login', 'state': 'failed'},
					],
				},
			]
		},
	}

	async def intercept(route, origin):
		if route.request.url == origin + '/api/runs' and route.request.method == 'GET':
			await route.fulfill(json={'runs': [run]})
			return True
		return False

	async with local_ui(tmp_path, intercept) as (page, _, _):
		details = page.locator('[data-run-id="39"] .run-details')
		await details.locator('summary').click()
		recovered, rejected = details.locator('.run-account').nth(0), details.locator('.run-account').nth(1)
		await expect(recovered.locator('.run-steps li').nth(0)).to_contain_text('账号密码登录: 需要访问验证')
		await expect(recovered.locator('.step-failed')).to_have_count(0)
		await expect(rejected.locator('.run-steps')).to_contain_text('账号密码登录: 失败')
		await expect(rejected.locator('.step-failed')).to_have_count(1)


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
