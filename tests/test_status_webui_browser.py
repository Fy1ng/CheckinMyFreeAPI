"""Status UI acceptance against synthetic cached balances, with no site requests.

Browser plugin not available. The flow under test is: login -> Status -> cached
balances -> explicit refresh or management -> drafts and expanded details survive.
"""

import json
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import SERVICE, STATIC_ROOT, create_app

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixtures')


def balances():
	return {
		'timezone': 'Asia/Singapore',
		'day': '2026-10-25',
		'refreshing': False,
		'next_refresh_at': '2026-10-25T11:00:00Z',
		'summary': {
			'balance': 30,
			'today_income': 2,
			'today_net_change': -1,
			'account_count': 3,
			'balance_count': 2,
			'fresh_count': 1,
			'income_count': 1,
			'net_change_count': 1,
		},
		'accounts': [
			{
				'id': 'known',
				'name': 'Any-Fy',
				'provider': 'anyrouter',
				'enabled': True,
				'balance': 0,
				'used': 20,
				'today_income': 2,
				'today_net_change': -1,
				'income_source': 'observed',
				'partial': True,
				'updated_at': '2026-10-25T10:00:00Z',
				'stale': False,
				'state': 'ok',
				'reason': 'balance_verified',
			},
			{
				'id': 'stale',
				'name': 'Agent-Fy',
				'provider': 'agentrouter',
				'enabled': True,
				'balance': 30,
				'used': None,
				'today_income': None,
				'today_net_change': None,
				'income_source': None,
				'updated_at': '2026-10-24T10:00:00Z',
				'stale': True,
				'state': 'needs_credentials',
				'reason': 'balance_session_expired',
			},
			{
				'id': 'unknown',
				'name': '<Unknown>',
				'provider': 'anyrouter',
				'enabled': False,
				'balance': None,
				'used': None,
				'today_income': None,
				'today_net_change': None,
				'income_source': None,
				'updated_at': None,
				'stale': True,
				'state': 'disabled',
				'reason': 'ACCOUNT_DISABLED',
			},
		],
		'history': [
			{'day': '2026-10-23', 'balance': 25, 'balance_count': 2, 'today_income': 1, 'today_net_change': 1},
			{'day': '2026-10-24', 'balance': None, 'balance_count': 0, 'today_income': None, 'today_net_change': None},
			{'day': '2026-10-25', 'balance': 30, 'balance_count': 2, 'today_income': 2, 'today_net_change': -1},
		],
	}


@asynccontextmanager
async def status_ui(tmp_path, *, direct=False, mobile=False):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	config, revision = service.store.load()
	config['accounts'] = [
		{
			'id': account_id,
			'name': name,
			'provider': 'anyrouter',
			'auth_type': 'cookie',
			'enabled': True,
			'cookies': 'session=synthetic-cookie',
			'api_user': '42',
		}
		for account_id, name in [('known', 'Any-Fy'), ('stale', 'Agent-Fy')]
	]
	service.store.save(config, revision)
	if not any(resource.canonical == '/status' for resource in app.router.resources()):

		async def status_shell(_):
			return web.FileResponse(STATIC_ROOT / 'index.html')

		app.router.add_get('/status', status_shell)
	fixture = {'payload': balances(), 'fail_read': False, 'fail_refresh': False, 'refresh_bodies': []}
	requests, errors, blocked = [], [], []
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		context = await browser.new_context(
			viewport={'width': 390, 'height': 844} if mobile else {'width': 1440, 'height': 1080}
		)
		origin = str(server.make_url('')).rstrip('/')

		async def guard(route):
			request = route.request
			path = request.url.removeprefix(origin)
			requests.append((request.method, path))
			if not request.url.startswith(origin + '/'):
				blocked.append(request.url)
				await route.abort()
			elif path == '/api/balances':
				await route.fulfill(
					status=503 if fixture['fail_read'] else 200,
					json={'error': 'synthetic-read-error'} if fixture['fail_read'] else fixture['payload'],
				)
			elif path == '/api/balances/refresh':
				fixture['refresh_bodies'].append(json.loads(request.post_data))
				assert request.headers.get('x-csrf-token')
				response: dict = (
					{'error': 'synthetic-busy'} if fixture['fail_refresh'] else {'run': {'id': 1, 'kind': 'balance'}}
				)
				await route.fulfill(
					status=409 if fixture['fail_refresh'] else 202,
					json=response,
				)
			else:
				await route.continue_()

		await context.route('**/*', guard)
		page = await context.new_page()
		page.set_default_timeout(5000)
		page.on('pageerror', lambda error: errors.append(str(error)))
		try:
			await page.goto(origin + ('/status' if direct else '/'))
			await page.get_by_label('管理密码').fill('synthetic-webui-password')
			await page.get_by_role('button', name='登录', exact=True).click()
			await expect(page.locator('#workspace')).to_be_visible()
			if not direct:
				await page.get_by_role('link', name='Status', exact=True).click()
			await expect(page.locator('#balance-summary')).to_contain_text('$30.00')
			yield page, service, fixture, requests
			assert not errors
			assert not blocked
		finally:
			await browser.close()


@pytest.mark.asyncio
async def test_cached_status_distinguishes_zero_unknown_stale_and_preserves_expansion(tmp_path):
	async with status_ui(tmp_path, direct=True) as (page, _, fixture, requests):
		assert page.url.endswith('/status')
		assert await page.title() == '账户 Status | NewAPI'
		await expect(page.locator('#balance-summary')).to_contain_text('已知 2 / 3 个账号')
		await expect(page.locator('#balance-summary')).to_contain_text('1 / 3')
		known = page.locator('[data-balance-account="known"]')
		await expect(known.locator('.account-balance')).to_have_text('$0.00')
		await expect(known).to_contain_text('采集期间已观测入账')
		await expect(known).to_contain_text('不代表全天统计')
		await expect(page.locator('[data-balance-account="unknown"] .account-balance')).to_have_text('未知')
		await expect(page.locator('[data-balance-account="unknown"] h3')).to_have_text('<Unknown>')
		stale = page.locator('[data-balance-account="stale"]')
		await expect(stale).to_contain_text('余额已过期')
		await expect(stale).to_contain_text('保留上次已知余额')
		await stale.get_by_text('查看查询详情', exact=True).click()
		await expect(stale).to_contain_text('监测会话已失效')
		await page.get_by_text('查看每日数据', exact=True).click()
		await expect(page.locator('#balance-history')).to_contain_text('2026-10-24')
		assert await page.locator('#balance-chart svg circle').count() == 2
		assert await page.locator('#balance-chart polyline').count() == 0
		await page.get_by_role('button', name='重新读取', exact=True).click()
		assert await stale.locator('details').get_attribute('open') is not None
		assert await page.locator('#balance-history-details').get_attribute('open') is not None
		fixture['payload']['accounts'][0].update(
			income_source='site', income_partial=False, net_change_partial=True, partial=True
		)
		fixture['payload']['history'] = [day for day in fixture['payload']['history'] if day['balance'] is not None]
		await page.get_by_role('button', name='重新读取', exact=True).click()
		await expect(known.locator('.balance-source')).to_contain_text('站点今日入账')
		await expect(known.locator('.balance-source')).not_to_contain_text('不代表全天统计')
		await expect(known.locator('.balance-source')).to_contain_text('净变化以当日首次采集为基准')
		await expect(page.locator('#balance-history tr')).to_have_count(3)
		assert await page.locator('#balance-chart polyline').count() == 0
		assert fixture['refresh_bodies'] == []
		assert not any(method == 'POST' and path == '/api/runs' for method, path in requests)


@pytest.mark.asyncio
async def test_status_navigation_keeps_management_draft_and_refreshes_only_on_click(tmp_path):
	async with status_ui(tmp_path) as (page, _, fixture, _):
		await page.get_by_role('button', name='刷新余额 Any-Fy', exact=True).click()
		assert fixture['refresh_bodies'] == [{'revision': 1, 'account_id': 'known'}]
		fixture['fail_refresh'] = True
		await page.get_by_role('button', name='刷新余额', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('synthetic-busy')
		await page.get_by_role('link', name='管理面板', exact=True).click()
		await page.get_by_role('button', name='定时与网络', exact=True).click()
		await page.get_by_label(re.compile('^余额采集间隔, 分钟')).fill('120')
		await expect(page.locator('#dirty-status')).to_have_text('有未保存的修改')
		await page.get_by_role('link', name='Status', exact=True).click()
		await expect(page.get_by_role('button', name='刷新余额', exact=True)).to_be_disabled()
		await page.get_by_role('link', name='管理面板', exact=True).click()
		await expect(page.get_by_label(re.compile('^余额采集间隔, 分钟'))).to_have_value('120')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		await page.get_by_role('link', name='Status', exact=True).click()
		await expect(page.get_by_role('button', name='刷新余额', exact=True)).to_be_enabled()
		fixture['fail_read'] = True
		await page.get_by_role('button', name='重新读取', exact=True).click()
		await expect(page.locator('#balances-error')).to_contain_text('已保留上次结果')
		await expect(page.locator('#balance-summary')).to_contain_text('$30.00')


@pytest.mark.asyncio
async def test_mobile_status_fits_and_records_screenshot_when_requested(tmp_path):
	async with status_ui(tmp_path, mobile=True) as (page, _, _, _):
		await expect(page.get_by_role('heading', name='账户 Status', exact=True)).to_be_visible()
		assert await page.evaluate('document.documentElement.scrollWidth <= window.innerWidth')
		await page.get_by_role('button', name='刷新余额', exact=True).focus()
		assert await page.get_by_role('button', name='刷新余额', exact=True).evaluate(
			'(element) => element === document.activeElement'
		)
		folder = os.getenv('CHECKIN_UI_SCREENSHOT_DIR')
		if folder:
			root = Path(folder)
			root.mkdir(parents=True, exist_ok=True)
			await page.screenshot(path=str(root / 'status-mobile.png'), full_page=True)
			await page.set_viewport_size({'width': 1440, 'height': 1080})
			await page.screenshot(path=str(root / 'status-desktop.png'), full_page=True)


@pytest.mark.asyncio
async def test_status_uses_balance_labels_for_balance_jobs(tmp_path):
	async with status_ui(tmp_path) as (page, service, _, _):
		summary = {
			'success_count': 1,
			'total_count': 1,
			'accounts': [
				{
					'id': 'known',
					'name': 'Any-Fy',
					'provider': 'anyrouter',
					'success': True,
					'reason': 'balance_verified',
				}
			],
		}
		service.jobs.db.execute(
			"INSERT INTO runs(state,started_at,finished_at,revision,kind,summary) VALUES ('succeeded',1,2,1,'balance',?)",
			(json.dumps(summary),),
		)
		service.jobs.db.commit()
		await page.get_by_role('link', name='管理面板', exact=True).click()
		await page.get_by_role('button', name='刷新', exact=True).click()
		await expect(page.locator('#runs-list .run-title')).to_contain_text('余额采集')
		await page.get_by_text('查看账号结果和步骤', exact=True).click()
		await expect(page.locator('#runs-list')).to_contain_text('余额已更新')
