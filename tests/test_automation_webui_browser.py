"""Automation UI uses synthetic APIs and never delivers real notifications.

Browser plugin not available. The tested flow is login -> configure Cron and
alerts -> save -> Status health -> explicit summary send -> observed outcome.
"""

import copy
import json
import os
import re
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import create_app

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixtures')


def fixture_config():
	return {
		'schema_version': 2,
		'accounts': [
			{
				'id': 'one',
				'name': 'Any Test',
				'provider': 'anyrouter',
				'auth_type': 'cookie',
				'enabled': True,
				'cookies': '__UNCHANGED_SECRET__',
				'api_user': '42',
			}
		],
		'notifications': {},
		'proxy_url': '',
		'schedule': {'enabled': False, 'interval_minutes': 360},
		'monitoring': {'enabled': True, 'interval_minutes': 60},
		'http': {'timeout_seconds': 30},
		'webui_url': '',
	}


def fixture_balances():
	return {
		'timezone': 'Asia/Singapore',
		'day': '2026-10-25',
		'refreshing': False,
		'next_refresh_at': '2026-10-25T12:00:00Z',
		'summary': {
			'balance': 2,
			'today_income': 1,
			'today_net_change': 0.5,
			'account_count': 1,
			'balance_count': 1,
			'fresh_count': 1,
			'income_count': 1,
			'net_change_count': 1,
		},
		'accounts': [
			{
				'id': 'one',
				'name': 'Any Test',
				'provider': 'anyrouter',
				'enabled': True,
				'balance': 2,
				'used': 1,
				'today_income': 1,
				'today_net_change': 0.5,
				'income_source': 'observed',
				'partial': True,
				'updated_at': '2026-10-25T11:00:00Z',
				'stale': False,
				'state': 'ok',
				'reason': None,
			}
		],
		'history': [],
	}


def fixture_automation():
	return {
		'timezone': 'Asia/Singapore',
		'day': '2026-10-25',
		'health': [
			{
				'account_id': 'one',
				'scope': 'checkin',
				'state': 'uncertain',
				'reason': 'WORKER_INTERRUPTED_RESULT_UNKNOWN',
				'failure_since': '2026-10-24T11:00:00Z',
				'last_failure_at': '2026-10-24T11:00:00Z',
				'last_success_at': None,
				'recovered_at': None,
				'consecutive_failures': 1,
			},
			{
				'account_id': 'one',
				'scope': 'balance',
				'state': 'healthy',
				'reason': 'balance_refreshed',
				'failure_since': None,
				'last_success_at': '2026-10-25T11:00:00Z',
				'recovered_at': None,
				'consecutive_failures': 0,
			},
		],
		'notifications': [
			{'id': 1, 'kind': 'low_balance', 'state': 'accepted', 'created_at': '2026-10-25T10:00:00Z'},
			{'id': 2, 'kind': 'recovery', 'state': 'unknown', 'created_at': '2026-10-25T10:30:00Z'},
			{
				'id': 3,
				'kind': 'daily_summary',
				'state': 'partial',
				'created_at': '2026-10-25T10:40:00Z',
				'delivery': {
					'channels': [
						{'channel': 'Fy1Push', 'state': 'accepted', 'error_code': None},
						{'channel': 'Email', 'state': 'failed', 'error_code': 'notification_rejected'},
					]
				},
			},
		],
		'daily_summary': {'last_day': '2026-10-24', 'next_at': '2026-10-25T15:55:00Z', 'last_state': 'accepted'},
	}


@asynccontextmanager
async def automation_ui(tmp_path, *, direct=False, mobile=False):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	fixture = {
		'config': fixture_config(),
		'revision': 1,
		'balances': fixture_balances(),
		'automation': fixture_automation(),
		'saves': [],
		'sends': [],
		'send_status': 202,
		'run': None,
	}
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
			elif path == '/api/config':
				if request.method == 'PUT':
					body = json.loads(request.post_data)
					assert request.headers.get('x-csrf-token')
					fixture['saves'].append(copy.deepcopy(body))
					fixture['config'] = body['config']
					fixture['revision'] += 1
				await route.fulfill(json={'config': fixture['config'], 'revision': fixture['revision']})
			elif path == '/api/status':
				await route.fulfill(
					json={
						'running': False,
						'run': fixture['run'],
						'attention': {},
						'next_run_at': '2026-10-26T00:00:00Z',
					}
				)
			elif path == '/api/runs':
				await route.fulfill(json={'runs': [fixture['run']] if fixture['run'] else []})
			elif path == '/api/balances':
				await route.fulfill(json=fixture['balances'])
			elif path == '/api/automation':
				await route.fulfill(json=fixture['automation'])
			elif path == '/api/automation/summary':
				assert request.headers.get('x-csrf-token')
				fixture['sends'].append(json.loads(request.post_data))
				fixture['run'] = {
					'id': 8,
					'kind': 'summary',
					'state': 'succeeded',
					'started_at': '2026-10-25T11:00:00Z',
					'finished_at': '2026-10-25T11:00:01Z',
					'summary': {},
				}
				await route.fulfill(
					status=fixture['send_status'],
					json={'run': fixture['run']} if fixture['send_status'] == 202 else {'error': '发送结果待确认'},
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
			yield page, fixture, requests
			assert not errors and not blocked
		finally:
			await browser.close()


async def test_cron_mode_presets_validation_and_save_preserve_interval(tmp_path):
	async with automation_ui(tmp_path) as (page, fixture, _):
		await page.get_by_role('button', name='定时与网络', exact=True).click()
		await expect(page.get_by_label(re.compile('^签到计划方式'))).to_have_value('interval')
		await page.get_by_label(re.compile('^签到计划方式')).select_option('cron')
		await page.get_by_role('button', name='每天 08:00 和 20:00', exact=True).click()
		await expect(page.get_by_label(re.compile('^Cron 表达式'))).to_have_value('0 8,20 * * *')
		await page.get_by_label(re.compile('^Cron 表达式')).fill('bad cron')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('需要包含 5 个字段')
		assert fixture['saves'] == []
		await page.get_by_label(re.compile('^Cron 表达式')).fill('0 8 * * *')
		await page.get_by_label('启用定时签到', exact=True).check()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		assert fixture['saves'][0]['config']['schedule'] == {
			'enabled': True,
			'mode': 'cron',
			'interval_minutes': 360,
			'cron': '0 8 * * *',
		}
		await expect(page.locator('[data-next-checkin]')).to_contain_text('UTC+8')
		assert fixture['sends'] == []


async def test_notification_preferences_and_account_threshold_support_decimal_and_inheritance(tmp_path):
	async with automation_ui(tmp_path) as (page, fixture, _):
		await page.get_by_role('button', name='通知渠道', exact=True).click()
		await page.get_by_label('启用低余额告警', exact=True).check()
		await page.get_by_label(re.compile('^全局低余额阈值')).fill('0.75')
		await page.get_by_label(re.compile('^低余额提醒冷却, 分钟')).fill('90')
		await page.get_by_label('启用故障恢复通知', exact=True).check()
		await page.get_by_label('启用每日日报', exact=True).check()
		await page.get_by_label(re.compile(r'^每日日报时间, UTC\+8')).fill('22:30')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		preferences = fixture['saves'][-1]['config']['automation']
		assert preferences['low_balance'] == {'enabled': True, 'threshold': 0.75, 'cooldown_minutes': 90}
		assert preferences['recovery']['enabled'] is True
		assert preferences['daily_summary'] == {'enabled': True, 'time': '22:30'}
		assert fixture['sends'] == []
		await page.get_by_role('button', name='账号', exact=False).filter(has_text='账号').first.click()
		await page.locator('[data-account-id="one"] .card-toggle').click()
		await page.get_by_text('账号告警', exact=True).click()
		threshold = page.get_by_label(re.compile('^低余额阈值, 站内美元额度'))
		await threshold.fill('-1')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('低余额阈值需要为')
		assert len(fixture['saves']) == 1
		await threshold.fill('2.5')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		assert fixture['saves'][-1]['config']['accounts'][0]['low_balance_threshold'] == 2.5
		await page.get_by_text('账号告警', exact=True).click()
		await page.get_by_label(re.compile('^低余额阈值, 站内美元额度')).fill('')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		assert fixture['saves'][-1]['config']['accounts'][0]['low_balance_threshold'] is None


async def test_status_separates_health_scopes_and_notification_acceptance_from_delivery(tmp_path):
	async with automation_ui(tmp_path, direct=True) as (page, fixture, _):
		assert page.url.endswith('/status') and await page.title() == '账户 Status | NewAPI'
		health = page.locator('[data-balance-account="one"] .account-health')
		await expect(health).to_contain_text('签到: 结果待核对, 持续')
		await expect(health).to_contain_text('余额查询: 正常')
		await expect(health).not_to_contain_text('签到: 已恢复')
		await expect(page.locator('#automation-events')).to_contain_text('设备送达待确认')
		await expect(page.locator('#automation-events')).to_contain_text('发送结果待确认, 不自动重发')
		await expect(page.locator('#automation-events')).to_contain_text('部分渠道已接收')
		await page.get_by_text('查看渠道结果', exact=True).click()
		await expect(page.locator('#automation-events')).to_contain_text('Email: 发送失败 / 渠道拒绝通知')
		await page.get_by_role('link', name='管理面板', exact=True).click()
		async with page.expect_response(lambda response: response.url.endswith('/api/automation')):
			await page.get_by_role('link', name='Status', exact=True).click()
		assert await page.locator('.automation-delivery-details').get_attribute('open') is not None
		await expect(page.locator('#daily-summary-status')).to_contain_text('UTC+8')
		fixture['balances']['accounts'][0].update(
			balance=None, updated_at=None, stale=True, state='needs_credentials', reason='balance_session_required'
		)
		await page.get_by_role('button', name='重新读取', exact=True).click()
		await expect(page.locator('[data-balance-account="one"]')).to_contain_text('待更新会话')
		await expect(page.locator('[data-balance-account="one"]')).not_to_contain_text('余额已过期')
		assert fixture['sends'] == []


async def test_summary_send_is_explicit_single_and_unknown_outcome_cannot_auto_repeat(tmp_path):
	async with automation_ui(tmp_path, direct=True) as (page, fixture, requests):
		assert fixture['sends'] == []
		await page.get_by_role('button', name='发送今日日报', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('日报发送任务已启动')
		assert fixture['sends'] == [{'revision': 1}]
		assert not any(method == 'POST' and path == '/api/runs' for method, path in requests)
		await page.get_by_role('link', name='管理面板', exact=True).click()
		await expect(page.locator('#task-description')).to_contain_text('每日摘要 #8')
		await page.get_by_role('link', name='Status', exact=True).click()
		fixture['send_status'] = 503
		await page.get_by_role('button', name='发送今日日报', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('为避免重复执行')
		await expect(page.get_by_role('button', name='发送今日日报', exact=True)).to_be_disabled()
		await page.wait_for_timeout(5500)
		assert len(fixture['sends']) == 2
		await expect(page.get_by_role('button', name='发送今日日报', exact=True)).to_be_disabled()
		await page.get_by_role('button', name='重新读取确认', exact=True).click()
		await expect(page.get_by_role('button', name='发送今日日报', exact=True)).to_be_enabled()
		assert len(fixture['sends']) == 2


async def test_automation_controls_fit_mobile_and_capture_evidence(tmp_path):
	async with automation_ui(tmp_path, direct=True, mobile=True) as (page, _, _):
		await expect(page.locator('#balance-view')).to_be_visible()
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		folder = os.getenv('CHECKIN_UI_SCREENSHOT_DIR')
		if folder:
			root = Path(folder)
			root.mkdir(parents=True, exist_ok=True)
			await page.screenshot(path=str(root / 'automation-status-mobile.png'), full_page=True)
		await page.get_by_role('link', name='管理面板', exact=True).click()
		await page.get_by_role('button', name='通知渠道', exact=True).click()
		await expect(page.get_by_label('启用低余额告警', exact=True)).to_be_visible()
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		await page.get_by_role('button', name='发送今日日报', exact=True).focus()
		assert await page.get_by_role('button', name='发送今日日报', exact=True).evaluate(
			'(element) => element === document.activeElement'
		)
		if folder:
			await page.screenshot(path=str(Path(folder) / 'automation-settings-mobile.png'), full_page=True)
			await page.set_viewport_size({'width': 1440, 'height': 1080})
			await page.get_by_role('link', name='Status', exact=True).click()
			await page.screenshot(path=str(Path(folder) / 'automation-status-desktop.png'), full_page=True)
