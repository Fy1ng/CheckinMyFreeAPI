"""Real local browser interaction with synthetic accounts and no site requests."""

import os
import re
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import SERVICE, create_app
from server.config_store import SECRET_KEEP

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixtures')


@pytest.mark.asyncio
async def test_webui_save_conflict_secret_retention_and_job_controls(tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	starts = []
	running = False
	run = None
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		try:
			context = await browser.new_context(viewport={'width': 1440, 'height': 1080}, timezone_id='Asia/Singapore')
			origin = str(server.make_url('')).rstrip('/')
			blocked = []

			async def network_guard(route):
				nonlocal running, run
				request = route.request
				if not request.url.startswith(origin + '/'):
					blocked.append(request.url)
					await route.abort()
				elif request.url == origin + '/api/status':
					await route.fulfill(json={'running': running, 'run': run, 'next_run_at': None})
				elif request.url == origin + '/api/runs' and request.method == 'POST':
					assert request.headers.get('x-csrf-token')
					starts.append(request.post_data_json['revision'])
					running = True
					run = {'id': 91, 'state': 'running', 'started_at': '2026-10-20T00:00:00Z'}
					await route.fulfill(json={'run': run})
				elif request.url == origin + '/api/runs/stop':
					running = False
					assert run is not None
					run = {**run, 'state': 'cancelled'}
					await route.fulfill(json={'stopped': True})
				elif request.url == origin + '/api/runs':
					await route.fulfill(json={'runs': [run] if run else []})
				else:
					await route.continue_()

			await context.route('**/*', network_guard)
			page = await context.new_page()
			errors = []
			page.on('pageerror', lambda error: errors.append(str(error)))
			await page.goto(origin)
			await page.get_by_label('管理密码').fill('synthetic-webui-password')
			await page.get_by_role('button', name='登录', exact=True).click()
			await expect(page.locator('#workspace')).to_be_visible()
			await page.get_by_role('button', name='+ 添加账号', exact=True).click()
			await page.get_by_label('认证方式').select_option('password')
			await page.get_by_label(re.compile('^账号名称')).fill('本地模拟账号')
			await page.get_by_label(re.compile('^站点登录账号')).fill('fixture@example.test')
			await page.get_by_label('站点密码', exact=True).fill('fixture-site-password')
			await expect(page.locator('#start-button')).to_be_disabled()
			await page.get_by_role('button', name='保存配置', exact=True).click()
			await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
			await expect(page.get_by_label('站点密码', exact=True)).to_have_value('')
			assert service.store.public()['config']['accounts'][0]['password'] == SECRET_KEEP
			assert b'fixture-site-password' not in (tmp_path / 'webui.sqlite3').read_bytes()
			assert starts == []
			await page.get_by_label(re.compile('^账号名称')).fill('冲突草稿')
			config, revision = service.store.load()
			service.store.save(config, revision)
			await page.get_by_role('button', name='保存配置', exact=True).click()
			await expect(page.locator('#global-message')).to_contain_text('保存冲突')
			await expect(page.get_by_label(re.compile('^账号名称'))).to_have_value('冲突草稿')
			page.once('dialog', lambda dialog: dialog.accept())
			await page.get_by_role('button', name='重新读取', exact=True).click()
			await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
			await page.get_by_label(re.compile('^账号名称')).fill('本地模拟账号')
			await page.get_by_role('button', name='保存配置', exact=True).click()
			await expect(page.locator('#config-revision')).to_have_text('已保存版本 3')
			assert service.store.load()[0]['accounts'][0]['password'] == 'fixture-site-password'
			await page.get_by_role('button', name='开始签到', exact=True).click()
			await expect(page.locator('#stop-button')).to_be_enabled()
			assert starts == [3]
			await expect(page.locator('#task-hint')).to_contain_text('使用 HTTP 执行')
			assert await page.locator('#manual-link').count() == 0
			await expect(page.locator('#start-button')).to_be_disabled()
			await page.get_by_role('button', name='停止任务', exact=True).click()
			await expect(page.locator('#start-button')).to_be_enabled()
			assert run is not None and run['state'] == 'cancelled'
			assert not service.jobs.history()
			if os.getenv('CHECKIN_UI_SCREENSHOT_DIR'):
				destination = Path(os.environ['CHECKIN_UI_SCREENSHOT_DIR'])
				destination.mkdir(parents=True, exist_ok=True)
				await page.evaluate('scrollTo(0, 0)')
				await page.screenshot(path=str(destination / 'webui-desktop.png'), full_page=True)
			await page.set_viewport_size({'width': 390, 'height': 844})
			assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
			if os.getenv('CHECKIN_UI_SCREENSHOT_DIR'):
				await page.evaluate('scrollTo(0, 0)')
				await page.screenshot(
					path=str(Path(os.environ['CHECKIN_UI_SCREENSHOT_DIR']) / 'webui-mobile.png'), full_page=True
				)
			await page.get_by_role('button', name='退出', exact=True).click()
			await expect(page.locator('#login-view')).to_be_visible()
			assert not errors
			assert not blocked
		finally:
			await browser.close()
