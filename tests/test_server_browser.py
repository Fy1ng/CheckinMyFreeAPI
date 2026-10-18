"""Real local browser interaction with synthetic accounts and no site requests."""

import os
import re
import time
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import SERVICE, create_app
from server.config_store import SECRET_KEEP

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixtures')


@pytest.mark.asyncio
async def test_webui_save_conflict_secret_retention_and_job_controls(monkeypatch, tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	starts = []

	async def start(revision):
		starts.append(revision)
		cursor = service.jobs.db.execute(
			"INSERT INTO runs(state,started_at,revision) VALUES ('running',?,?)", (time.time(), revision)
		)
		service.jobs.db.commit()
		service.jobs.active_id = cursor.lastrowid
		service.jobs.manual = {'transport': 'desktop', 'deadline': time.monotonic() + 600}
		service.jobs.db.execute("UPDATE runs SET state='awaiting_login' WHERE id=?", (service.jobs.active_id,))
		service.jobs.db.commit()
		return service.jobs.history()[0]

	async def stop():
		service.jobs.db.execute(
			"UPDATE runs SET state='cancelled',finished_at=? WHERE id=?", (time.time(), service.jobs.active_id)
		)
		service.jobs.db.commit()
		service.jobs.active_id = None
		service.jobs.manual = None
		return True

	monkeypatch.setattr(service.jobs, 'start', start)
	monkeypatch.setattr(service.jobs, 'stop', stop)
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		try:
			context = await browser.new_context(viewport={'width': 1440, 'height': 1080}, timezone_id='Asia/Singapore')
			origin = str(server.make_url('')).rstrip('/')
			blocked = []

			async def network_guard(route):
				if route.request.url.startswith(origin + '/'):
					await route.continue_()
				else:
					blocked.append(route.request.url)
					await route.abort()

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
			await page.get_by_label('站点登录邮箱').fill('fixture@example.test')
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
			await expect(page.locator('#task-hint')).to_contain_text('本机已打开的 Chromium')
			await expect(page.locator('#task-hint')).to_contain_text('剩余约')
			await expect(page.locator('#manual-link')).to_be_hidden()
			await expect(page.locator('#start-button')).to_be_disabled()
			page.once('dialog', lambda dialog: dialog.accept())
			await page.get_by_role('button', name='停止任务', exact=True).click()
			await expect(page.locator('#start-button')).to_be_enabled()
			assert service.jobs.history()[0]['state'] == 'cancelled'
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
