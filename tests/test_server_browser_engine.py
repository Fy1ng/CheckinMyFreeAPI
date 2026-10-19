"""Browser selection persists once without launching a login or check-in task."""

import json
import os
import re
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import SERVICE, create_app

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixture')


@pytest.mark.asyncio
async def test_browser_choice_keeps_humanize_preference_and_saves_without_running(tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		try:
			context = await browser.new_context(viewport={'width': 1440, 'height': 1080})
			origin = str(server.make_url('')).rstrip('/')
			saves = []
			blocked = []
			tasks = []

			async def guard(route):
				request = route.request
				if not request.url.startswith(origin + '/'):
					blocked.append(request.url)
					await route.abort()
				elif request.method == 'POST' and request.url in {
					origin + '/api/identities/login',
					origin + '/api/runs',
				}:
					tasks.append(request.url)
					await route.abort()
				else:
					if request.method == 'PUT' and request.url == origin + '/api/config':
						saves.append(json.loads(request.post_data))
					await route.continue_()

			await context.route('**/*', guard)
			page = await context.new_page()
			errors = []
			page.on('pageerror', lambda error: errors.append(str(error)))
			await page.goto(origin)
			await page.get_by_label('管理密码').fill('synthetic-webui-password')
			await page.get_by_role('button', name='登录', exact=True).click()
			await expect(page.locator('#workspace')).to_be_visible()
			await page.get_by_role('button', name='定时与浏览器', exact=True).click()
			engine = page.get_by_role('combobox', name=re.compile('^浏览器'))
			humanize = page.get_by_label('启用自然交互', exact=True)
			await expect(engine).to_have_value('cloakbrowser')
			await expect(humanize).to_be_enabled()
			await expect(humanize).to_be_checked()
			await engine.select_option('chrome')
			await expect(humanize).to_be_disabled()
			await expect(humanize).to_be_checked()
			await expect(page.get_by_text('系统 Chrome 不使用此选项.', exact=False)).to_be_visible()
			await engine.select_option('cloakbrowser')
			await expect(humanize).to_be_enabled()
			await expect(humanize).to_be_checked()
			await humanize.uncheck()
			await engine.select_option('chrome')
			await expect(humanize).to_be_disabled()
			await expect(humanize).not_to_be_checked()
			assert not saves
			assert service.store.load()[1] == 0
			await page.get_by_role('button', name='保存配置', exact=True).click()
			await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
			assert len(saves) == 1
			assert saves[0]['config']['browser']['engine'] == 'chrome'
			assert saves[0]['config']['browser']['humanize'] is False
			assert service.store.load()[0]['browser']['engine'] == 'chrome'
			await page.reload()
			await expect(page.locator('#workspace')).to_be_visible()
			await page.get_by_role('button', name='定时与浏览器', exact=True).click()
			await expect(engine).to_have_value('chrome')
			await expect(humanize).to_be_disabled()
			await expect(humanize).not_to_be_checked()
			await engine.select_option('cloakbrowser')
			await expect(humanize).to_be_enabled()
			await expect(humanize).not_to_be_checked()
			assert len(saves) == 1
			assert not service.jobs.history()
			assert not service.jobs.status()['running']
			assert not tasks
			assert not blocked
			assert not errors
			if os.getenv('CHECKIN_UI_SCREENSHOT_DIR'):
				await engine.select_option('chrome')
				destination = Path(os.environ['CHECKIN_UI_SCREENSHOT_DIR'])
				destination.mkdir(parents=True, exist_ok=True)
				await page.screenshot(path=str(destination / 'webui-browser-engine.png'), full_page=True)
		finally:
			await browser.close()
