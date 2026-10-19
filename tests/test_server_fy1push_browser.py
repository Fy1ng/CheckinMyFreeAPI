"""Fy1Push form persistence, using a temporary service and synthetic credentials."""

import os
import re
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import SERVICE, create_app
from server.config_store import SECRET_KEEP

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixture')


@pytest.mark.asyncio
async def test_fy1push_form_keeps_token_private_and_saving_never_sends(tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		try:
			context = await browser.new_context(viewport={'width': 1440, 'height': 1050}, timezone_id='Asia/Singapore')
			origin = str(server.make_url('')).rstrip('/')
			blocked = []

			async def guard(route):
				if route.request.url.startswith(origin + '/'):
					await route.continue_()
				else:
					blocked.append(route.request.url)
					await route.abort()

			await context.route('**/*', guard)
			page = await context.new_page()
			await page.goto(origin)
			await page.get_by_label('管理密码').fill('synthetic-webui-password')
			await page.get_by_role('button', name='登录', exact=True).click()
			await expect(page.locator('#workspace')).to_be_visible()
			await page.get_by_role('button', name='通知渠道', exact=True).click()
			group = page.locator('details.notification-group').filter(has=page.get_by_text('Fy1Push', exact=True))
			await group.locator('summary').click()
			await group.get_by_label(re.compile('^服务器 URL')).fill('https://push.example.test')
			await group.get_by_label('发送 token', exact=True).fill('synthetic-fy1push-sending-token')
			await group.get_by_label(re.compile('^消息分组')).fill('签到')
			await page.get_by_role('button', name='保存配置', exact=True).click()
			await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
			await expect(group.get_by_label('发送 token', exact=True)).to_have_value('')
			assert service.store.public()['config']['notifications']['FY1PUSH_TOKEN'] == SECRET_KEEP
			await group.get_by_label(re.compile('^消息分组')).fill('服务通知')
			await page.get_by_role('button', name='保存配置', exact=True).click()
			await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
			assert service.store.load()[0]['notifications']['FY1PUSH_TOKEN'] == 'synthetic-fy1push-sending-token'
			assert not service.jobs.history()
			assert not service.jobs.status()['running']
			assert not blocked
			assert b'synthetic-fy1push-sending-token' not in (tmp_path / 'webui.sqlite3').read_bytes()
			if os.getenv('CHECKIN_UI_SCREENSHOT_DIR'):
				destination = Path(os.environ['CHECKIN_UI_SCREENSHOT_DIR'])
				destination.mkdir(parents=True, exist_ok=True)
				await group.scroll_into_view_if_needed()
				await page.screenshot(path=str(destination / 'webui-fy1push.png'), full_page=True)
			await group.get_by_role('button', name='清除', exact=True).click()
			await page.get_by_role('button', name='保存配置', exact=True).click()
			await expect(page.locator('#config-revision')).to_have_text('已保存版本 3')
			assert service.store.load()[0]['notifications']['FY1PUSH_TOKEN'] == ''
		finally:
			await browser.close()
