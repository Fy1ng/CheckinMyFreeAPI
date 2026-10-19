"""Isolated WebUI folding and identity login interactions, without external requests."""

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import SERVICE, create_app

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixtures')


@asynccontextmanager
async def local_browser(app, *, identity_error=False, uncertain_login=False):
	requests = []
	running = False
	states: dict[str, dict] = {}
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		context = await browser.new_context(viewport={'width': 1440, 'height': 1080})
		origin = str(server.make_url('')).rstrip('/')
		errors = []
		blocked = []

		async def guard(route):
			nonlocal running
			request = route.request
			if not request.url.startswith(origin + '/'):
				blocked.append(request.url)
				await route.abort()
			elif request.url == origin + '/api/identities':
				reply: dict[str, object] = (
					{'error': 'synthetic identity state failure'} if identity_error else {'identities': states}
				)
				await route.fulfill(
					status=503 if identity_error else 200,
					json=reply,
				)
			elif request.url == origin + '/api/identities/login':
				assert request.method == 'POST'
				assert request.headers.get('x-csrf-token')
				requests.append(json.loads(request.post_data))
				running = True
				if uncertain_login:
					await route.abort('failed')
				else:
					await route.fulfill(
						json={'run': {'id': 91, 'kind': 'identity_login', 'identity': requests[-1]['identity']}}
					)
			elif request.url == origin + '/api/status':
				await route.fulfill(
					json={
						'running': running,
						'run': {
							'id': 91,
							'kind': 'identity_login',
							'identity': requests[-1]['identity'],
							'state': 'awaiting_login',
							'manual_transport': 'desktop',
							'manual_remaining_seconds': 599,
						}
						if running
						else None,
						'platform': {'manual_supported': True, 'manual_mode': 'desktop'},
					}
				)
			else:
				await route.continue_()

		await context.route('**/*', guard)
		page = await context.new_page()
		page.on('pageerror', lambda error: errors.append(str(error)))
		try:
			await page.goto(origin)
			await page.get_by_label('管理密码').fill('synthetic-webui-password')
			await page.get_by_role('button', name='登录', exact=True).click()
			await expect(page.locator('#workspace')).to_be_visible()
			await expect(page.locator('#config-revision')).not_to_have_text('尚未读取配置')
			yield page, requests, states
			assert not errors
			assert not blocked
		finally:
			await browser.close()


@pytest.mark.asyncio
async def test_saved_cards_fold_and_oauth_selection_preserves_drafts(tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	config, revision = service.store.load()
	config['accounts'] = [
		{'id': 'saved', 'name': 'Saved account', 'email': 'fixture@example.test', 'password': 'synthetic'}
	]
	config['identities'] = {'saved-ld': {'type': 'linuxdo', 'proxy': 'direct'}}
	config['providers'] = {'saved-site': {'domain': 'https://fixture.example.test'}}
	service.store.save(config, revision)
	async with local_browser(app) as (page, requests, _):
		account = page.locator('.config-card').first
		await expect(account.locator('.card-toggle')).to_have_attribute('aria-expanded', 'false')
		await expect(account.get_by_label('账号名称', exact=False)).to_be_hidden()
		await account.locator('.card-toggle').click()
		await account.get_by_label('账号名称', exact=False).fill('Draft preserved')
		await account.locator('.card-toggle').focus()
		await page.keyboard.press('Enter')
		await expect(account.locator('.card-toggle')).to_have_attribute('aria-expanded', 'false')
		await expect(account.locator('.card-summary')).to_contain_text('AnyRouter')
		await page.locator('[data-tab="identities"]').click()
		await expect(page.locator('.card-toggle')).to_have_attribute('aria-expanded', 'false')
		await page.locator('.card-toggle').click()
		await expect(page.get_by_label('身份别名', exact=False)).to_have_value('saved-ld')
		await page.locator('[data-tab="providers"]').click()
		await expect(page.locator('.card-toggle')).to_have_attribute('aria-expanded', 'false')
		await page.locator('.card-toggle').click()
		await page.get_by_label('站点域名', exact=False).fill('https://draft.example.test')
		await page.get_by_role('button', name='+ 添加站点', exact=True).click()
		await expect(page.locator('.config-card').last.locator('.card-toggle')).to_have_attribute(
			'aria-expanded', 'true'
		)
		await page.locator('[data-tab="accounts"]').click()
		await expect(account.locator('.card-toggle')).to_have_attribute('aria-expanded', 'false')
		await account.locator('.card-toggle').click()
		await expect(account.get_by_label('账号名称', exact=False)).to_have_value('Draft preserved')
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		new_account = page.locator('.config-card').last
		await expect(new_account.locator('.card-toggle')).to_have_attribute('aria-expanded', 'true')
		await expect(new_account.get_by_label('登录身份', exact=False)).to_have_value('saved-ld')
		await expect(page.locator('#identity-count')).to_have_text('1')
		await new_account.get_by_label('认证方式').select_option('github')
		await expect(new_account.get_by_label('登录身份', exact=False)).to_have_value('github-1')
		await expect(page.locator('#identity-count')).to_have_text('2')
		await expect(page.locator('#global-message')).to_contain_text('草稿中新建')
		await new_account.get_by_label('认证方式').select_option('password')
		await new_account.get_by_label('认证方式').select_option('github')
		await expect(page.locator('#identity-count')).to_have_text('2')
		await new_account.get_by_role('button', name='编辑此身份', exact=True).click()
		identity = page.locator('.config-card').last
		await identity.get_by_label('身份别名', exact=False).fill('draft-github')
		await expect(identity.get_by_label('身份代理模式')).to_have_value('direct')
		await page.locator('[data-tab="accounts"]').click()
		await expect(new_account.get_by_label('登录身份', exact=False)).to_have_value('draft-github')
		await new_account.get_by_role('button', name='移除account-1', exact=True).click()
		await expect(account.locator('.card-toggle')).to_have_attribute('aria-expanded', 'true')
		await page.locator('[data-tab="providers"]').click()
		await expect(page.locator('.config-card').first.get_by_label('站点域名', exact=False)).to_have_value(
			'https://draft.example.test'
		)
		await page.set_viewport_size({'width': 390, 'height': 844})
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		assert service.store.load()[1] == 1
		assert requests == []


@pytest.mark.asyncio
async def test_default_oauth_creates_one_identity_and_login_needs_no_account(tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	async with local_browser(app) as (page, requests, states):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await expect(page.get_by_label('登录身份', exact=False)).to_have_value('linuxdo-1')
		await expect(page.locator('#identity-count')).to_have_text('1')
		await page.get_by_role('button', name='移除account-1', exact=True).click()
		await page.locator('[data-tab="identities"]').click()
		await expect(page.get_by_role('button', name='先保存再登录', exact=True)).to_be_disabled()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
		await expect(page.get_by_role('button', name='登录 / 重新登录', exact=True)).to_be_enabled()
		states['linuxdo-1'] = {'state': 'verified', 'username': 'fixture-user', 'verified_at': '2026-10-19T10:00:00Z'}
		await page.get_by_role('button', name='重新读取登录状态', exact=True).click()
		await expect(page.locator('[data-identity-state]')).to_contain_text('上次验证成功: fixture-user')
		await expect(page.locator('#identity-load-status')).to_contain_text('不代表当前仍在线')
		if os.getenv('CHECKIN_UI_SCREENSHOT_DIR'):
			destination = Path(os.environ['CHECKIN_UI_SCREENSHOT_DIR'])
			destination.mkdir(parents=True, exist_ok=True)
			await page.screenshot(path=str(destination / 'webui-identity-login.png'), full_page=True)
		await page.set_viewport_size({'width': 390, 'height': 844})
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		await page.set_viewport_size({'width': 1440, 'height': 1080})
		await page.get_by_role('button', name='登录 / 重新登录', exact=True).dblclick()
		await expect(page.locator('#task-description')).to_contain_text('身份登录 linuxdo-1')
		await expect(page.locator('#task-hint')).to_contain_text('本机已打开的 Chromium')
		await expect(page.locator('#stop-button')).to_be_enabled()
		await expect(page.get_by_role('button', name='登录 / 重新登录', exact=True)).to_be_disabled()
		assert requests == [{'revision': 1, 'identity': 'linuxdo-1'}]
		assert service.store.load()[0]['accounts'] == []


@pytest.mark.asyncio
async def test_identity_state_failure_allows_edit_and_unknown_login_is_not_repeated(tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	async with local_browser(app, identity_error=True, uncertain_login=True) as (page, requests, _):
		await page.locator('[data-tab="identities"]').click()
		await expect(page.locator('#identity-load-status')).to_contain_text('读取登录状态失败')
		await page.get_by_role('button', name='+ 添加身份', exact=True).click()
		await expect(page.locator('.card-toggle')).to_have_attribute('aria-expanded', 'true')
		await page.get_by_label('身份别名', exact=False).fill('standalone')
		await expect(page.get_by_role('button', name='先保存再登录', exact=True)).to_be_disabled()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
		await expect(page.get_by_role('button', name='登录 / 重新登录', exact=True)).to_be_enabled()
		await page.get_by_role('button', name='登录 / 重新登录', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('请求已发出, 但未能确认结果')
		await expect(page.get_by_role('button', name='登录 / 重新登录', exact=True)).to_be_disabled()
		await page.get_by_role('button', name='重新读取确认', exact=True).click()
		await expect(page.locator('#task-description')).to_contain_text('身份登录 standalone')
		await expect(page.get_by_role('button', name='登录 / 重新登录', exact=True)).to_be_disabled()
		assert requests == [{'revision': 1, 'identity': 'standalone'}]
