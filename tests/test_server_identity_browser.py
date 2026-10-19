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
		await expect(new_account.get_by_label('登录身份', exact=False)).to_have_value('')
		await expect(new_account.locator('.card-summary')).to_contain_text('保存时自动新建身份')
		await expect(page.locator('#identity-count')).to_have_text('1')
		await new_account.get_by_label('认证方式').select_option('password')
		await new_account.get_by_label('认证方式').select_option('github')
		await expect(page.locator('#identity-count')).to_have_text('1')
		await page.locator('[data-tab="identities"]').click()
		await page.get_by_role('button', name='+ 添加身份', exact=True).click()
		await page.locator('.config-card').last.get_by_label('身份平台').select_option('github')
		await page.locator('[data-tab="accounts"]').click()
		await new_account.get_by_label('登录身份', exact=False).select_option('identity-1')
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
async def test_oauth_creates_identity_only_on_save_and_login_needs_no_account(tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	async with local_browser(app) as (page, requests, states):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await expect(page.get_by_label('登录身份', exact=False)).to_have_value('')
		await expect(page.locator('#identity-count')).to_have_text('0')
		await page.get_by_role('button', name='移除account-1', exact=True).click()
		await expect(page.locator('#identity-count')).to_have_text('0')
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		for auth_type in ['github', 'password', 'github', 'linuxdo']:
			await page.get_by_label('认证方式').select_option(auth_type)
			await expect(page.locator('#identity-count')).to_have_text('0')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('需要填写目标站点用户名或用户 ID')
		await expect(page.locator('#identity-count')).to_have_text('0')
		assert service.store.load()[1] == 0
		await page.get_by_label('目标站点用户名', exact=False).fill('fixture-user')
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.locator('.config-card').last.get_by_label('目标站点用户名', exact=False).fill('fixture-user')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
		await expect(page.locator('#identity-count')).to_have_text('1')
		config, _ = service.store.load()
		assert config['identities'] == {'linuxdo-1': {'type': 'linuxdo', 'proxy': 'direct'}}
		assert [account['auth']['identity'] for account in config['accounts']] == ['linuxdo-1', 'linuxdo-1']
		assert requests == []
		assert service.jobs.history() == []
		await page.get_by_role('button', name='移除account-1', exact=True).click()
		await page.get_by_role('button', name='移除account-2', exact=True).click()
		await page.locator('[data-tab="identities"]').click()
		await page.locator('.card-toggle').click()
		await expect(page.get_by_role('button', name='先保存再登录', exact=True)).to_be_disabled()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
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
		assert requests == [{'revision': 2, 'identity': 'linuxdo-1'}]
		assert service.store.load()[0]['accounts'] == []


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['rejected', 'conflict', 'uncertain'])
async def test_oauth_save_failure_does_not_create_draft_identity(tmp_path, failure):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	async with local_browser(app) as (page, requests, _):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.get_by_label('认证方式').select_option('github')
		await page.get_by_label('目标站点用户名', exact=False).fill('fixture-user')
		if failure == 'conflict':
			config, revision = service.store.load()
			service.store.save(config, revision)
		else:

			async def fail_save(route):
				if route.request.method != 'PUT':
					await route.fallback()
				elif failure == 'uncertain':
					await route.abort('failed')
				else:
					await route.fulfill(status=400, json={'error': 'synthetic save rejection'})

			await page.route('**/api/config', fail_save)
		await page.get_by_role('button', name='保存配置', exact=True).click()
		message = {
			'rejected': 'synthetic save rejection',
			'conflict': '保存冲突',
			'uncertain': '请求已发出, 但未能确认结果',
		}[failure]
		await expect(page.locator('#global-message')).to_contain_text(message)
		await expect(page.locator('#identity-count')).to_have_text('0')
		await expect(page.get_by_label('登录身份', exact=False)).to_have_value('')
		await expect(page.get_by_label('目标站点用户名', exact=False)).to_have_value('fixture-user')
		config, _ = service.store.load()
		assert config['identities'] == {}
		assert config['accounts'] == []
		assert requests == []
		assert service.jobs.history() == []
		if failure == 'uncertain':
			await expect(page.get_by_role('button', name='保存配置', exact=True)).to_be_disabled()
		else:
			if failure == 'conflict':
				await page.get_by_label('认证方式').select_option('password')
				await expect(page.locator('#identity-count')).to_have_text('0')
			else:
				await page.unroute('**/api/config', fail_save)
				await page.get_by_role('button', name='保存配置', exact=True).click()
				await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
				config, _ = service.store.load()
				assert config['identities'] == {'github-1': {'type': 'github', 'proxy': 'direct'}}
				assert config['accounts'][0]['auth']['identity'] == 'github-1'


@pytest.mark.asyncio
@pytest.mark.parametrize('invalid_reference', [None, 'deleted', 'wrong-type'])
async def test_oauth_save_requires_matching_existing_identity(tmp_path, invalid_reference):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	config, revision = service.store.load()
	config['identities'] = {'ld-a': {'type': 'linuxdo'}, 'ld-b': {'type': 'linuxdo'}}
	service.store.save(config, revision)
	async with local_browser(app) as (page, requests, _):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.get_by_label('目标站点用户名', exact=False).fill('fixture-user')
		await expect(page.get_by_label('登录身份', exact=False)).to_have_value('')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('需要选择类型匹配的登录身份')
		await expect(page.locator('#identity-count')).to_have_text('2')
		assert service.store.load()[1] == 1
		await page.get_by_label('登录身份', exact=False).select_option('ld-a')
		if invalid_reference:
			await page.locator('[data-tab="identities"]').click()
			identity = page.locator('.config-card').first
			if invalid_reference == 'deleted':
				await identity.get_by_role('button', name='移除ld-a', exact=True).click()
			else:
				await identity.locator('.card-toggle').click()
				await identity.get_by_label('身份平台').select_option('github')
			await page.locator('[data-tab="accounts"]').click()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		if invalid_reference:
			await expect(page.locator('#global-message')).to_contain_text('需要选择类型匹配的登录身份')
			await expect(page.get_by_label('登录身份', exact=False)).to_have_value('ld-a')
			assert service.store.load()[1] == 1
		else:
			await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
			config, _ = service.store.load()
			assert set(config['identities']) == {'ld-a', 'ld-b'}
			assert config['accounts'][0]['auth']['identity'] == 'ld-a'
		assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize('platform', ['linuxdo', 'github'])
@pytest.mark.parametrize('existing_count', [1, 2])
async def test_oauth_can_create_independent_identities_when_matching_identity_exists(
	tmp_path, platform, existing_count
):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	config, revision = service.store.load()
	existing_alias = f'{platform}-1'
	config['identities'] = {existing_alias: {'type': platform, 'proxy': 'direct'}}
	if existing_count == 2:
		config['identities']['new-identity-1'] = {'type': platform, 'proxy': 'direct'}
	config['accounts'] = [
		{
			'id': 'existing',
			'provider': 'anyrouter',
			'auth': {'type': platform, 'identity': existing_alias},
			'expected_username': 'existing-user',
		}
	]
	service.store.save(config, revision)
	async with local_browser(app) as (page, requests, _):
		for _ in range(2):
			await page.get_by_role('button', name='+ 添加账号', exact=True).click()
			account = page.locator('.config-card').last
			if platform != 'linuxdo':
				await account.get_by_label('认证方式').select_option(platform)
			await expect(account.get_by_label('登录身份', exact=False)).to_have_value(
				existing_alias if existing_count == 1 else ''
			)
			await account.get_by_label('登录身份', exact=False).select_option(label='新建独立身份 (保存时创建)')
			await expect(account.locator('.card-summary')).to_contain_text('保存时新建独立身份')
			await expect(account.get_by_role('button', name='编辑此身份', exact=True)).to_have_count(0)
			await expect(page.locator('#identity-count')).to_have_text(str(existing_count))
			await account.get_by_label('目标站点用户名', exact=False).fill('new-user')
		await page.locator('[data-tab="identities"]').click()
		await expect(page.locator('.config-card')).to_have_count(existing_count)
		await page.locator('[data-tab="accounts"]').click()
		await expect(account.get_by_label('登录身份', exact=False).locator('option:checked')).to_have_text(
			'新建独立身份 (保存时创建)'
		)

		async def reject_save(route):
			payload = json.loads(route.request.post_data)['config']
			assert all('_uiNewIdentity' not in account and '_uiAuth' not in account for account in payload['accounts'])
			await route.fulfill(status=400, json={'error': 'synthetic save rejection'})

		await page.route('**/api/config', reject_save)
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#global-message')).to_contain_text('synthetic save rejection')
		await expect(page.locator('#identity-count')).to_have_text(str(existing_count))
		await expect(account.get_by_label('登录身份', exact=False).locator('option:checked')).to_have_text(
			'新建独立身份 (保存时创建)'
		)
		assert service.store.load()[0] == config
		await page.unroute('**/api/config', reject_save)
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
		await expect(page.locator('#identity-count')).to_have_text(str(existing_count + 2))
		saved, _ = service.store.load()
		assert saved['accounts'][0] == config['accounts'][0]
		assert [account['auth']['identity'] for account in saved['accounts'][1:]] == [f'{platform}-2', f'{platform}-3']
		assert saved['identities'] == {
			**config['identities'],
			f'{platform}-2': {'type': platform, 'proxy': 'direct'},
			f'{platform}-3': {'type': platform, 'proxy': 'direct'},
		}
		assert requests == []
		assert service.jobs.history() == []


@pytest.mark.asyncio
async def test_pending_new_identity_can_be_cancelled_or_switched_without_creating_identity(tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-webui-password', scheduler=False)
	service = app[SERVICE]
	config, revision = service.store.load()
	config['identities'] = {'linuxdo-1': {'type': 'linuxdo'}, 'github-1': {'type': 'github'}}
	service.store.save(config, revision)
	async with local_browser(app) as (page, requests, _):
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		for platform in ['github', 'password', 'linuxdo']:
			await page.get_by_label('登录身份', exact=False).select_option(label='新建独立身份 (保存时创建)')
			await page.get_by_label('认证方式').select_option(platform)
			if platform == 'password':
				await page.get_by_label('认证方式').select_option('github')
				platform = 'github'
			await expect(page.get_by_label('登录身份', exact=False)).to_have_value(f'{platform}-1')
			await expect(page.locator('#identity-count')).to_have_text('2')
		await page.get_by_label('登录身份', exact=False).select_option(label='新建独立身份 (保存时创建)')
		await page.get_by_label('登录身份', exact=False).select_option('linuxdo-1')
		await page.get_by_label('目标站点用户名', exact=False).fill('existing-user')
		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await (
			page.locator('.config-card')
			.last.get_by_label('登录身份', exact=False)
			.select_option(label='新建独立身份 (保存时创建)')
		)
		await page.get_by_role('button', name='移除account-2', exact=True).click()
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
		saved, _ = service.store.load()
		assert saved['identities'] == config['identities']
		assert len(saved['accounts']) == 1
		assert saved['accounts'][0]['auth'] == {'type': 'linuxdo', 'identity': 'linuxdo-1'}
		assert requests == []


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
