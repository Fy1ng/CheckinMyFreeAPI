"""Encrypted backup UI acceptance with mocked APIs and synthetic files only.

Browser plugin not available. The tested flow is an authenticated backup page
through settings, create/download, preview and explicitly confirmed restore.
No real database, password, upstream account or notification service is used.
"""

import copy
import json
import os
import re
from contextlib import asynccontextmanager
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer
from playwright.async_api import async_playwright, expect

from server.app import STATIC_ROOT

pytestmark = pytest.mark.skipif(os.getenv('CHECKIN_BROWSER_TESTS') != '1', reason='Opt-in local Chromium fixtures')

ADMIN_PASSWORD = 'synthetic-backup-admin-password'
RECOVERY_PASSWORD = 'synthetic-independent-recovery-password'
SECRET_KEEP = '__UNCHANGED_SECRET__'
BACKUP_ID = 'backup-20261025T100000Z-synthetic.nab'


def multipart_values(request):
	content_type = request.headers['content-type']
	message = BytesParser(policy=policy.default).parsebytes(
		('Content-Type: ' + content_type + '\r\nMIME-Version: 1.0\r\n\r\n').encode() + request.post_data_buffer
	)
	fields = {}
	for part in message.iter_parts():
		name = part.get_param('name', header='content-disposition')
		content = part.get_payload(decode=True)
		assert isinstance(content, bytes)
		fields[name] = {'filename': part.get_filename(), 'content': content} if name == 'file' else content.decode()
	return fields


@asynccontextmanager
async def backup_ui(tmp_path, *, authenticated=True, mobile=False):
	app = web.Application()

	async def download(_):
		return web.Response(
			body=b'synthetic-encrypted-backup',
			content_type='application/octet-stream',
			headers={'Content-Disposition': 'attachment; filename="' + BACKUP_ID + '"'},
		)

	app.router.add_get('/api/backups/' + BACKUP_ID, download)
	for path, filename in [
		('/backups', 'backups.html'),
		('/backups.js', 'backups.js'),
		('/passkeys.js', 'passkeys.js'),
		('/style.css', 'style.css'),
	]:

		async def static(_, filename=filename):
			return web.FileResponse(STATIC_ROOT / filename)

		app.router.add_get(path, static)
	fixture: dict = {
		'authenticated': authenticated,
		'csrf': 'synthetic-backup-csrf',
		'config': {
			'schema_version': 2,
			'accounts': [],
			'backups': {'enabled': False, 'time': '03:00', 'retain_count': 7, 'password': SECRET_KEEP},
		},
		'revision': 4,
		'backups': [{'id': BACKUP_ID, 'created_at': '2026-10-25T10:00:00Z', 'size': 4096}],
		'saves': [],
		'creates': [],
		'previews': [],
		'restores': [],
		'create_status': 201,
		'preview_status': 200,
		'preview_error': '备份校验失败或恢复密码错误',
		'expire_list': False,
	}
	requests, errors, console, blocked = [], [], [], []
	async with TestServer(app) as server, async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		context = await browser.new_context(
			viewport={'width': 390, 'height': 844} if mobile else {'width': 1440, 'height': 1080}, accept_downloads=True
		)
		origin = str(server.make_url('')).rstrip('/')

		async def guard(route):
			request = route.request
			path = request.url.removeprefix(origin)
			requests.append((request.method, path))
			if not request.url.startswith(origin + '/'):
				blocked.append(request.url)
				await route.abort()
				return
			if not path.startswith('/api/'):
				await route.continue_()
				return
			if path == '/api/session':
				await route.fulfill(json={'authenticated': fixture['authenticated'], 'csrf': fixture['csrf']})
				return
			if path == '/api/login':
				body = json.loads(request.post_data)
				fixture['authenticated'] = body['password'] == ADMIN_PASSWORD
				await route.fulfill(
					status=200 if fixture['authenticated'] else 401,
					json={'authenticated': True, 'csrf': fixture['csrf']}
					if fixture['authenticated']
					else {'error': '管理员密码错误, 请重新输入'},
				)
				return
			if not fixture['authenticated']:
				await route.fulfill(status=401, json={'error': '登录已失效, 请重新登录'})
				return
			if request.method not in {'GET', 'HEAD'}:
				assert request.headers.get('x-csrf-token') == fixture['csrf']
			if path == '/api/config':
				if request.method == 'PUT':
					body = json.loads(request.post_data)
					fixture['saves'].append(copy.deepcopy(body))
					fixture['config'] = body['config']
					if fixture['config']['backups']['password']:
						fixture['config']['backups']['password'] = SECRET_KEEP
					fixture['revision'] += 1
				await route.fulfill(json={'config': fixture['config'], 'revision': fixture['revision']})
			elif path == '/api/backups' and request.method == 'GET':
				if fixture['expire_list']:
					fixture['authenticated'] = False
					await route.fulfill(status=401, json={'error': '登录已失效, 请重新登录'})
				else:
					await route.fulfill(
						json={
							'backups': fixture['backups'],
							'next_at': '2026-10-25T19:00:00Z',
							'last_state': 'succeeded',
							'error': None,
						}
					)
			elif path == '/api/backups' and request.method == 'POST':
				fixture['creates'].append(json.loads(request.post_data))
				if fixture['create_status'] == 201:
					await route.fulfill(status=201, json={'backup': fixture['backups'][0]})
				else:
					await route.fulfill(
						status=fixture['create_status'],
						json={'error': '操作过于频繁, 请在 60 秒后重试'}
						if fixture['create_status'] == 429
						else {'error': '备份执行结果待确认'},
					)
			elif path == '/api/backups/preview':
				fixture['previews'].append(multipart_values(request))
				await route.fulfill(
					status=fixture['preview_status'],
					json={
						'ticket': 'synthetic-preview-ticket',
						'created_at': '2026-10-25T10:00:00Z',
						'expires_at': '2026-10-25T10:10:00Z',
						'counts': {'accounts': 6, 'runs': 36},
					}
					if fixture['preview_status'] == 200
					else {'error': fixture['preview_error']},
				)
			elif path == '/api/backups/restore':
				fixture['restores'].append(json.loads(request.post_data))
				fixture['authenticated'] = False
				await route.fulfill(
					json={'restored': True, 'before_backup': BACKUP_ID, 'automatic_tasks_disabled': True}
				)
			elif path == '/api/backups/' + BACKUP_ID:
				await route.continue_()
			else:
				pytest.fail('Unexpected backup UI request: ' + path)

		await context.route('**/*', guard)
		page = await context.new_page()
		page.set_default_timeout(5000)
		page.on('pageerror', lambda error: errors.append(str(error)))
		page.on(
			'console', lambda message: console.append(message.text) if message.type in {'error', 'warning'} else None
		)
		try:
			await page.goto(origin + '/backups')
			await expect(page.locator('#backup-workspace' if authenticated else '#backup-login')).to_be_visible()
			if authenticated:
				await expect(page.locator('#backup-files')).to_contain_text('下载加密备份')
			yield page, fixture, requests
			assert not errors and not blocked
			assert all('Failed to load resource' in item for item in console), console
		finally:
			await browser.close()


async def upload_preview(page):
	await page.locator('#restore-file').set_input_files(
		{'name': 'source.nab', 'mimeType': 'application/octet-stream', 'buffer': b'synthetic-encrypted-data'}
	)
	await page.locator('#restore-password').fill(RECOVERY_PASSWORD)
	await page.get_by_role('button', name='校验并预览', exact=True).click()


async def test_backup_settings_keep_marker_refresh_preserves_draft_and_create_download_are_explicit(tmp_path):
	async with backup_ui(tmp_path) as (page, fixture, _):
		assert await page.title() == '备份与恢复 | NewAPI'
		await expect(page.locator('#backup-password')).to_have_value('')
		await expect(page.locator('#backup-password')).to_have_attribute('placeholder', '已保存, 留空保留')
		await page.locator('#backup-time').fill('04:15')
		await page.locator('#backup-password').fill(RECOVERY_PASSWORD)
		await expect(page.locator('#backup-create')).to_be_disabled()
		await page.get_by_role('button', name='刷新列表', exact=True).click()
		await expect(page.locator('#backup-time')).to_have_value('04:15')
		await expect(page.locator('#backup-password')).to_have_value(RECOVERY_PASSWORD)
		assert fixture['saves'] == [] and fixture['creates'] == []
		await page.get_by_role('button', name='保存备份设置', exact=True).click()
		await expect(page.locator('#backup-message')).to_contain_text('备份设置已保存')
		assert fixture['saves'][-1]['config']['backups']['password'] == RECOVERY_PASSWORD
		await expect(page.locator('#backup-password')).to_have_value('')
		await page.locator('#backup-retention').fill('8')
		await page.get_by_role('button', name='保存备份设置', exact=True).click()
		await expect(page.locator('#backup-create')).to_be_enabled()
		assert fixture['saves'][-1]['config']['backups']['password'] == SECRET_KEEP
		await page.get_by_role('button', name='立即创建备份', exact=True).click()
		await expect(page.locator('#backup-message')).to_contain_text('加密备份已创建')
		assert fixture['creates'] == [{'revision': 6}]
		async with page.expect_download() as event:
			await page.get_by_role('link', name='下载加密备份', exact=True).click()
		download = await event.value
		assert download.suggested_filename == BACKUP_ID
		assert Path(await download.path()).read_bytes() == b'synthetic-encrypted-backup'


async def test_backup_preview_requires_admin_password_and_confirmation_before_restore(tmp_path):
	async with backup_ui(tmp_path) as (page, fixture, _):
		await upload_preview(page)
		await expect(page.locator('#restore-preview')).to_be_visible()
		await expect(page.locator('#restore-preview-detail')).to_contain_text('账户: 6')
		await expect(page.locator('#restore-preview-detail')).to_contain_text('运行记录: 36')
		await expect(page.locator('#restore-preview-detail')).to_contain_text('校验有效期:')
		await expect(page.locator('#restore-preview')).to_contain_text('当前数据会先自动备份')
		await expect(page.locator('#restore-password')).to_have_value('')
		assert fixture['previews'][0]['revision'] == '4'
		assert fixture['previews'][0]['password'] == RECOVERY_PASSWORD
		assert fixture['previews'][0]['file'] == {'filename': 'source.nab', 'content': b'synthetic-encrypted-data'}
		await page.get_by_role('button', name='确认恢复', exact=True).click()
		assert fixture['restores'] == []
		await page.locator('#restore-admin-password').fill(ADMIN_PASSWORD)
		await page.get_by_role('button', name='确认恢复', exact=True).click()
		assert fixture['restores'] == []
		await page.locator('#restore-confirm').check()
		await page.locator('#restore-admin-password').fill('')
		await page.get_by_role('button', name='确认恢复', exact=True).click()
		assert fixture['restores'] == []
		await page.locator('#restore-admin-password').fill(ADMIN_PASSWORD)
		await page.get_by_role('button', name='确认恢复', exact=True).click()
		await expect(page).to_have_url(re.compile(r'/backups\?restored=1$'))
		await expect(page.locator('#backup-login-message')).to_contain_text('恢复完成')
		await expect(page.locator('#backup-login')).to_be_visible()
		assert fixture['restores'] == [
			{'revision': 4, 'ticket': 'synthetic-preview-ticket', 'admin_password': ADMIN_PASSWORD}
		]


@pytest.mark.parametrize('error', ['备份文件格式无效', '恢复密码错误或文件损坏'])
async def test_backup_preview_errors_are_visible_without_replacing_data(tmp_path, error):
	async with backup_ui(tmp_path) as (page, fixture, _):
		fixture['preview_status'], fixture['preview_error'] = 400, error
		await upload_preview(page)
		await expect(page.locator('#backup-message')).to_be_visible()
		await expect(page.locator('#backup-message')).to_have_text(error)
		await expect(page.locator('#restore-preview')).to_be_hidden()
		assert fixture['restores'] == []


async def test_rate_limit_is_readable_and_unknown_create_is_not_repeated(tmp_path):
	async with backup_ui(tmp_path) as (page, fixture, _):
		fixture['create_status'] = 429
		await page.get_by_role('button', name='立即创建备份', exact=True).click()
		await expect(page.locator('#backup-message')).to_contain_text('60 秒后重试')
		assert len(fixture['creates']) == 1
		fixture['create_status'] = 500
		await page.get_by_role('button', name='立即创建备份', exact=True).click()
		await expect(page.locator('#backup-message')).to_contain_text('请求结果尚未确认')
		await expect(page.locator('#backup-create')).to_be_disabled()
		await expect(page.locator('#backup-save')).to_be_disabled()
		await page.get_by_role('button', name='刷新列表', exact=True).click()
		await expect(page.locator('#backup-create')).to_be_disabled()
		assert len(fixture['creates']) == 2
		await page.get_by_role('button', name='重新读取', exact=True).click()
		await expect(page.locator('#backup-create')).to_be_enabled()
		assert len(fixture['creates']) == 2


async def test_wrong_login_password_is_visible_on_login_page_and_correct_login_recovers(tmp_path):
	async with backup_ui(tmp_path, authenticated=False) as (page, _, _):
		await page.get_by_label('管理密码', exact=True).fill('synthetic-wrong-password')
		await page.get_by_role('button', name='登录', exact=True).click()
		await expect(page.locator('#backup-login-message')).to_be_visible()
		await expect(page.locator('#backup-login-message')).to_contain_text('密码错误')
		await page.get_by_label('管理密码', exact=True).fill(ADMIN_PASSWORD)
		await page.get_by_role('button', name='登录', exact=True).click()
		await expect(page.locator('#backup-workspace')).to_be_visible()


async def test_expired_session_explains_reauthentication_on_visible_login_page(tmp_path):
	async with backup_ui(tmp_path) as (page, fixture, _):
		fixture['expire_list'] = True
		await page.get_by_role('button', name='刷新列表', exact=True).click()
		await expect(page.locator('#backup-login')).to_be_visible()
		await expect(page.locator('#backup-login-message')).to_contain_text('登录已失效')
		await expect(page.locator('#backup-create')).to_be_disabled()


async def test_backup_page_mobile_preview_and_desktop_screenshots(tmp_path):
	async with backup_ui(tmp_path, mobile=True) as (page, _, _):
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		await upload_preview(page)
		await expect(page.locator('#restore-preview')).to_be_visible()
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		folder = os.getenv('CHECKIN_UI_SCREENSHOT_DIR')
		if folder:
			root = Path(folder)
			root.mkdir(parents=True, exist_ok=True)
			await page.screenshot(path=str(root / 'backup-mobile.png'), full_page=True)
			await page.set_viewport_size({'width': 1440, 'height': 1080})
			await page.screenshot(path=str(root / 'backup-desktop.png'), full_page=True)
