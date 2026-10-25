"""Disposable local-mode UI/restore acceptance with no management identity prompts.

Browser plugin not available. Uses a temporary Chrome profile against the local
Go fixture. No real account, notification, autostart or production server runs.
"""

import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from playwright.async_api import async_playwright, expect

RECOVERY_PASSWORD = 'synthetic-local-browser-backup-password'  # nosec B105


async def main():
	origin = sys.argv[1]
	evidence = Path(tempfile.mkdtemp(prefix='checkin-local-noauth-ui-'))
	errors, console, requests, external = [], [], [], []
	async with async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome') or None, headless=True
		)
		context = await browser.new_context(viewport={'width': 1440, 'height': 1080}, accept_downloads=True)

		async def guard(route):
			request = route.request
			if not request.url.startswith(origin + '/'):
				external.append(request.url)
				await route.abort()
				return
			requests.append({'method': request.method, 'path': request.url.removeprefix(origin).split('?')[0]})
			if request.url == origin + '/api/backups/restore':
				body = request.post_data_json
				assert set(body) == {'revision', 'ticket'}, body
			await route.continue_()

		await context.route('**/*', guard)
		page = await context.new_page()
		page.on('pageerror', lambda error: errors.append(str(error)))
		page.on('console', lambda item: console.append(item.text) if item.type in {'error', 'warning'} else None)
		page.set_default_timeout(10000)
		try:
			await page.goto(origin)
			await expect(page.locator('#workspace')).to_be_visible()
			await expect(page.locator('#login-view')).to_be_hidden()
			await expect(page.locator('#logout-button')).to_be_hidden()
			await expect(page.locator('.workspace-nav a[href="/security"]')).to_be_hidden()
			await page.get_by_role('button', name='+ 添加账号', exact=True).click()
			await page.get_by_label('启用此账号', exact=True).uncheck()
			await page.get_by_label(re.compile('^账号名称')).fill('Local snapshot')
			await page.get_by_role('button', name='保存配置', exact=True).click()
			await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
			await page.locator('[data-tab="runtime"]').click()
			await expect(page.locator('.go-runtime-panel')).to_be_visible()
			await page.screenshot(path=str(evidence / 'desktop-local-runtime.png'), full_page=True)

			await page.get_by_role('link', name='Status', exact=True).click()
			await expect(page.locator('#balance-view')).to_be_visible()
			await expect(page.locator('#login-view')).to_be_hidden()
			await page.set_viewport_size({'width': 390, 'height': 844})
			assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
			await page.screenshot(path=str(evidence / 'mobile-local-status.png'), full_page=True)

			await page.goto(origin + '/security')
			await expect(page.locator('#security-local')).to_be_visible()
			await expect(page.locator('#security-login')).to_be_hidden()
			await expect(page.locator('#security-register')).to_be_hidden()
			await expect(page.locator('#security-current-password')).to_be_hidden()
			await expect(page.locator('#security-local')).to_contain_text('无需管理密码或 Passkey')

			await page.set_viewport_size({'width': 1440, 'height': 1080})
			await page.goto(origin + '/backups')
			await expect(page.locator('#backup-workspace')).to_be_visible()
			await expect(page.locator('#backup-login')).to_be_hidden()
			await expect(page.locator('.workspace-nav a[href="/security"]')).to_be_hidden()
			await page.locator('#backup-password').fill(RECOVERY_PASSWORD)
			await page.locator('#backup-save').click()
			await expect(page.locator('#backup-message')).to_contain_text('备份设置已保存')
			await page.locator('#backup-create').click()
			await expect(page.locator('#backup-files a')).to_have_count(1)
			async with page.expect_download() as download_event:
				await page.locator('#backup-files a').first.click()
			download = await download_event.value
			backup_path = evidence / 'synthetic-local-snapshot.nab'
			await download.save_as(backup_path)
			assert backup_path.read_bytes().startswith(b'NEWAPI-BACKUP\x00\x01')

			await page.goto(origin)
			await expect(page.locator('#workspace')).to_be_visible()
			await page.locator('[data-account-id] .card-toggle').click()
			await page.get_by_label(re.compile('^账号名称')).fill('Changed after snapshot')
			await page.get_by_role('button', name='保存配置', exact=True).click()
			await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')

			await page.goto(origin + '/backups')
			await expect(page.locator('#backup-workspace')).to_be_visible()
			await page.locator('#restore-file').set_input_files(backup_path)
			await page.locator('#restore-password').fill(RECOVERY_PASSWORD)
			await page.locator('#backup-preview').click()
			await expect(page.locator('#restore-preview')).to_be_visible()
			await expect(page.locator('#restore-password-reauth')).to_be_hidden()
			await expect(page.locator('#restore-passkey-reauth')).to_be_hidden()
			assert not await page.locator('#restore-admin-password').evaluate('(input) => input.required')
			await expect(page.locator('#restore-completion-hint')).to_contain_text('无需管理员身份验证')
			await page.screenshot(path=str(evidence / 'desktop-local-restore-preview.png'), full_page=True)
			await page.set_viewport_size({'width': 390, 'height': 844})
			assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
			await page.screenshot(path=str(evidence / 'mobile-local-restore-preview.png'), full_page=True)
			await page.locator('#restore-confirm').check()
			await page.locator('#backup-restore').click()
			await expect(page).to_have_url(origin + '/backups?restored=1')
			await expect(page.locator('#backup-workspace')).to_be_visible()
			await expect(page.locator('#backup-login')).to_be_hidden()
			await expect(page.locator('#backup-message')).to_contain_text('无需重新登录')
			await page.goto(origin)
			await expect(page.locator('#workspace')).to_be_visible()
			await expect(page.locator('[data-account-id] .card-title')).to_have_text('Local snapshot')
			assert not await page.locator('vite-error-overlay, nextjs-portal').count()
			assert not errors, errors
			assert not console, console
			assert not external, external
			assert not any(
				item['path'].startswith(('/api/setup', '/api/login', '/api/passkey', '/api/security/reauth'))
				for item in requests
			), requests
			assert not any(item['method'] == 'POST' and item['path'] == '/api/runs' for item in requests), requests
			print(
				json.dumps(
					{
						'result': 'passed',
						'screenshots': str(evidence),
						'viewports': ['1440x1080', '390x844'],
						'no_authentication_requests': True,
						'local_restore_without_admin_proof': True,
						'backup_decryption_preserved': True,
						'page_errors': errors,
						'console': console,
						'external_requests': external,
					}
				)
			)
		finally:
			await browser.close()


asyncio.run(main())
