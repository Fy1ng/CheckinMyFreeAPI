"""Real Go WebUI acceptance using disposable data and Chrome virtual keys.

Browser plugin not available. The flow under test is first setup -> save an
account -> inspect Status/notifications/backups -> persist startup settings.
The independent HTTPS fixture verifies that Passkey mode closes public passwords.
All browser requests stay inside the two local Go test servers.
"""

import asyncio
import json
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import async_playwright, expect

PASSWORD = 'synthetic-Go-app-browser-password'  # nosec B105
COOKIE = 'session=synthetic-Go-app-browser-cookie'
NOTIFY_TOKEN = 'synthetic-Go-app-browser-notify-token'  # nosec B105
PUBLIC_ORIGIN = 'https://go-app.example.test'


async def inspect(page, screenshots, name):
	assert await page.locator('main').inner_text()
	assert not await page.locator('vite-error-overlay, nextjs-portal').count()
	assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
	await page.screenshot(path=str(screenshots / f'{name}.png'), full_page=True)


async def local_flow(browser, local, screenshots):
	context = await browser.new_context(viewport={'width': 1440, 'height': 1080})
	errors, console, blocked, requests = [], [], [], []

	async def guard(route):
		request = route.request
		requests.append((request.method, urlsplit(request.url).path))
		if not request.url.startswith(local + '/'):
			blocked.append(request.url)
			await route.abort()
			return
		assert not (
			request.method == 'POST'
			and urlsplit(request.url).path in {'/api/runs', '/api/runtime/autostart', '/api/automation/summary'}
		)
		await route.continue_()

	await context.route('**/*', guard)
	page = await context.new_page()
	page.set_default_timeout(8000)
	page.on('pageerror', lambda error: errors.append(str(error)))
	page.on(
		'console',
		lambda message: console.append(
			{'type': message.type, 'text': message.text, 'url': message.location.get('url', '')}
		)
		if message.type in {'error', 'warning'}
		else None,
	)
	try:
		await page.goto(local + '/')
		assert page.url == local + '/'
		assert await page.title() == 'NewAPI 签到控制台'
		await expect(page.locator('#login-confirm-password')).to_be_visible()
		await page.locator('#login-password').fill(PASSWORD)
		await page.locator('#login-confirm-password').fill(PASSWORD)
		async with page.expect_response(
			lambda response: response.url == local + '/api/setup' and response.request.method == 'POST'
		) as configured:
			await page.locator('#login-button').click()
		assert (await configured.value).status == 201
		# The UI follows setup with an ordinary password login using the freshly
		# configured password. The setup response itself never issues a session.
		await expect(page.locator('#workspace')).to_be_visible()
		await expect(page.locator('#login-confirm-password')).to_be_hidden()
		notice = page.locator('#global-message')
		acknowledgement = page.get_by_role('button', name='我已知晓', exact=True)
		await expect(acknowledgement).to_be_visible()
		await expect(notice).to_contain_text('旧配置已保留并转换为 HTTP 配置')
		bounds = await acknowledgement.bounding_box()
		text_bounds = await notice.locator('span').bounding_box()
		assert bounds and text_bounds and bounds['x'] >= text_bounds['x'] + text_bounds['width']
		await acknowledgement.click()
		await expect(notice).to_be_hidden()
		await page.reload()
		await expect(page.locator('#workspace')).to_be_visible()
		await expect(acknowledgement).to_have_count(0)
		assert await page.evaluate("localStorage.getItem('newapi.migration.acknowledged:1:0')") == '1'

		await page.get_by_role('button', name='+ 添加账号', exact=True).click()
		await page.get_by_label(re.compile('^账号名称')).fill('Isolated Go account')
		await page.get_by_label('Cookie', exact=True).fill(COOKIE)
		await page.get_by_label(re.compile('^目标站点用户 ID')).fill('17')
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#dirty-status')).to_have_text('所有修改已保存')
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 1')
		await expect(page.get_by_label('Cookie', exact=True)).to_have_value('')
		await expect(page.get_by_label('Cookie', exact=True)).to_have_attribute('placeholder', '已设置, 留空保留')
		snapshot = await page.evaluate("async () => (await fetch('/api/config')).json()")
		assert snapshot['config']['accounts'][0]['cookies'] == '__UNCHANGED_SECRET__'
		assert COOKIE not in json.dumps(snapshot)
		assert COOKIE not in await page.locator('body').inner_text()
		await expect(acknowledgement).to_have_count(0)

		await page.locator('[data-tab="notifications"]').click()
		group = page.locator('details.notification-group').filter(has=page.locator('summary', has_text='Fy1Push'))
		await group.locator('summary').click()
		await group.get_by_label(re.compile('^服务器 URL')).fill('https://push.example.test')
		await group.get_by_label('发送 token', exact=True).fill(NOTIFY_TOKEN)
		await page.get_by_role('button', name='保存配置', exact=True).click()
		await expect(page.locator('#config-revision')).to_have_text('已保存版本 2')
		group = page.locator('details.notification-group').filter(has=page.locator('summary', has_text='Fy1Push'))
		await expect(group.get_by_label('发送 token', exact=True)).to_have_value('')
		snapshot = await page.evaluate("async () => (await fetch('/api/config')).json()")
		assert snapshot['config']['accounts'][0]['cookies'] == '__UNCHANGED_SECRET__'
		assert snapshot['config']['notifications']['FY1PUSH_TOKEN'] == '__UNCHANGED_SECRET__'
		assert NOTIFY_TOKEN not in json.dumps(snapshot)

		await page.locator('[data-tab="runtime"]').click()
		panel = page.locator('.go-runtime-panel')
		await expect(panel).to_be_visible()
		await page.locator('#runtime-startup-checkin').uncheck()
		await page.locator('#runtime-startup-delay').fill('23')
		async with page.expect_response(
			lambda response: response.url == local + '/api/runtime' and response.request.method == 'PUT'
		) as saved:
			await page.locator('#runtime-save').click()
		assert (await saved.value).status == 200
		await expect(page.locator('#runtime-startup-checkin')).not_to_be_checked()
		runtime = await page.evaluate("async () => (await fetch('/api/runtime')).json()")
		assert runtime['settings']['run_on_startup'] is False
		assert runtime['settings']['startup_delay_seconds'] == 23
		await inspect(page, screenshots, 'desktop-runtime')
		await page.reload()
		await expect(page.locator('#workspace')).to_be_visible()
		await page.locator('[data-tab="runtime"]').click()
		await expect(page.locator('#runtime-startup-checkin')).not_to_be_checked()
		await expect(page.locator('#runtime-startup-delay')).to_have_value('23')
		await page.set_viewport_size({'width': 390, 'height': 844})
		await inspect(page, screenshots, 'mobile-runtime')

		await page.goto(local + '/status')
		await expect(page.locator('#balance-view')).to_be_visible()
		await expect(page.locator('#balance-accounts')).to_contain_text('Isolated Go account')
		await expect(page.locator('#balances-error')).to_be_hidden()
		await expect(page.locator('#automation-error')).to_be_hidden()
		await inspect(page, screenshots, 'mobile-status')
		await page.set_viewport_size({'width': 1440, 'height': 1080})
		await inspect(page, screenshots, 'desktop-status')

		await page.goto(local + '/backups')
		assert await page.title() == '备份与恢复 | NewAPI'
		await expect(page.locator('#backup-workspace')).to_be_visible()
		await expect(page.locator('#backup-reload')).to_be_enabled()
		assert await page.locator('#backup-retention').input_value() == '7'
		await inspect(page, screenshots, 'desktop-backups')
		assert not blocked, blocked
		assert not errors, errors
		assert not console, console
		assert ('POST', '/api/setup') in requests
		return {'requests': len(requests), 'page_errors': errors, 'console': console, 'external_requests': blocked}
	except Exception:
		await page.screenshot(path=str(screenshots / 'local-failure.png'), full_page=True)
		print(
			json.dumps(
				{
					'phase': 'local',
					'page_errors': errors,
					'console': console,
					'screenshot': str(screenshots / 'local-failure.png'),
				}
			),
			flush=True,
		)
		raise
	finally:
		await context.close()


async def public_flow(browser, public, screenshots):
	context = await browser.new_context(viewport={'width': 1440, 'height': 1080})
	errors, console, blocked = [], [], []

	async def forward(route):
		request = route.request
		if not request.url.startswith(PUBLIC_ORIGIN + '/'):
			blocked.append(request.url)
			await route.abort()
			return
		headers = await request.all_headers()
		headers.update({'host': 'go-app.example.test', 'x-forwarded-proto': 'https', 'x-forwarded-for': '203.0.113.9'})
		response = await route.fetch(url=public + urlsplit(request.url).path, headers=headers)
		await route.fulfill(response=response)

	await context.route('**/*', forward)
	page = await context.new_page()
	page.set_default_timeout(8000)
	page.on('pageerror', lambda error: errors.append(str(error)))
	page.on(
		'console',
		lambda message: console.append(
			{'type': message.type, 'text': message.text, 'url': message.location.get('url', '')}
		)
		if message.type in {'error', 'warning'}
		else None,
	)
	cdp = await context.new_cdp_session(page)
	await cdp.send('WebAuthn.enable')
	await cdp.send(
		'WebAuthn.addVirtualAuthenticator',
		{
			'options': {
				'protocol': 'ctap2',
				'transport': 'internal',
				'hasResidentKey': True,
				'hasUserVerification': True,
				'isUserVerified': True,
				'automaticPresenceSimulation': True,
			}
		},
	)
	try:
		await page.goto(PUBLIC_ORIGIN + '/security')
		await page.locator('#security-login-password').fill(PASSWORD)
		await page.locator('#security-login-button').click()
		await expect(page.locator('#security-workspace')).to_be_visible()
		await page.locator('#security-current-password').fill(PASSWORD)
		await page.locator('#security-key-label').fill('Isolated complete Go app virtual key')
		await page.locator('#security-register').click()
		await expect(page.locator('#security-key-count')).to_have_text('1 / 10')
		await page.locator('#verify-passkey').click()
		await expect(page.locator('#security-keys .badge')).to_have_text('已验证')
		await page.locator('#enable-passkey-mode').click()
		await expect(page.locator('#security-mode-badge')).to_have_text('Passkey 版')
		result = await page.evaluate(
			"""async (password) => {
            const response = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({password})});
            return {status: response.status, body: await response.json()};
        }""",
			PASSWORD,
		)
		assert result['status'] == 403
		await page.goto(PUBLIC_ORIGIN + '/')
		await expect(page.locator('#workspace')).to_be_visible()
		await page.locator('#logout-button').click()
		await expect(page.locator('#login-view')).to_be_visible()
		await expect(page.locator('#password-login-controls')).to_be_hidden()
		await expect(page.locator('#passkey-login-button')).to_be_visible()
		await inspect(page, screenshots, 'desktop-passkey-login')
		await page.locator('#passkey-login-button').click()
		await expect(page.locator('#workspace')).to_be_visible()
		unexpected = [
			item for item in console if not (item['url'] == PUBLIC_ORIGIN + '/api/login' and '403' in item['text'])
		]
		assert not errors, errors
		assert not unexpected, unexpected
		assert not blocked, blocked
		return {
			'public_password_status': result['status'],
			'page_errors': errors,
			'console': console,
			'external_requests': blocked,
		}
	except Exception:
		await page.screenshot(path=str(screenshots / 'public-failure.png'), full_page=True)
		print(
			json.dumps(
				{
					'phase': 'public',
					'page_errors': errors,
					'console': console,
					'screenshot': str(screenshots / 'public-failure.png'),
				}
			),
			flush=True,
		)
		raise
	finally:
		await context.close()


async def main():
	screenshots = Path(os.getenv('CHECKIN_GO_APP_SCREENSHOT_DIR') or tempfile.mkdtemp(prefix='checkin-go-app-browser-'))
	screenshots.mkdir(parents=True, exist_ok=True)
	print(json.dumps({'screenshots': str(screenshots)}), flush=True)
	async with async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome'), headless=True
		)
		try:
			local = await local_flow(browser, sys.argv[1], screenshots)
			public = await public_flow(browser, sys.argv[2], screenshots)
			print(
				json.dumps(
					{
						'result': 'passed',
						'screenshots': str(screenshots),
						'viewports': ['1440x1080', '390x844'],
						'local': local,
						'public': public,
					}
				),
				flush=True,
			)
		finally:
			await browser.close()


if __name__ == '__main__':
	asyncio.run(main())
