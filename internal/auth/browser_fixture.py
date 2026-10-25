"""Isolated real-browser contract check for the Go authentication package.

Browser plugin not available. Runs only when CHECKIN_AUTH_BROWSER_TESTS=1.
All network requests are forwarded to the disposable local Go test server.
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from playwright.async_api import async_playwright, expect

ORIGIN = 'https://security.example.test'
PASSWORD = 'synthetic-Go-test-admin-password'  # nosec B105


async def main():
	local = sys.argv[1]
	screenshots = Path(
		os.getenv('CHECKIN_GO_AUTH_SCREENSHOT_DIR') or tempfile.mkdtemp(prefix='checkin-go-auth-browser-')
	)
	screenshots.mkdir(parents=True, exist_ok=True)
	async with async_playwright() as playwright:
		browser = await playwright.chromium.launch(
			channel=os.getenv('CHECKIN_TEST_BROWSER_CHANNEL', 'chrome'), headless=True
		)
		context = await browser.new_context(viewport={'width': 1440, 'height': 1080})
		blocked, errors, warnings = [], [], []

		async def forward(route):
			request = route.request
			if not request.url.startswith(ORIGIN + '/'):
				blocked.append(request.url)
				await route.abort()
				return
			headers = await request.all_headers()
			headers.update(
				{'host': 'security.example.test', 'x-forwarded-proto': 'https', 'x-forwarded-for': '203.0.113.8'}
			)
			response = await route.fetch(url=local + urlsplit(request.url).path, headers=headers)
			await route.fulfill(response=response)

		await context.route('**/*', forward)
		page = await context.new_page()
		page.on('pageerror', lambda error: errors.append(str(error)))
		page.on('console', lambda message: warnings.append(message.text) if message.type == 'warning' else None)
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
		await page.goto(ORIGIN + '/security')
		assert page.url == ORIGIN + '/security'
		assert await page.title() == '登录与安全 | NewAPI'
		await expect(page.locator('#security-login')).to_be_visible()
		await page.locator('#security-login-password').fill(PASSWORD)
		await page.locator('#security-login-button').click()
		await expect(page.locator('#security-workspace')).to_be_visible()
		await page.locator('#security-current-password').fill(PASSWORD)
		await page.locator('#security-key-label').fill('Isolated Go Chrome virtual key')
		await page.locator('#security-register').click()
		await expect(page.locator('#security-key-count')).to_have_text('1 / 10')
		await expect(page.locator('#security-keys .badge')).to_have_text('待验证')
		await page.locator('#verify-passkey').click()
		await expect(page.locator('#security-keys .badge')).to_have_text('已验证')
		await page.locator('#enable-passkey-mode').click()
		await expect(page.locator('#security-mode-badge')).to_have_text('Passkey 版')
		await expect(page.locator('[data-delete-passkey]')).to_be_disabled()
		await page.screenshot(path=str(screenshots / 'desktop.png'), full_page=True)
		await page.set_viewport_size({'width': 390, 'height': 844})
		await page.screenshot(path=str(screenshots / 'mobile.png'), full_page=True)
		await page.locator('#security-logout').click()
		await expect(page.locator('#security-login')).to_be_visible()
		await expect(page.locator('#security-password-login')).to_be_hidden()
		await page.locator('#security-passkey-login').click()
		await expect(page.locator('#security-workspace')).to_be_visible()
		await expect(page.locator('#security-mode-badge')).to_have_text('Passkey 版')
		result = await page.evaluate(
			"""async (password) => {
            const response = await fetch('/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({password})});
            return {status: response.status, body: await response.json()};
        }""",
			PASSWORD,
		)
		assert result['status'] == 403
		page.on('dialog', lambda dialog: dialog.accept())
		await page.locator('#enable-password-mode').click()
		await expect(page.locator('#security-mode-badge')).to_have_text('密码版')
		await page.locator('#security-current-password').fill(PASSWORD)
		await page.locator('[data-delete-passkey]').click()
		await expect(page.locator('#security-key-count')).to_have_text('0 / 10')
		assert not errors, errors
		assert not blocked, blocked
		assert not warnings, warnings
		print(
			json.dumps(
				{
					'result': 'passed',
					'screenshots': str(screenshots),
					'viewports': ['1440x1080', '390x844'],
					'page_errors': errors,
					'warnings': warnings,
				}
			)
		)
		await browser.close()


if __name__ == '__main__':
	asyncio.run(main())
