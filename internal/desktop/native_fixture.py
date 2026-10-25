"""Transient Wails/WebView2 acceptance with local data and a virtual authenticator.

Browser plugin not available. No user browser profile or production site is read.
All requests remain inside this test's localhost backend and CDP endpoints.
"""

import asyncio
import ctypes
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

from playwright.async_api import async_playwright, expect

PASSWORD = 'native-desktop-test-password'  # nosec B105
ROOT = Path(sys.argv[2])
SCREENS = Path(tempfile.mkdtemp(prefix='checkin-native-webview-'))
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
# Resolve Windows-only ctypes exports dynamically for cross-platform type checks.
USER32 = getattr(ctypes, 'windll').user32
USER32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
USER32.IsWindowVisible.argtypes = [wintypes.HWND]
USER32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
CALLBACK = getattr(ctypes, 'WINFUNCTYPE')(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def port():
	with socket.socket() as listener:
		listener.bind(('127.0.0.1', 0))
		return listener.getsockname()[1]


def visible_windows(pid):
	windows = []

	def visit(handle, unused):
		owner = wintypes.DWORD()
		USER32.GetWindowThreadProcessId(handle, ctypes.byref(owner))
		if owner.value == pid and USER32.IsWindowVisible(handle):
			windows.append(handle)
		return True

	USER32.EnumWindows(CALLBACK(visit), 0)
	return windows


def get(url):
	with OPENER.open(url, timeout=2) as response:
		return json.load(response)


async def until(check, message, seconds=15):
	deadline = time.monotonic() + seconds
	while time.monotonic() < deadline:
		try:
			value = check()
			if value:
				return value
		except (OSError, ValueError):
			pass
		await asyncio.sleep(0.1)
	raise AssertionError(message)


async def phase(playwright, hidden):
	data = ROOT / ('hidden' if hidden else 'visible')
	backend_port, debug_port = port(), port()
	base = f'http://localhost:{backend_port}'
	debug = f'http://127.0.0.1:{debug_port}'
	environment = dict(os.environ, CHECKIN_DESKTOP_TEST_CDP_PORT=str(debug_port))
	args = [sys.argv[1], '--data-dir', str(data), '--port', str(backend_port)]
	process = await asyncio.to_thread(
		subprocess.Popen,
		[*args, *(['--hidden'] if hidden else [])],
		env=environment,
		stdout=subprocess.DEVNULL,
		stderr=subprocess.PIPE,
	)
	errors = []
	browser = None
	try:
		await until(lambda: get(base + '/healthz').get('ok'), 'native backend did not start')
		if hidden:
			await asyncio.sleep(1)
			assert not visible_windows(process.pid), 'silent startup displayed a window'
			secondary = await asyncio.to_thread(
				subprocess.Popen,
				[*args, '--page', '/status'],
				env=environment,
				stdout=subprocess.DEVNULL,
				stderr=subprocess.PIPE,
			)
			assert await asyncio.to_thread(secondary.wait, 10) == 0
			if secondary.stderr:
				secondary.stderr.close()
		await until(lambda: get(debug + '/json/version'), 'isolated WebView2 CDP did not start')
		browser = await playwright.chromium.connect_over_cdp(debug)
		context = browser.contexts[0]
		page = await until(
			lambda: next((p for p in context.pages if p.url.startswith(base)), None),
			'native page did not load the existing Go WebUI',
		)
		page.on('pageerror', lambda error: errors.append(str(error)))
		await expect(page.locator('#login-view')).to_be_visible()
		await page.locator('#login-password').fill(PASSWORD)
		await page.get_by_role('button', name='登录', exact=True).click()
		await expect(page.locator('#workspace')).to_be_visible()
		await page.wait_for_function('() => window.__checkinDesktopGuard === true')
		external = f'http://127.0.0.1:{port()}/external-test'
		for method in ['link', 'form', 'location', 'open']:
			await page.evaluate(
				"""({method, url}) => {
                  if (method === 'link') { const a = document.createElement('a'); a.href = url; a.textContent = 'External test'; document.body.append(a); a.click(); a.remove(); }
                  if (method === 'form') { const form = document.createElement('form'); form.action = url; document.body.append(form); form.submit(); form.remove(); }
                  if (method === 'location') location.assign(url);
                  if (method === 'open') window.open(url);
                }""",
				{'method': method, 'url': external},
			)
			await expect(page.locator('#checkin-desktop-link-notice')).to_be_visible()
			assert page.url.startswith(base)
			await page.locator('#checkin-desktop-link-notice button').last.click()
		backup_link_allowed = await page.evaluate("""() => {
          const a = document.createElement('a'); a.href = '/api/backups/backup-test.nab'; a.download = ''; document.body.append(a);
          let allowed = false; a.addEventListener('click', event => { allowed = !event.defaultPrevented; event.preventDefault(); });
          a.click(); a.remove(); return allowed;
        }""")
		assert backup_link_allowed, 'native guard blocked an authenticated backup download link'
		assert await page.evaluate('isSecureContext')
		passkey = False
		if not hidden:
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
			await page.goto(base + '/security')
			await expect(page.locator('#security-workspace')).to_be_visible()
			await page.locator('#security-current-password').fill(PASSWORD)
			await page.locator('#security-key-label').fill('Disposable WebView2 virtual key')
			await page.locator('#security-register').click()
			await expect(page.locator('#security-key-count')).to_have_text('1 / 10')
			await page.locator('#verify-passkey').click()
			await expect(page.locator('#security-keys .badge')).to_have_text('已验证')
			await page.screenshot(path=str(SCREENS / 'native-passkey.png'), full_page=True)
			passkey = True
			await page.goto(base + '/')
			await expect(page.locator('#workspace')).to_be_visible()
		assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
		assert not await page.locator('vite-error-overlay, nextjs-portal').count()
		await page.evaluate("window.__fixtureUnsavedDraft = 'preserve-me'")
		reopen = await asyncio.to_thread(
			subprocess.Popen, args, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
		)
		assert await asyncio.to_thread(reopen.wait, 10) == 0
		if reopen.stderr:
			reopen.stderr.close()
		await asyncio.sleep(0.3)
		assert await page.evaluate('window.__fixtureUnsavedDraft') == 'preserve-me', (
			'ordinary activation reloaded unsaved state'
		)
		await page.screenshot(path=str(SCREENS / f'{"hidden" if hidden else "visible"}-webview.png'), full_page=True)
		handles = await until(lambda: visible_windows(process.pid), 'native main window is not visible')
		USER32.PostMessageW(handles[0], 0x0010, 0, 0)
		await until(lambda: not visible_windows(process.pid), 'closing the native window did not hide it')
		assert process.poll() is None
		assert get(base + '/healthz')['ok']
		quiet = await asyncio.to_thread(
			subprocess.Popen, [*args, '--hidden'], env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
		)
		assert await asyncio.to_thread(quiet.wait, 10) == 0
		if quiet.stderr:
			quiet.stderr.close()
		await asyncio.sleep(0.25)
		assert not visible_windows(process.pid), 'second silent launch activated the window'
		secondary = await asyncio.to_thread(
			subprocess.Popen,
			[*args, '--page', '/status'],
			env=environment,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.PIPE,
		)
		assert await asyncio.to_thread(secondary.wait, 10) == 0
		if secondary.stderr:
			secondary.stderr.close()
		await until(lambda: visible_windows(process.pid), 'second launch did not restore the primary window')
		await expect(page).to_have_url(base + '/status')
		await expect(page.locator('#workspace')).to_be_visible()
		assert (data / 'fixture-start-count').read_text().splitlines() == ['1']
		await page.screenshot(path=str(SCREENS / f'{"hidden" if hidden else "visible"}-restored.png'), full_page=True)
		assert not errors, errors
		request = urllib.request.Request(base + '/fixture/quit', data=b'', method='POST')
		with OPENER.open(request, timeout=3) as response:
			assert response.status == 202
		assert await asyncio.to_thread(process.wait, 15) == 0
		await asyncio.sleep(0.5)
		assert (data / 'fixture-stop-count').read_text().splitlines() == ['1']
		return {
			'hidden': hidden,
			'start_callbacks': 1,
			'stop_callbacks': 1,
			'close_hides': True,
			'single_instance': True,
			'secure_context': True,
			'external_navigation_blocked': True,
			'activation_preserves_draft': True,
			'passkey_verified': passkey,
			'page_errors': errors,
		}
	finally:
		if process.poll() is None:
			process.terminate()
			await asyncio.to_thread(process.wait, 10)
		if process.stderr:
			process.stderr.close()
		if browser:
			await browser.close()
		await asyncio.sleep(1)


async def main():
	async with async_playwright() as playwright:
		if '--download-only' in sys.argv:
			result = await backup_download(playwright)
			print(json.dumps({'result': 'passed', 'screenshots': str(SCREENS), 'backup_download': result}))
			return
		results = [await phase(playwright, False), await phase(playwright, True)]
	print(json.dumps({'result': 'passed', 'screenshots': str(SCREENS), 'phases': results}))


async def backup_download(playwright):
	data = ROOT / 'download'
	downloads = ROOT / 'downloaded-files'
	downloads.mkdir()
	backend_port, debug_port = port(), port()
	base = f'http://localhost:{backend_port}'
	debug = f'http://127.0.0.1:{debug_port}'
	environment = dict(os.environ, CHECKIN_DESKTOP_TEST_CDP_PORT=str(debug_port))
	args = [sys.argv[1], '--data-dir', str(data), '--port', str(backend_port), '--page', '/backups']
	process = await asyncio.to_thread(
		subprocess.Popen, args, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
	)
	browser = None
	errors = []
	try:
		await until(lambda: get(base + '/healthz').get('ok'), 'download fixture backend did not start')
		await until(lambda: get(debug + '/json/version'), 'download fixture WebView2 CDP did not start')
		browser = await playwright.chromium.connect_over_cdp(debug)
		cdp = await browser.new_browser_cdp_session()
		await cdp.send(
			'Browser.setDownloadBehavior', {'behavior': 'allow', 'downloadPath': str(downloads), 'eventsEnabled': True}
		)
		events = []
		cdp.on('Browser.downloadProgress', lambda event: events.append(event))
		context = browser.contexts[0]
		page = await until(
			lambda: next((p for p in context.pages if p.url.startswith(base)), None), 'native backups page not loaded'
		)
		page.on('pageerror', lambda error: errors.append(str(error)))
		await expect(page.locator('#backup-login')).to_be_visible()
		await page.locator('#backup-login-password').fill(PASSWORD)
		await page.locator('#backup-login-form').get_by_role('button', name='登录', exact=True).click()
		await expect(page.locator('#backup-workspace')).to_be_visible()
		await page.wait_for_function('() => window.__checkinDesktopGuard === true')
		await page.locator('#backup-password').fill('synthetic-native-recovery-password')
		await page.locator('#backup-save').click()
		await expect(page.locator('#backup-message')).to_contain_text('备份设置已保存')
		await page.locator('#backup-create').click()
		link = page.get_by_role('link', name='下载加密备份', exact=True)
		await expect(link).to_have_count(1)
		await link.click()
		completed = await until(
			lambda: next((event for event in events if event.get('state') == 'completed'), None),
			'native WebView2 download did not complete',
			seconds=20,
		)
		assert completed
		files = list(downloads.glob('*.nab'))
		assert len(files) == 1, list(downloads.iterdir())
		copied = files[0].read_bytes()
		source_files = list((data / 'backups').glob('*.nab'))
		assert len(source_files) == 1
		source = source_files[0].read_bytes()
		assert copied == source
		assert copied.startswith(b'NEWAPI-BACKUP\x00\x01')
		assert len(copied) > 4096 and not copied.lstrip().startswith((b'<!doctype', b'<html'))
		assert await page.locator('#checkin-desktop-link-notice').count() == 0
		assert page.url == base + '/backups'
		assert not errors, errors
		await page.screenshot(path=str(SCREENS / 'native-backup-download.png'), full_page=True)
		request = urllib.request.Request(base + '/fixture/quit', data=b'', method='POST')
		with OPENER.open(request, timeout=3) as response:
			assert response.status == 202
		assert await asyncio.to_thread(process.wait, 15) == 0
		return {
			'bytes': len(copied),
			'sha256': hashlib.sha256(copied).hexdigest(),
			'matches_encrypted_source': True,
			'guard_allowed': True,
			'native_download_completed': True,
			'page_errors': errors,
		}
	finally:
		if process.poll() is None:
			process.terminate()
			await asyncio.to_thread(process.wait, 10)
		if process.stderr:
			process.stderr.close()
		if browser:
			await browser.close()
		await asyncio.sleep(1)


asyncio.run(main())
