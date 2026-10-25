"""Opt-in full Windows desktop acceptance with disposable data and WebView2.

Run this script explicitly from the repository's Python environment. The desktop
executable must be built with desktop,desktoptest,production; --build creates
that test executable in a private temporary directory. It never installs an
autostart entry, sends notifications, or configures a real account. Local owned
desktops enter directly without an administrator setup or verification request;
an attached server must keep its existing administrator authentication.
"""

import argparse
import asyncio
import contextlib
import ctypes
import hashlib
import http.cookiejar
import json
import os
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

from playwright.async_api import async_playwright, expect

PASSWORD = 'synthetic-windows-product-password'  # nosec B105
REPOSITORY = Path(__file__).resolve().parents[1]


def free_port():
	with socket.socket() as listener:
		listener.bind(('127.0.0.1', 0))
		return listener.getsockname()[1]


def json_get(address):
	opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
	with opener.open(address, timeout=1) as response:
		return json.load(response)


class API:
	def __init__(self, origin):
		self.origin, self.csrf = origin, ''
		self.opener = urllib.request.build_opener(
			urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
		)

	def request(self, path, body=None, method=None):
		headers = {'Accept': 'application/json', 'Origin': self.origin}
		if body is not None:
			headers['Content-Type'] = 'application/json'
		if self.csrf:
			headers['X-CSRF-Token'] = self.csrf
		request = urllib.request.Request(
			self.origin + path,
			data=json.dumps(body).encode() if body is not None else None,
			headers=headers,
			method=method,
		)
		with self.opener.open(request, timeout=5) as response:
			return json.load(response)

	def login(self):
		self.csrf = self.request('/api/login', {'password': PASSWORD})['csrf']


async def wait_for(check, label, seconds=20):
	deadline, last = time.monotonic() + seconds, None
	while time.monotonic() < deadline:
		try:
			value = check()
			if value:
				return value
		except (OSError, ValueError, subprocess.SubprocessError) as error:
			last = type(error).__name__
		await asyncio.sleep(0.1)
	raise AssertionError(f'{label} did not complete ({last})')


def native_api():
	# These exports exist only on Windows, where this opt-in fixture runs.
	user32 = getattr(ctypes, 'windll').user32
	user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
	user32.IsWindowVisible.argtypes = [wintypes.HWND]
	user32.IsWindowVisible.restype = wintypes.BOOL
	user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
	user32.PostMessageW.restype = wintypes.BOOL
	user32.SetForegroundWindow.argtypes = [wintypes.HWND]
	user32.SetForegroundWindow.restype = wintypes.BOOL
	user32.GetForegroundWindow.restype = wintypes.HWND
	user32.AttachThreadInput.argtypes = [wintypes.DWORD, wintypes.DWORD, wintypes.BOOL]
	user32.AttachThreadInput.restype = wintypes.BOOL
	user32.GetKeyboardState.argtypes = [ctypes.POINTER(wintypes.BYTE)]
	user32.SetKeyboardState.argtypes = [ctypes.POINTER(wintypes.BYTE)]
	user32.SendMessageTimeoutW.argtypes = [
		wintypes.HWND,
		wintypes.UINT,
		wintypes.WPARAM,
		wintypes.LPARAM,
		wintypes.UINT,
		wintypes.UINT,
		ctypes.POINTER(ctypes.c_size_t),
	]
	return user32


def visible_windows(pid):
	user32, result = native_api(), []
	callback = getattr(ctypes, 'WINFUNCTYPE')(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

	def visit(handle, unused):
		owner = wintypes.DWORD()
		user32.GetWindowThreadProcessId(handle, ctypes.byref(owner))
		if owner.value == pid and user32.IsWindowVisible(handle):
			result.append(handle)
		return True

	user32.EnumWindows(callback(visit), 0)
	return result


def close_native_window(pid):
	handles = visible_windows(pid)
	assert len(handles) == 1, f'expected one owned native window, found {len(handles)}'
	assert native_api().PostMessageW(handles[0], 0x0010, 0, 0), 'native close message failed'


async def quit_native_shortcut(pid):
	"""Exercise the real native accelerator without sending global keystrokes."""
	handles = visible_windows(pid)
	assert len(handles) == 1
	user32 = native_api()
	thread = user32.GetWindowThreadProcessId(handles[0], None)
	current = getattr(ctypes, 'windll').kernel32.GetCurrentThreadId()
	# A background test runner cannot always acquire foreground focus. Attaching
	# only these input queues lets the owned HWND process Ctrl+Q using Wails'
	# native GetKeyboardState handler, with no event sent to another window.
	assert user32.AttachThreadInput(current, thread, True), 'owned input queue attachment failed'
	original = (wintypes.BYTE * 256)()
	assert user32.GetKeyboardState(original)
	modified = (wintypes.BYTE * 256).from_buffer_copy(original)
	modified[0x11] |= 0x80
	try:
		assert user32.SetKeyboardState(modified)
		result = ctypes.c_size_t()
		assert user32.SendMessageTimeoutW(handles[0], 0x0100, 0x51, 0, 2, 3000, ctypes.byref(result)), (
			'owned Ctrl+Q message failed'
		)
	finally:
		user32.SetKeyboardState(original)
		user32.AttachThreadInput(current, thread, False)


def instance(data):
	return json.loads((data / 'desktop-control.json').read_text(encoding='utf-8'))['instance']


def assert_no_runs(data):
	with sqlite3.connect(data / 'webui.sqlite3') as database:
		assert database.execute('SELECT count(*) FROM runs').fetchone()[0] == 0
		assert database.execute('SELECT count(*) FROM http_sessions').fetchone()[0] == 0


class Processes:
	def __init__(self):
		self.items = []

	def start(self, binary, arguments, debug_port=None):
		environment = dict(os.environ)
		for name in list(environment):
			if name.startswith('CHECKIN_') or name.startswith('WEBVIEW2_'):
				del environment[name]
		if debug_port is not None:
			environment['CHECKIN_DESKTOP_TEST_CDP_PORT'] = str(debug_port)
		process = subprocess.Popen(
			[str(binary), *arguments],
			env=environment,
			stdin=subprocess.DEVNULL,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.PIPE,
		)
		self.items.append(process)
		return process

	async def secondary(self, binary, arguments, debug_port):
		process = self.start(binary, arguments, debug_port)
		assert await asyncio.to_thread(process.wait, 15) == 0, 'secondary desktop launch did not exit cleanly'

	def close(self):
		for process in reversed(self.items):
			if process.poll() is None:
				process.terminate()
				with contextlib.suppress(subprocess.TimeoutExpired):
					process.wait(timeout=10)
				if process.poll() is None:
					process.kill()
					process.wait(timeout=10)
			if process.stderr is not None:
				process.stderr.close()


async def connect(playwright, base, debug_port, evidence):
	debug = f'http://127.0.0.1:{debug_port}'
	await wait_for(lambda: json_get(debug + '/json/version'), 'test WebView2 CDP endpoint')
	browser = await playwright.chromium.connect_over_cdp(debug)
	context = browser.contexts[0]
	page = await wait_for(
		lambda: next((item for item in context.pages if item.url.startswith(base + '/')), None), 'native product WebUI'
	)
	page.set_default_timeout(10000)
	page.on('pageerror', lambda error: evidence['page_errors'].append(str(error)))
	page.on(
		'console',
		lambda message: evidence['console'].append(
			{'type': message.type, 'text': message.text, 'url': message.location.get('url', '')}
		)
		if message.type in {'warning', 'error'}
		else None,
	)
	page.on(
		'request',
		lambda request: evidence['external_requests'].append(request.url)
		if request.url.startswith(('http:', 'https:')) and not request.url.startswith(base + '/')
		else None,
	)
	page.on(
		'request',
		lambda request: evidence.setdefault('management_requests', []).append(request.url.removeprefix(base))
		if request.url.startswith(base + '/api/')
		else None,
	)
	evidence.setdefault('management_requests', []).extend(
		await page.evaluate(
			"""origin => performance.getEntriesByType('resource').map(entry => entry.name)
            .filter(url => url.startsWith(origin + '/api/')).map(url => url.slice(origin.length))""",
			base,
		)
	)
	return browser, page


async def inspect(page, report, label):
	expected_title = '账户 Status | NewAPI' if page.url.endswith('/status') else 'NewAPI 签到控制台'
	await expect(page).to_have_title(expected_title)
	assert await page.locator('main').inner_text()
	assert not await page.locator('vite-error-overlay, nextjs-portal').count()
	assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
	await page.screenshot(path=str(report / f'{label}.png'), full_page=True)


def assert_console(evidence):
	unexplained = [
		item
		for item in evidence['console']
		if not (item['url'].endswith('/favicon.ico') and '404 (Not Found)' in item['text'])
	]
	assert not unexplained, unexplained


async def login_page(page, setup=False):
	await expect(page.locator('#login-view')).to_be_visible()
	await page.locator('#login-password').fill(PASSWORD)
	if setup:
		await expect(page.locator('#login-confirm-password')).to_be_visible()
		await page.locator('#login-confirm-password').fill(PASSWORD)
	await page.locator('#login-button').click()
	await expect(page.locator('#workspace')).to_be_visible()
	await page.wait_for_function('() => window.__checkinDesktopGuard === true')


async def local_workspace(page):
	await expect(page.locator('#workspace')).to_be_visible()
	await expect(page.locator('#login-view')).to_be_hidden()
	await expect(page.locator('#logout-button')).to_be_hidden()
	await expect(page.locator('.workspace-nav a[href="/security"]')).to_be_hidden()
	policy = await page.evaluate("async () => (await fetch('/api/session')).json()")
	assert policy['authenticated'] is True and policy['local_mode'] is True
	assert policy['auth_mode'] == 'local' and policy['reauth_method'] == 'none'
	assert not policy['password_login_allowed'] and not policy['passkey_available']
	assert policy['csrf'] and not policy.get('setup_required', False)
	await page.wait_for_function('() => window.__checkinDesktopGuard === true')


async def runtime_panel(page, expected_desktop):
	if not page.url.endswith('/'):
		await page.goto(page.url.split('/status')[0].rstrip('/') + '/')
	await page.locator('[data-tab="runtime"]').click()
	await expect(page.locator('.go-runtime-panel')).to_be_visible()
	settings = await page.evaluate("async () => (await fetch('/api/runtime')).json()")
	assert settings['desktop'] is expected_desktop
	await expect(page.locator('#runtime-autostart')).to_be_visible()
	return settings


async def exit_backend_from_page(page, process):
	accepted = []

	async def accept(dialog):
		assert dialog.type == 'confirm'
		accepted.append(True)
		await dialog.accept()

	page.once('dialog', accept)
	await page.locator('#runtime-exit').click()
	assert await asyncio.to_thread(process.wait, 20) == 0, 'owned desktop/backend did not exit'
	assert accepted, 'shutdown confirmation was not shown'
	assert not visible_windows(process.pid)


async def owned_scenario(playwright, binary, report, processes, root):
	data, backend_port, debug_port = root / 'owned-data', free_port(), free_port()
	base = f'http://localhost:{backend_port}'
	args = ['app', '--data-dir', str(data), '--port', str(backend_port)]
	evidence: dict[str, list] = {'page_errors': [], 'console': [], 'external_requests': []}
	process = processes.start(binary, args, debug_port)
	await wait_for(lambda: json_get(base + '/healthz').get('ok'), 'new local product backend')
	assert not json_get(base + '/healthz').get('setup_required', False), 'local startup requested password setup'
	await wait_for(lambda: visible_windows(process.pid), 'new native product window')
	first_instance = instance(data)
	key_digest = hashlib.sha256((data / 'master.key').read_bytes()).hexdigest()
	browser, page = await connect(playwright, base, debug_port, evidence)
	try:
		await local_workspace(page)
		await page.goto(base + '/security')
		await expect(page.locator('#security-login')).to_be_hidden()
		await expect(page.locator('#security-current-password')).to_be_hidden()
		await expect(page.locator('#security-register')).to_be_hidden()
		await expect(page.locator('main')).to_contain_text('本地')
		await page.screenshot(path=str(report / 'windows-local-security.png'), full_page=True)
		await page.goto(base + '/')
		await local_workspace(page)
		await runtime_panel(page, True)
		await expect(page.locator('.go-runtime-panel')).to_contain_text('关闭窗口后隐藏到托盘')
		await page.locator('#runtime-startup-checkin').uncheck()
		await page.locator('#runtime-startup-delay').fill('17')
		await page.locator('#runtime-save').click()
		await expect(page.locator('.go-runtime-panel .inline-message')).to_contain_text('启动设置已保存')
		settings = await page.evaluate("async () => (await fetch('/api/runtime')).json()")
		assert settings['settings']['run_on_startup'] is False
		assert settings['settings']['startup_delay_seconds'] == 17
		await inspect(page, report, 'windows-owned-runtime')
		close_native_window(process.pid)
		await wait_for(lambda: not visible_windows(process.pid), 'close to tray')
		assert process.poll() is None and json_get(base + '/healthz')['ok']
		await processes.secondary(binary, [*args, '--hidden'], debug_port)
		await asyncio.sleep(0.4)
		assert not visible_windows(process.pid), 'a secondary hidden launch opened a window'
		await processes.secondary(binary, [*args, '--page', '/status'], debug_port)
		await wait_for(lambda: visible_windows(process.pid), 'secondary activation')
		await expect(page).to_have_url(base + '/status')
		await expect(page.locator('#workspace')).to_be_visible()
		assert instance(data) == first_instance
		assert_no_runs(data)
		await inspect(page, report, 'windows-owned-restored-status')
		await page.goto(base + '/')
		await expect(page.locator('#workspace')).to_be_visible()
		await runtime_panel(page, True)
		await exit_backend_from_page(page, process)
		await wait_for(lambda: not (data / 'desktop-control.json').exists(), 'owned identity removal')
	finally:
		with contextlib.suppress(Exception):
			await browser.close()
	# A genuine new hidden startup owns the existing persisted empty database.
	debug_port = free_port()
	hidden = processes.start(binary, [*args, '--hidden'], debug_port)
	await wait_for(lambda: json_get(base + '/healthz').get('ok'), 'hidden product restart')
	await asyncio.sleep(0.8)
	assert not visible_windows(hidden.pid), 'primary --hidden startup opened a window'
	hidden_instance = instance(data)
	assert hidden_instance != first_instance
	assert hashlib.sha256((data / 'master.key').read_bytes()).hexdigest() == key_digest
	await processes.secondary(binary, [*args, '--hidden'], debug_port)
	await asyncio.sleep(0.25)
	assert not visible_windows(hidden.pid)
	assert_no_runs(data)
	await processes.secondary(binary, [*args, '--page', '/status'], debug_port)
	await wait_for(lambda: visible_windows(hidden.pid), 'hidden instance activation')
	browser, page = await connect(playwright, base, debug_port, evidence)
	try:
		await expect(page).to_have_url(base + '/status')
		await local_workspace(page)
		assert instance(data) == hidden_instance
		await inspect(page, report, 'windows-hidden-restored-status')
		await page.goto(base + '/')
		await expect(page.locator('#workspace')).to_be_visible()
		await runtime_panel(page, True)
		await expect(page.locator('#runtime-startup-checkin')).not_to_be_checked()
		await expect(page.locator('#runtime-startup-delay')).to_have_value('17')
		await exit_backend_from_page(page, hidden)
		await wait_for(lambda: not (data / 'desktop-control.json').exists(), 'hidden identity removal')
	finally:
		with contextlib.suppress(Exception):
			await browser.close()
	assert_no_runs(data)
	assert not evidence['page_errors'], evidence['page_errors']
	assert not evidence['external_requests'], evidence['external_requests']
	assert not [
		path
		for path in evidence['management_requests']
		if path.startswith(('/api/login', '/api/setup', '/api/passkey/', '/api/security/reauth'))
	], 'local UI attempted administrator verification'
	assert_console(evidence)
	return {
		'first_launch_without_password_setup': True,
		'no_admin_verification_requests': True,
		'local_security_controls_hidden': True,
		'desktop_runtime': True,
		'close_hides': True,
		'primary_hidden': True,
		'secondary_hidden_preserves_hidden': True,
		'secondary_status_activates': True,
		'single_backend_per_instance': True,
		'owned_shutdown_exits_native_and_backend': True,
		'identity_removed_on_exit': True,
		'persisted_settings_and_master_key': True,
		'runs': 0,
		**evidence,
	}


async def attached_scenario(playwright, binary, cli, report, processes, root):
	data, backend_port, debug_port = root / 'attached-data', free_port(), free_port()
	base = f'http://localhost:{backend_port}'
	args = ['--data-dir', str(data), '--port', str(backend_port)]
	server = processes.start(cli, ['serve', *args])
	await wait_for(lambda: json_get(base + '/healthz').get('setup_required'), 'headless product backend')
	api = API(base)
	policy = api.request('/api/session')
	api.csrf = policy['setup_csrf']
	api.request('/api/setup', {'password': PASSWORD, 'confirm_password': PASSWORD})
	api.login()
	first_instance = instance(data)
	assert api.request('/api/runtime')['desktop'] is False
	assert_no_runs(data)
	evidence: dict[str, list] = {'page_errors': [], 'console': [], 'external_requests': []}
	gui = processes.start(binary, ['app', *args], debug_port)
	await wait_for(lambda: visible_windows(gui.pid), 'attached native window')
	browser, page = await connect(playwright, base, debug_port, evidence)
	try:
		await login_page(page)
		await runtime_panel(page, False)
		assert instance(data) == first_instance and server.poll() is None
		assert_no_runs(data)
		await inspect(page, report, 'windows-attached-headless-runtime')
		await page.locator('body').click(position={'x': 20, 'y': 20})
		await quit_native_shortcut(gui.pid)
		assert await asyncio.to_thread(gui.wait, 15) == 0, 'Ctrl+Q did not close the attached GUI'
		assert server.poll() is None and json_get(base + '/healthz')['ok']
		assert instance(data) == first_instance, 'attached GUI replaced the headless backend'
		assert api.request('/api/session')['authenticated'], 'attached GUI exit revoked a separate browser session'
		assert api.request('/api/config')['revision'] == 0
		assert_no_runs(data)
		api.request('/api/runtime/shutdown', {})
		assert await asyncio.to_thread(server.wait, 15) == 0
		await wait_for(lambda: not (data / 'desktop-control.json').exists(), 'headless identity removal')
	finally:
		with contextlib.suppress(Exception):
			await browser.close()
	assert not evidence['page_errors'], evidence['page_errors']
	assert not evidence['external_requests'], evidence['external_requests']
	assert_console(evidence)
	return {
		'attached_existing_backend': True,
		'ctrl_q_exits_only_gui': True,
		'headless_identity_and_session_preserved': True,
		'explicit_headless_shutdown': True,
		'runs': 0,
		**evidence,
	}


async def main(arguments):
	assert os.name == 'nt', 'this acceptance script requires Windows'
	arguments.report.mkdir(parents=True, exist_ok=True)
	with tempfile.TemporaryDirectory(prefix='checkin-windows-product-', ignore_cleanup_errors=True) as temporary:
		root = Path(temporary)
		binary = arguments.binary.resolve() if arguments.binary else root / 'checkin-desktop-test.exe'
		cli = arguments.cli.resolve()
		if arguments.build:
			built = await asyncio.to_thread(
				subprocess.run,
				[
					'go',
					'build',
					'-mod=readonly',
					'-tags',
					'desktop,desktoptest,production',
					'-ldflags',
					'-H=windowsgui',
					'-o',
					str(binary),
					'./cmd/checkin',
				],
				cwd=REPOSITORY,
				capture_output=True,
				text=True,
				timeout=300,
			)
			assert built.returncode == 0, built.stderr
		assert binary.is_file() and cli.is_file(), 'provide an existing desktoptest binary and CLI'
		processes = Processes()
		try:
			async with async_playwright() as playwright:
				owned = await owned_scenario(playwright, binary, arguments.report, processes, root)
				attached = await attached_scenario(playwright, binary, cli, arguments.report, processes, root)
			result = {'result': 'passed', 'screenshots': str(arguments.report), 'owned': owned, 'attached': attached}
			(arguments.report / 'result.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
			print(json.dumps(result))
		except Exception:
			for label in ['owned-data', 'attached-data']:
				data = root / label
				for name in ['server.log', 'desktop.log']:
					if (data / name).is_file():
						(arguments.report / f'{label}-{name}').write_bytes((data / name).read_bytes())
			raise
		finally:
			processes.close()
			await asyncio.sleep(1)


if __name__ == '__main__':
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--binary', type=Path, help='desktoptest-tagged full product executable')
	parser.add_argument('--cli', type=Path, required=True, help='full product headless CLI executable')
	parser.add_argument(
		'--build', action='store_true', help='build the test desktop executable into a temporary folder'
	)
	parser.add_argument(
		'--report', type=Path, default=Path(tempfile.mkdtemp(prefix='checkin-windows-desktop-evidence-'))
	)
	asyncio.run(main(parser.parse_args()))
