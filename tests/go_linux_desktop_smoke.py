"""Opt-in Linux Wails lifecycle acceptance on a disposable Xvfb/DBus session.

Run this file explicitly, never against a user's desktop. It only creates local
empty application data. No account, notification, real browser profile, autostart
item or production server is used. GTK window close is sent as WM_DELETE_WINDOW;
tray actions use the application's real exported DBusMenu interface.
Owned local desktops need no administrator password file or verification;
attaching to an independent server must preserve its existing authentication.
"""

import argparse
import contextlib
import ctypes
import ctypes.util
import hashlib
import http.cookiejar
import json
import os
import re
import signal
import socket
import sqlite3
import struct
import subprocess
import tempfile
import time
import urllib.request
import zlib
from pathlib import Path

PASSWORD = 'synthetic-linux-desktop-password'  # nosec B105


def command(*args, check=True):
	return subprocess.run(args, check=check, text=True, capture_output=True, timeout=10)


def wait_for(check, label, seconds=20):
	deadline = time.monotonic() + seconds
	last = None
	while time.monotonic() < deadline:
		try:
			value = check()
			if value:
				return value
		except (OSError, ValueError, subprocess.SubprocessError) as error:
			last = type(error).__name__
		time.sleep(0.1)
	raise AssertionError(f'{label} did not complete ({last})')


def free_port():
	with socket.socket() as listener:
		listener.bind(('127.0.0.1', 0))
		return listener.getsockname()[1]


def visible_windows(pid):
	result = command(
		'xdotool', 'search', '--onlyvisible', '--all', '--pid', str(pid), '--name', '^CheckinMyFreeAPI$', check=False
	)
	if result.returncode not in (0, 1):
		raise RuntimeError('xdotool search failed')
	return [int(item) for item in result.stdout.split()]


def close_window(window):
	"""Send the same WM protocol message as a window manager's close button."""
	xlib = ctypes.CDLL(ctypes.util.find_library('X11'))
	xlib.XOpenDisplay.restype = ctypes.c_void_p
	xlib.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_bool]
	xlib.XInternAtom.restype = ctypes.c_ulong
	xlib.XSendEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_bool, ctypes.c_long, ctypes.c_void_p]
	xlib.XFlush.argtypes = [ctypes.c_void_p]
	xlib.XCloseDisplay.argtypes = [ctypes.c_void_p]

	class Data(ctypes.Union):
		_fields_ = [('b', ctypes.c_char * 20), ('s', ctypes.c_short * 10), ('l', ctypes.c_long * 5)]

	class ClientMessage(ctypes.Structure):
		_fields_ = [
			('type', ctypes.c_int),
			('serial', ctypes.c_ulong),
			('send_event', ctypes.c_int),
			('display', ctypes.c_void_p),
			('window', ctypes.c_ulong),
			('message_type', ctypes.c_ulong),
			('format', ctypes.c_int),
			('data', Data),
		]

	class Event(ctypes.Union):
		_fields_ = [('client', ClientMessage), ('pad', ctypes.c_long * 24)]

	display = xlib.XOpenDisplay(None)
	if not display:
		raise RuntimeError('the isolated X11 display is unavailable')
	try:
		event = Event()
		event.client.type = 33
		event.client.send_event = 1
		event.client.display = display
		event.client.window = window
		event.client.message_type = xlib.XInternAtom(display, b'WM_PROTOCOLS', False)
		event.client.format = 32
		event.client.data.l[0] = xlib.XInternAtom(display, b'WM_DELETE_WINDOW', False)
		event.client.data.l[1] = 0
		if not xlib.XSendEvent(display, window, False, 0, ctypes.byref(event)):
			raise RuntimeError('window close message failed')
		xlib.XFlush(display)
	finally:
		xlib.XCloseDisplay(display)


def tray_action(pid, label):
	service = f'org.kde.StatusNotifierItem-{pid}-1'
	base = ['gdbus', 'call', '--session', '--dest', service, '--object-path', '/StatusNotifierMenu']
	result = command(*base, '--method', 'com.canonical.dbusmenu.GetLayout', '0', '1', "['label']")
	for match in re.finditer(r'\((?:int32\s+)?(\d+),\s*\{([^{}]*)\}', result.stdout):
		if f"'label': <'{label}'>" in match[2]:
			command(*base, '--method', 'com.canonical.dbusmenu.Event', match[1], 'clicked', '<int32 0>', '0')
			return
	raise AssertionError(f'the real DBus tray menu has no {label!r} entry')


def capture_xwd(source, destination):
	"""Convert the isolated Xvfb framebuffer to PNG using only Python stdlib."""
	if source is None:
		return None
	raw = Path(source).read_bytes()
	fields = struct.unpack('>25I', raw[:100])
	(
		header_size,
		version,
		image_format,
		depth,
		width,
		height,
		_,
		byte_order,
		_,
		_,
		_,
		bpp,
		pitch,
		_,
		red_mask,
		green_mask,
		blue_mask,
		_,
		_,
		colors,
		*_rest,
	) = fields
	if version != 7 or image_format != 2 or depth not in (24, 32) or bpp != 32:
		raise AssertionError('unsupported Xvfb framebuffer format')
	start = header_size + colors * 12
	order = '<I' if byte_order == 0 else '>I'
	shifts = [(mask & -mask).bit_length() - 1 for mask in (red_mask, green_mask, blue_mask)]
	rows = bytearray()
	for y in range(height):
		rows.append(0)
		for x in range(width):
			pixel = struct.unpack_from(order, raw, start + y * pitch + x * 4)[0]
			rows.extend(
				((pixel & mask) >> shift) for mask, shift in zip((red_mask, green_mask, blue_mask), shifts, strict=True)
			)

	def chunk(name, data):
		return struct.pack('>I', len(data)) + name + data + struct.pack('>I', zlib.crc32(name + data) & 0xFFFFFFFF)

	png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0))
	png += chunk(b'IDAT', zlib.compress(rows)) + chunk(b'IEND', b'')
	Path(destination).write_bytes(png)
	return hashlib.sha256(png).hexdigest()


class Scenario:
	def __init__(self, binary, report, label, xwd):
		self.binary, self.report, self.label, self.xwd = binary, report, label, xwd
		self.temp = tempfile.TemporaryDirectory(prefix='checkin-linux-desktop-')
		self.data = Path(self.temp.name) / 'data'
		self.data.mkdir(mode=0o700)
		self.password_file = self.data / 'admin-password.txt'
		self.port = free_port()
		self.base = f'http://localhost:{self.port}'
		self.processes, self.logs = [], []
		self.opener = urllib.request.build_opener(
			urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
		)
		self.csrf = ''

	def api(self, path, body=None):
		headers = {'Origin': self.base, 'Accept': 'application/json'}
		if body is not None:
			headers['Content-Type'] = 'application/json'
		if self.csrf:
			headers['X-CSRF-Token'] = self.csrf
		request = urllib.request.Request(
			self.base + path, data=json.dumps(body).encode() if body is not None else None, headers=headers
		)
		with self.opener.open(request, timeout=3) as response:
			return json.load(response)

	def start(self, mode='app', hidden=False):
		log = (self.report / f'{self.label}-{len(self.processes)}.log').open('wb')
		self.logs.append(log)
		args = [
			self.binary,
			mode,
			'--data-dir',
			str(self.data),
			'--port',
			str(self.port),
		]
		if mode == 'serve':
			self.password_file.write_text(PASSWORD, encoding='utf-8')
			self.password_file.chmod(0o600)
			args.extend(['--password-file', str(self.password_file)])
		if hidden:
			args.append('--hidden')
		environment = dict(os.environ)
		for key, directory in (
			('XDG_CACHE_HOME', 'cache'),
			('XDG_CONFIG_HOME', 'config'),
			('XDG_DATA_HOME', 'share'),
			('XDG_STATE_HOME', 'state'),
		):
			environment[key] = str(Path(self.temp.name) / directory)
		environment['NO_AT_BRIDGE'] = '1'
		process = subprocess.Popen(
			args,
			stdin=subprocess.DEVNULL,
			stdout=log,
			stderr=subprocess.STDOUT,
			start_new_session=True,
			env=environment,
		)
		self.processes.append(process)
		return process

	def healthy(self):
		return self.api('/healthz').get('runtime') == 'go'

	def authenticate(self, local_expected):
		policy = self.api('/api/session')
		if local_expected:
			assert policy['authenticated'] is True and policy['local_mode'] is True
			assert policy['auth_mode'] == 'local' and policy['reauth_method'] == 'none'
			assert not policy.get('setup_required', False)
			assert not policy['password_login_allowed'] and not policy['passkey_available']
			self.csrf = policy['csrf']
			assert not self.password_file.exists(), 'local desktop needed an initial password file'
		else:
			assert not policy['authenticated'] and not policy.get('local_mode', False)
			self.csrf = self.api('/api/login', {'password': PASSWORD})['csrf']

	def instance(self):
		return json.loads((self.data / 'desktop-control.json').read_text(encoding='utf-8'))['instance']

	def no_runs(self):
		with sqlite3.connect(f'file:{self.data / "webui.sqlite3"}?mode=ro', uri=True) as db:
			count = db.execute('SELECT count(*) FROM runs').fetchone()[0]
		assert count == 0, f'the lifecycle test unexpectedly started {count} tasks'

	def screenshot(self, state):
		return capture_xwd(self.xwd, self.report / f'{self.label}-{state}.png')

	def stop_backend(self):
		policy = self.api('/api/session')
		self.csrf = (
			policy['csrf'] if policy.get('local_mode') else self.api('/api/login', {'password': PASSWORD})['csrf']
		)
		self.api('/api/runtime/shutdown', {})

	def close(self):
		with contextlib.suppress(OSError, ValueError):
			self.stop_backend()
		for process in reversed(self.processes):
			if process.poll() is None:
				with contextlib.suppress(ProcessLookupError):
					getattr(os, 'killpg')(process.pid, signal.SIGTERM)
				try:
					process.wait(timeout=5)
				except subprocess.TimeoutExpired:
					with contextlib.suppress(ProcessLookupError):
						getattr(os, 'killpg')(process.pid, getattr(signal, 'SIGKILL'))
					process.wait(timeout=5)
		for log in self.logs:
			log.close()
		self.temp.cleanup()


def check_lifecycle(binary, report, xwd, hidden):
	scenario = Scenario(binary, report, 'hidden' if hidden else 'visible', xwd)
	try:
		primary = scenario.start(hidden=hidden)
		wait_for(scenario.healthy, 'native desktop backend')
		scenario.authenticate(local_expected=True)
		original = scenario.instance()
		if hidden:
			time.sleep(1)
			assert not visible_windows(primary.pid), 'silent startup showed a main window'
			assert primary.poll() is None
		else:
			window = wait_for(lambda: visible_windows(primary.pid), 'native window')[0]
			time.sleep(2)
			scenario.screenshot('shown')
			close_window(window)
			wait_for(lambda: not visible_windows(primary.pid), 'close-to-tray')
			assert scenario.healthy() and primary.poll() is None
			scenario.screenshot('hidden')
		secondary = scenario.start()
		assert secondary.wait(timeout=10) == 0, 'secondary desktop launch did not forward activation'
		wait_for(lambda: visible_windows(primary.pid), 'existing native window activation')
		assert scenario.instance() == original, 'secondary launch replaced or restarted the backend'
		scenario.no_runs()
		time.sleep(1)
		scenario.screenshot('reactivated')
		tray_action(primary.pid, '查看 Status')
		assert scenario.healthy()
		tray_action(primary.pid, '退出程序')
		assert primary.wait(timeout=15) == 0, 'real tray exit did not stop the desktop cleanly'
		scenario.no_runs()
		return {
			'local_without_password_or_passkey': True,
			'hidden_start': hidden,
			'reactivated_primary': True,
			'same_backend_instance': True,
			'tray_status_action': True,
			'tray_exit': True,
			'account_runs': 0,
		}
	finally:
		scenario.close()


def check_attachment(binary, report, xwd):
	scenario = Scenario(binary, report, 'attached', xwd)
	try:
		server = scenario.start(mode='serve')
		wait_for(scenario.healthy, 'headless native server')
		scenario.authenticate(local_expected=False)
		original = scenario.instance()
		gui = scenario.start()
		wait_for(lambda: visible_windows(gui.pid), 'attached desktop window')
		assert scenario.instance() == original
		tray_action(gui.pid, '退出程序')
		assert gui.wait(timeout=15) == 0
		assert server.poll() is None and scenario.healthy(), 'exiting attached desktop stopped the independent server'
		assert scenario.instance() == original
		scenario.no_runs()
		scenario.stop_backend()
		assert server.wait(timeout=15) == 0
		return {
			'headless_kept_authentication': True,
			'attached_existing_backend': True,
			'same_backend_instance': True,
			'tray_exit_kept_server': True,
			'account_runs': 0,
		}
	finally:
		scenario.close()


def main():
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--binary', required=True)
	parser.add_argument('--report-dir', required=True)
	parser.add_argument('--xwd')
	args = parser.parse_args()
	if (
		os.name != 'posix'
		or os.getenv('CHECKIN_DESKTOP_ISOLATED_DISPLAY') != '1'
		or not os.getenv('DISPLAY')
		or not os.getenv('DBUS_SESSION_BUS_ADDRESS')
	):
		raise SystemExit(
			'Run only inside a disposable Xvfb + dbus-run-session with CHECKIN_DESKTOP_ISOLATED_DISPLAY=1.'
		)
	if os.getenv('GDK_BACKEND') != 'x11' or os.getenv('WAYLAND_DISPLAY'):
		raise SystemExit('The test requires GDK_BACKEND=x11 with WAYLAND_DISPLAY unset; never use the WSLg desktop.')
	if not Path(args.binary).is_file():
		raise SystemExit('The native desktop binary does not exist.')
	report = Path(args.report_dir)
	report.mkdir(parents=True, exist_ok=True)
	results = [check_lifecycle(str(Path(args.binary).resolve()), report, args.xwd, hidden) for hidden in (False, True)]
	results.append(check_attachment(str(Path(args.binary).resolve()), report, args.xwd))
	summary = {
		'result': 'passed',
		'platform': 'linux',
		'display': os.environ['DISPLAY'],
		'real_dbus_tray_callbacks': True,
		'visual_tray_host': False,
		'external_requests': 0,
		'scenarios': results,
	}
	(report / 'acceptance.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
	print(json.dumps(summary))


if __name__ == '__main__':
	main()
