"""Short-lived, authenticated noVNC gateway; no authentication material enters URLs."""

from __future__ import annotations

import asyncio
import hmac
import os
import re
import secrets
import shutil
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import WSMsgType, web

LOGIN_HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>临时登录接管</title>
<style>body{font:16px system-ui;max-width:480px;margin:12vh auto;padding:24px;color:#203040}
input,button{box-sizing:border-box;width:100%;padding:12px;margin-top:12px;font:inherit}
p{line-height:1.7}</style><h1>临时登录接管</h1><p>此窗口控制 GitHub Runner 中的浏览器。
请输入预先设置的远程接管密码，不是 GitHub 或 LinuxDo 的账号密码。</p>
<form action="/login" method="post"><label for="password">远程接管密码</label>
<input id="password" name="password" type="password" required autocomplete="off" maxlength="512">
<button type="submit">连接浏览器</button></form><p>登录完成或超过时限后，入口会自动关闭。</p></html>"""

VIEWER_HTML = """<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Runner 浏览器</title>
<style>body{margin:0;font:14px system-ui;background:#17202b;color:white}header{padding:12px}
button{padding:7px 12px;margin-left:12px}#screen{height:calc(100vh - 64px)}</style>
<header><span id="status">正在连接临时浏览器…</span>
<button id="resume">已完成登录，继续授权</button><button id="logout">断开</button></header>
<div id="screen"></div><script type="module" src="/viewer.js"></script></html>"""

VIEWER_JS = """import RFB from '/assets/core/rfb.js';
const status = document.getElementById('status');
const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
const rfb = new RFB(document.getElementById('screen'), scheme + '//' + location.host + '/websockify');
rfb.scaleViewport = true; rfb.resizeSession = false;
rfb.addEventListener('connect', () => { status.textContent = '请在远程浏览器中完成登录与授权'; });
rfb.addEventListener('disconnect', () => { status.textContent = '连接已关闭：任务已继续、超时或终止'; });
document.getElementById('resume').onclick = async () => {
  const response = await fetch('/resume', {method:'POST'});
  status.textContent = response.ok ? '已请求继续授权' : '会话已失效';
};
document.getElementById('logout').onclick = async () => {
  await fetch('/logout', {method:'POST'}); rfb.disconnect(); location.replace('/login');
};"""


class ManualLoginError(RuntimeError):
	pass


class ManualGateway:
	def __init__(self, password: str, assets: Path, vnc_port: int, timeout: int, *, secure_cookie: bool = True):
		if len(password) < 24 or len(password) > 512:
			raise ManualLoginError('CHECKIN_REMOTE_PASSWORD must contain 24 to 512 characters')
		self._password = password.encode()
		self.assets = assets.resolve()
		self.vnc_port = vnc_port
		self.deadline = time.monotonic() + timeout
		self.timeout = timeout
		self.secure_cookie = secure_cookie
		self.origin = ''
		self._session: str | None = None
		self._attempts: list[float] = []
		self._sockets: set[web.WebSocketResponse] = set()
		self.resume = asyncio.Event()
		self.app = web.Application(middlewares=[self._guard], client_max_size=4096)
		self.app.router.add_get('/login', self.login_page)
		self.app.router.add_post('/login', self.login)
		self.app.router.add_get('/', self.viewer)
		self.app.router.add_get('/viewer.js', self.viewer_script)
		self.app.router.add_get('/assets/{path:.*}', self.asset)
		self.app.router.add_get('/websockify', self.websocket)
		self.app.router.add_post('/resume', self.continue_login)
		self.app.router.add_post('/logout', self.logout)
		self.app.on_response_prepare.append(self._headers)

	async def _headers(self, request: web.Request, response: web.StreamResponse) -> None:
		response.headers.update(
			{
				'Cache-Control': 'no-store',
				'Referrer-Policy': 'no-referrer',
				'X-Content-Type-Options': 'nosniff',
				'X-Frame-Options': 'DENY',
				'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' blob: data:; frame-ancestors 'none'; form-action 'self'; connect-src 'self'",
			}
		)

	@web.middleware
	async def _guard(self, request: web.Request, handler):
		if time.monotonic() >= self.deadline:
			raise web.HTTPGone(text='This login session has expired')
		if not self.origin:
			raise web.HTTPServiceUnavailable(text='Gateway is starting')
		if request.host != urlsplit(self.origin).netloc:
			raise web.HTTPForbidden(text='Invalid host')
		if request.method == 'POST' or request.path == '/websockify':
			if request.headers.get('Origin') != self.origin:
				raise web.HTTPForbidden(text='Invalid origin')
		if request.path != '/login':
			provided = request.cookies.get('checkin_session', '')
			if not self._session or not hmac.compare_digest(provided.encode(), self._session.encode()):
				if request.path == '/' and request.method == 'GET':
					raise web.HTTPFound('/login')
				raise web.HTTPUnauthorized(text='Authentication required')
		return await handler(request)

	async def login_page(self, request: web.Request) -> web.Response:
		return web.Response(text=LOGIN_HTML, content_type='text/html')

	async def login(self, request: web.Request) -> web.Response:
		now = time.monotonic()
		self._attempts = [attempt for attempt in self._attempts if now - attempt < 60]
		if len(self._attempts) >= 5:
			raise web.HTTPTooManyRequests(text='Try again later', headers={'Retry-After': '60'})
		self._attempts.append(now)
		payload = await request.post()
		provided = payload.get('password', '')
		if not isinstance(provided, str) or not hmac.compare_digest(provided.encode(), self._password):
			raise web.HTTPUnauthorized(text='Invalid remote access password')
		await self.revoke()
		self._session = secrets.token_urlsafe(32)
		response = web.HTTPSeeOther('/')
		response.set_cookie(
			'checkin_session',
			self._session,
			httponly=True,
			secure=self.secure_cookie,
			samesite='Strict',
			max_age=max(1, int(self.deadline - now)),
			path='/',
		)
		raise response

	async def viewer(self, request: web.Request) -> web.Response:
		return web.Response(text=VIEWER_HTML, content_type='text/html')

	async def viewer_script(self, request: web.Request) -> web.Response:
		return web.Response(text=VIEWER_JS, content_type='application/javascript')

	async def asset(self, request: web.Request) -> web.FileResponse:
		relative = request.match_info['path']
		if '\\' in relative or ':' in relative or not relative.startswith(('core/', 'vendor/')):
			raise web.HTTPNotFound()
		path = (self.assets / relative).resolve()
		if not path.is_relative_to(self.assets) or not path.is_file():
			raise web.HTTPNotFound()
		return web.FileResponse(path)

	async def continue_login(self, request: web.Request) -> web.Response:
		self.resume.set()
		return web.Response(text='Continue requested')

	async def logout(self, request: web.Request) -> web.Response:
		await self.revoke()
		response = web.Response(text='Disconnected')
		response.del_cookie('checkin_session', path='/')
		return response

	async def revoke(self) -> None:
		self._session = None
		for connection in tuple(self._sockets):
			await connection.close(code=1001, message=b'Session closed')

	async def websocket(self, request: web.Request) -> web.WebSocketResponse:
		if self._sockets:
			raise web.HTTPConflict(text='A browser connection is already active')
		reader, writer = await asyncio.open_connection('127.0.0.1', self.vnc_port)
		connection = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024, heartbeat=20)
		await connection.prepare(request)
		self._sockets.add(connection)

		async def to_browser() -> None:
			while chunk := await reader.read(64 * 1024):
				await connection.send_bytes(chunk)

		async def to_vnc() -> None:
			async for message in connection:
				if message.type != WSMsgType.BINARY:
					break
				writer.write(message.data)
				await writer.drain()

		tasks = [asyncio.create_task(to_browser()), asyncio.create_task(to_vnc())]
		try:
			await asyncio.wait(
				tasks, timeout=max(0, self.deadline - time.monotonic()), return_when=asyncio.FIRST_COMPLETED
			)
		finally:
			for task in tasks:
				task.cancel()
			await asyncio.gather(*tasks, return_exceptions=True)
			writer.close()
			await writer.wait_closed()
			self._sockets.discard(connection)
			await connection.close()
		return connection


def child_environment() -> dict[str, str]:
	allowed = {
		'PATH',
		'HOME',
		'DISPLAY',
		'XAUTHORITY',
		'TMPDIR',
		'LANG',
		'LC_ALL',
		'LD_LIBRARY_PATH',
		'SYSTEMROOT',
		'TEMP',
		'TMP',
		'USERPROFILE',
		'LOCALAPPDATA',
	}
	return {key: value for key, value in os.environ.items() if key in allowed}


def unused_local_port() -> int:
	with socket.socket() as probe:
		probe.bind(('127.0.0.1', 0))
		return int(probe.getsockname()[1])


class ManualTakeover:
	def __init__(self, timeout: int):
		if not 30 <= timeout <= 1800:
			raise ManualLoginError('Manual login timeout must be between 30 and 1800 seconds')
		self.timeout = timeout
		self.gateway: ManualGateway | None = None
		self.url = ''
		self._processes: list[asyncio.subprocess.Process] = []
		self._runner: web.AppRunner | None = None
		self._drain_task: asyncio.Task | None = None

	async def __aenter__(self) -> 'ManualTakeover':
		if os.getenv('CHECKIN_MANUAL_LOGIN', '').lower() not in {'true', '1', 'yes'}:
			raise ManualLoginError('Manual browser login is disabled')
		if sys.platform != 'linux' or not os.getenv('DISPLAY'):
			raise ManualLoginError('Manual login requires the headed Linux/Xvfb workflow')
		if os.getenv('CHECKIN_MANUAL_HEADLESS') == 'true':
			raise ManualLoginError('Manual login requires headless mode to be disabled')
		x11vnc = shutil.which('x11vnc')
		local = os.getenv('CHECKIN_MANUAL_TRANSPORT') == 'local'
		cloudflared = shutil.which('cloudflared')
		assets = Path(os.getenv('NOVNC_WEB_ROOT', '/usr/share/novnc'))
		if not x11vnc or (not local and not cloudflared) or not (assets / 'core' / 'rfb.js').is_file():
			raise ManualLoginError('Manual login dependencies are unavailable')
		try:
			vnc_port = unused_local_port()
			self.gateway = ManualGateway(os.getenv('CHECKIN_REMOTE_PASSWORD', ''), assets, vnc_port, self.timeout)
			process = await asyncio.create_subprocess_exec(
				x11vnc,
				'-display',
				os.environ['DISPLAY'],
				'-localhost',
				'-listen',
				'127.0.0.1',
				'-rfbport',
				str(vnc_port),
				'-forever',
				'-shared',
				'-nopw',
				'-noxdamage',
				stdout=asyncio.subprocess.DEVNULL,
				stderr=asyncio.subprocess.DEVNULL,
				env=child_environment(),
				start_new_session=True,
			)
			self._processes.append(process)
			await self._wait_for_vnc(vnc_port, process)
			self._runner = web.AppRunner(self.gateway.app, access_log=None, shutdown_timeout=3)
			await self._runner.setup()
			site = web.TCPSite(self._runner, '127.0.0.1', 0)
			await site.start()
			addresses = self._runner.addresses
			gateway_port = addresses[0][1]
			if local:
				self.url = f'http://127.0.0.1:{gateway_port}'
				self.gateway.origin = self.url
				self.gateway._session = os.environ['CHECKIN_MANUAL_SESSION']
				return self
			tunnel = await asyncio.create_subprocess_exec(
				cloudflared,
				'tunnel',
				'--config',
				'/dev/null',
				'--no-autoupdate',
				'--protocol',
				'http2',
				'--url',
				f'http://127.0.0.1:{gateway_port}',
				stdout=asyncio.subprocess.DEVNULL,
				stderr=asyncio.subprocess.PIPE,
				env=child_environment(),
				start_new_session=True,
			)
			self._processes.append(tunnel)
			self.url = await asyncio.wait_for(self._read_tunnel_url(tunnel), timeout=45)
			self.gateway.origin = self.url
			self.gateway.deadline = time.monotonic() + self.timeout
			self._drain_task = asyncio.create_task(self._drain_tunnel(tunnel))
			return self
		except BaseException:
			await self.close()
			raise

	async def _wait_for_vnc(self, port: int, process: asyncio.subprocess.Process) -> None:
		async with asyncio.timeout(15):
			while process.returncode is None:
				try:
					reader, writer = await asyncio.open_connection('127.0.0.1', port)
					writer.close()
					await writer.wait_closed()
					return
				except OSError:
					await asyncio.sleep(0.2)
			raise ManualLoginError('The loopback VNC server could not start')

	async def _read_tunnel_url(self, process: asyncio.subprocess.Process) -> str:
		if process.stderr is None:
			raise ManualLoginError('Tunnel output is unavailable')
		while line := await process.stderr.readline():
			match = re.search(rb'https://[a-z0-9-]+\.trycloudflare\.com\b', line)
			if match:
				return match.group().decode('ascii')
		raise ManualLoginError('The temporary HTTPS tunnel could not start')

	async def _drain_tunnel(self, process: asyncio.subprocess.Process) -> None:
		if process.stderr is not None:
			while await process.stderr.read(4096):
				pass

	async def __aexit__(self, exception_type, exception, traceback) -> None:
		await self.close()

	async def close(self) -> None:
		if self.gateway is not None:
			self.gateway.deadline = 0
			await self.gateway.revoke()
		if self._runner is not None:
			await self._runner.cleanup()
			self._runner = None
		for process in reversed(self._processes):
			if process.returncode is not None:
				continue
			try:
				process.terminate()
				await asyncio.wait_for(process.wait(), timeout=5)
			except ProcessLookupError:
				pass
			except TimeoutError:
				process.kill()
				await process.wait()
		self._processes.clear()
		if self._drain_task is not None:
			self._drain_task.cancel()
			await asyncio.gather(self._drain_task, return_exceptions=True)
			self._drain_task = None
