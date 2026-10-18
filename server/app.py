"""Loopback WebUI with password sessions, CSRF checks and protected browser access."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web

from server.config_store import ConfigError, ConfigStore, ConflictError
from server.jobs import BusyError, JobManager

STATIC_ROOT = Path(__file__).parent / 'static'


class WebService:
	def __init__(self, data_dir: Path, key: bytes, password: str | None, *, scheduler: bool = True):
		self.store = ConfigStore(data_dir / 'webui.sqlite3', key)
		self.store.load()
		self.jobs = JobManager(self.store, data_dir, key)
		self.db = sqlite3.connect(data_dir / 'webui.sqlite3')
		self.db.execute(
			'CREATE TABLE IF NOT EXISTS web_auth (id INTEGER PRIMARY KEY CHECK(id=1), salt BLOB NOT NULL, digest BLOB NOT NULL)'
		)
		row = self.db.execute('SELECT salt,digest FROM web_auth WHERE id=1').fetchone()
		if row is None:
			if password is None or len(password) < 16 or len(password) > 512:
				raise ValueError('首次启动需要设置 16 到 512 字符的 WebUI 密码')
			salt = secrets.token_bytes(16)
			digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
			self.db.execute('INSERT INTO web_auth VALUES (1,?,?)', (salt, digest))
			self.db.commit()
			row = salt, digest
		self.salt, self.digest = row
		self.sessions: dict[str, dict] = {}
		self.attempts: list[float] = []
		self.client: ClientSession | None = None
		self.sockets: dict[str, set] = {}
		self.scheduler_enabled = scheduler

	def session(self, request: web.Request) -> dict | None:
		token = request.cookies.get('checkin_web_session', '')
		session = self.sessions.get(token)
		if session and session['expires'] > time.monotonic():
			return session
		self.sessions.pop(token, None)
		return None

	@web.middleware
	async def guard(self, request: web.Request, handler):
		try:
			host = urlsplit('http://' + request.host).hostname
			if host not in {'127.0.0.1', 'localhost', '::1'}:
				raise web.HTTPForbidden(text='只允许本机地址或 SSH 转发访问')
			mutating = request.method not in {'GET', 'HEAD', 'OPTIONS'}
			websocket = request.headers.get('Upgrade', '').lower() == 'websocket'
			if mutating or websocket:
				if request.headers.get('Origin') != f'{request.scheme}://{request.host}':
					raise web.HTTPForbidden(text='请求来源不匹配')
			session = self.session(request)
			public = request.path in {'/', '/app.js', '/style.css', '/api/login', '/api/session', '/healthz'}
			if not public and session is None:
				return web.json_response({'error': '请先登录'}, status=401)
			if mutating and request.path != '/api/login' and not request.path.startswith('/manual/'):
				if session is None or not hmac.compare_digest(request.headers.get('X-CSRF-Token', ''), session['csrf']):
					return web.json_response({'error': '页面凭据已失效, 请重新登录'}, status=403)
			return await handler(request)
		except ConflictError as error:
			return web.json_response({'error': str(error)}, status=409)
		except (ConfigError, ValueError, TypeError, json.JSONDecodeError) as error:
			message = str(error) if isinstance(error, ConfigError) else '请求格式无效'
			return web.json_response({'error': message}, status=400)
		except BusyError as error:
			return web.json_response({'error': str(error)}, status=409)

	async def headers(self, request: web.Request, response: web.StreamResponse) -> None:
		response.headers.update(
			{
				'Cache-Control': 'no-store',
				'Referrer-Policy': 'no-referrer',
				'X-Content-Type-Options': 'nosniff',
				'X-Frame-Options': 'SAMEORIGIN',
				'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; frame-src 'self'; frame-ancestors 'self'; form-action 'self'; connect-src 'self'",
			}
		)

	async def session_status(self, request):
		session = self.session(request)
		return web.json_response({'authenticated': session is not None, 'csrf': session['csrf'] if session else ''})

	async def login(self, request):
		now = time.monotonic()
		self.attempts = [attempt for attempt in self.attempts if now - attempt < 60]
		if len(self.attempts) >= 5:
			return web.json_response(
				{'error': '尝试次数过多, 请在 60 秒后重试'}, status=429, headers={'Retry-After': '60'}
			)
		self.attempts.append(now)
		payload = await request.json()
		if not isinstance(payload, dict):
			raise ValueError
		password = payload.get('password', '')
		if not isinstance(password, str) or len(password) > 512:
			return web.json_response({'error': '密码错误'}, status=401)
		digest = await asyncio.to_thread(hashlib.scrypt, password.encode(), salt=self.salt, n=16384, r=8, p=1)
		if not hmac.compare_digest(digest, self.digest):
			return web.json_response({'error': '密码错误'}, status=401)
		old_token = request.cookies.get('checkin_web_session', '')
		await self.revoke(old_token)
		self.sessions = {token: value for token, value in self.sessions.items() if value['expires'] > now}
		if len(self.sessions) >= 16:
			await self.revoke(next(iter(self.sessions)))
		token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
		self.sessions[token] = {'csrf': csrf, 'expires': now + 8 * 3600}
		response = web.json_response({'authenticated': True, 'csrf': csrf})
		response.set_cookie(
			'checkin_web_session', token, httponly=True, samesite='Strict', secure=False, max_age=8 * 3600
		)
		return response

	async def revoke(self, token: str) -> None:
		self.sessions.pop(token, None)
		for connection in tuple(self.sockets.pop(token, set())):
			await connection.close(code=1001)

	async def logout(self, request):
		await self.revoke(request.cookies.get('checkin_web_session', ''))
		response = web.json_response({'authenticated': False})
		response.del_cookie('checkin_web_session')
		return response

	async def get_config(self, request):
		return web.json_response(self.store.public())

	async def save_config(self, request):
		body = await request.json()
		if (
			not isinstance(body, dict)
			or type(body.get('revision')) is not int
			or not isinstance(body.get('config'), dict)
		):
			raise ValueError
		result = self.store.save(body['config'], body['revision'])
		self.jobs.schedule_changed()
		return web.json_response(result)

	async def start_run(self, request):
		body = await request.json()
		if not isinstance(body, dict) or type(body.get('revision')) is not int:
			raise ValueError
		return web.json_response({'run': await self.jobs.start(body['revision'])}, status=202)

	async def stop_run(self, request):
		return web.json_response({'stopping': await self.jobs.stop()})

	async def status(self, request):
		return web.json_response(self.jobs.status())

	async def runs(self, request):
		return web.json_response({'runs': self.jobs.history()})

	async def static(self, request):
		name = request.path.lstrip('/') or 'index.html'
		return web.FileResponse(STATIC_ROOT / name)

	async def health(self, request):
		return web.json_response({'ok': True})

	async def manual(self, request):
		manual = self.jobs.manual
		if self.jobs.stopping or not manual or str(self.jobs.active_id) != request.match_info['run_id']:
			return web.Response(status=410, text='人工登录窗口已关闭')
		origin = manual.get('url', '')
		parsed = urlsplit(origin)
		if parsed.scheme != 'http' or parsed.hostname != '127.0.0.1' or not parsed.port:
			return web.Response(status=503, text='人工登录入口不可用')
		tail = request.match_info['tail']
		if tail.startswith('/') or '\\' in tail or '..' in tail.split('/'):
			return web.Response(status=404)
		if tail in {'logout', 'login'}:
			return web.HTTPSeeOther('/')
		upstream = origin + '/' + tail
		if request.query_string:
			upstream += '?' + request.query_string
		headers = {'Origin': origin, 'Cookie': 'checkin_session=' + manual['session']}
		assert self.client is not None
		if request.headers.get('Upgrade', '').lower() == 'websocket':
			async with self.client.ws_connect(upstream, headers=headers, max_msg_size=4 * 1024 * 1024) as remote:
				connection = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024, heartbeat=20)
				await connection.prepare(request)
				token = request.cookies['checkin_web_session']
				self.sockets.setdefault(token, set()).add(connection)

				async def pipe(source, target):
					async for message in source:
						if message.type == WSMsgType.BINARY:
							await target.send_bytes(message.data)
						elif message.type == WSMsgType.TEXT:
							await target.send_str(message.data)
						else:
							break

				async def valid():
					ended = asyncio.Event()
					while (
						self.session(request)
						and self.jobs.manual
						and self.jobs.manual.get('session') == manual['session']
						and not self.jobs.stopping
					):
						try:
							await asyncio.wait_for(ended.wait(), timeout=0.5)
						except TimeoutError:
							pass

				tasks = [
					asyncio.create_task(pipe(remote, connection)),
					asyncio.create_task(pipe(connection, remote)),
					asyncio.create_task(valid()),
				]
				try:
					await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
				finally:
					for task in tasks:
						task.cancel()
					await asyncio.gather(*tasks, return_exceptions=True)
					self.sockets.get(token, set()).discard(connection)
					await connection.close()
				return connection
		body = await request.read()
		if request.content_type:
			headers['Content-Type'] = request.content_type
		async with self.client.request(
			request.method, upstream, headers=headers, data=body, allow_redirects=False
		) as response:
			content = await response.read()
			content_type = response.headers.get('Content-Type', 'application/octet-stream')
			prefix = f'/manual/{self.jobs.active_id}'
			if tail in {'', 'viewer.js'} and ('text/html' in content_type or 'javascript' in content_type):
				text = content.decode()
				for root in ('/viewer.js', '/assets/', '/websockify', '/resume', '/logout', '/login'):
					text = text.replace(root, prefix + root)
				content = text.encode()
			return web.Response(status=response.status, body=content, headers={'Content-Type': content_type})

	async def lifecycle(self, app):
		self.client = ClientSession(timeout=ClientTimeout(total=30), trust_env=False)
		if self.scheduler_enabled:
			await self.jobs.open()
		try:
			yield
		finally:
			for token in tuple(self.sessions):
				await self.revoke(token)
			await self.jobs.close()
			await self.client.close()
			self.store.close()
			self.db.close()


SERVICE = web.AppKey('service', WebService)


def create_app(data_dir: Path, key: bytes, password: str | None = None, *, scheduler: bool = True) -> web.Application:
	data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
	service = WebService(data_dir, key, password, scheduler=scheduler)
	app = web.Application(middlewares=[service.guard], client_max_size=1024 * 1024)
	app[SERVICE] = service
	app.on_response_prepare.append(service.headers)
	app.cleanup_ctx.append(service.lifecycle)
	app.router.add_get('/healthz', service.health)
	for path in ('/', '/app.js', '/style.css'):
		app.router.add_get(path, service.static)
	app.router.add_get('/api/session', service.session_status)
	app.router.add_post('/api/login', service.login)
	app.router.add_post('/api/logout', service.logout)
	app.router.add_get('/api/config', service.get_config)
	app.router.add_put('/api/config', service.save_config)
	app.router.add_get('/api/status', service.status)
	app.router.add_get('/api/runs', service.runs)
	app.router.add_post('/api/runs', service.start_run)
	app.router.add_post('/api/runs/stop', service.stop_run)
	app.router.add_route('*', '/manual/{run_id}/{tail:.*}', service.manual)
	return app
