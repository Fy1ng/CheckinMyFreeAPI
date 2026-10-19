"""Loopback HTTP-only WebUI with password sessions and CSRF checks."""

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

from aiohttp import web

from server.config_store import ConfigError, ConfigStore, ConflictError
from server.jobs import BusyError, JobManager, acquire_file_lock

STATIC_ROOT = Path(__file__).parent / 'static'


class WebService:
	def __init__(self, data_dir: Path, key: bytes, password: str | None, *, scheduler: bool = True):
		lease = acquire_file_lock(data_dir / 'service.lock')
		try:
			self.store = ConfigStore(data_dir / 'webui.sqlite3', key)
			self.store.load()
			self.jobs = JobManager(self.store, data_dir, key, instance_lock=lease)
		except BaseException:
			if hasattr(self, 'store'):
				self.store.close()
			lease.close()
			raise
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
			if mutating and request.path != '/api/login':
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

	async def logout(self, request):
		await self.revoke(request.cookies.get('checkin_web_session', ''))
		response = web.json_response({'authenticated': False})
		response.del_cookie('checkin_web_session')
		return response

	async def get_config(self, request):
		result = self.store.public()
		result['migration'] = self.store.migration_info()
		return web.json_response(result)

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

	async def resolve_attention(self, request):
		body = await request.json()
		if (
			not isinstance(body, dict)
			or type(body.get('revision')) is not int
			or not isinstance(body.get('account_id'), str)
		):
			raise ValueError
		self.jobs.resolve_attention(body['account_id'], body['revision'])
		return web.json_response({'resolved': True})

	async def status(self, request):
		return web.json_response(self.jobs.status())

	async def runs(self, request):
		return web.json_response({'runs': self.jobs.history()})

	async def static(self, request):
		name = request.path.lstrip('/') or 'index.html'
		return web.FileResponse(STATIC_ROOT / name)

	async def health(self, request):
		return web.json_response({'ok': True})

	async def lifecycle(self, app):
		if self.scheduler_enabled:
			await self.jobs.open()
		try:
			yield
		finally:
			for token in tuple(self.sessions):
				await self.revoke(token)
			await self.jobs.close()
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
	app.router.add_post('/api/accounts/resolve', service.resolve_attention)
	return app
