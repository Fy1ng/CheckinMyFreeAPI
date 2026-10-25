"""Password-protected WebUI with explicit loopback or HTTPS ingress and CSRF checks."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path

from aiohttp import web

from server.backup import MAX_BACKUP_BYTES, BackupError
from server.backup_runtime import BackupRuntime
from server.config_store import ConfigError, ConfigStore, ConflictError
from server.jobs import BusyError, JobManager, acquire_file_lock
from server.web_access import WebAccess

STATIC_ROOT = Path(__file__).parent / 'static'
WEB_ORIGIN = web.RequestKey('web_origin', str)


class WebService:
	def __init__(
		self,
		data_dir: Path,
		key: bytes,
		password: str | None,
		*,
		scheduler: bool = True,
		access: WebAccess | None = None,
	):
		self.data_dir, self.key = data_dir, key
		self.maintenance = False
		self.backup_operation = asyncio.Lock()
		self.restore_context: dict[str, dict] = {}
		self.access = access or WebAccess()
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
		self.client_attempts: dict[str, list[float]] = {}
		self._login_busy = False
		self.scheduler_enabled = scheduler
		self.backups = BackupRuntime(self.store, data_dir, key, self.jobs)

	def session(self, request: web.Request) -> dict | None:
		token = request.cookies.get('checkin_web_session', '')
		session = self.sessions.get(token)
		if session and session['expires'] > time.monotonic() and session['origin'] == request.get(WEB_ORIGIN):
			return session
		if session and session['expires'] <= time.monotonic():
			self.sessions.pop(token, None)
		return None

	@web.middleware
	async def guard(self, request: web.Request, handler):
		try:
			if self.maintenance:
				return web.json_response(
					{'error': '正在恢复数据, 请稍后重新登录'}, status=503, headers={'Retry-After': '5'}
				)
			origin = self.access.origin(request)
			request[WEB_ORIGIN] = origin
			mutating = request.method not in {'GET', 'HEAD', 'OPTIONS'}
			websocket = request.headers.get('Upgrade', '').lower() == 'websocket'
			if mutating or websocket:
				if request.headers.get('Origin') != origin:
					raise web.HTTPForbidden(text='请求来源不匹配')
			session = self.session(request)
			public = request.path in {
				'/',
				'/status',
				'/backups',
				'/app.js',
				'/backups.js',
				'/style.css',
				'/api/login',
				'/api/session',
				'/healthz',
			}
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
		if self.access.public_origin and request.get(WEB_ORIGIN) == self.access.public_origin:
			response.headers['Strict-Transport-Security'] = 'max-age=31536000'

	async def session_status(self, request):
		session = self.session(request)
		return web.json_response({'authenticated': session is not None, 'csrf': session['csrf'] if session else ''})

	@staticmethod
	def login_limited():
		return web.json_response({'error': '尝试次数过多, 请在 60 秒后重试'}, status=429, headers={'Retry-After': '60'})

	def password_check_finished(self, task: asyncio.Task) -> None:
		self._login_busy = False
		# Retrieve an exception even if its HTTP handler was disconnected/cancelled.
		if not task.cancelled():
			task.exception()

	async def login(self, request):
		now = time.monotonic()
		self.attempts = [attempt for attempt in self.attempts if now - attempt < 60]
		self.client_attempts = {
			ip: recent
			for ip, attempts in self.client_attempts.items()
			if (recent := [attempt for attempt in attempts if now - attempt < 60])
		}
		client_ip = self.access.client_ip(request)
		attempts = self.client_attempts.get(client_ip, [])
		if (
			len(self.attempts) >= 30
			or len(attempts) >= 5
			or self._login_busy
			or (client_ip not in self.client_attempts and len(self.client_attempts) >= 256)
		):
			return self.login_limited()
		self.attempts.append(now)
		self.client_attempts[client_ip] = [*attempts, now]
		payload = await request.json()
		if not isinstance(payload, dict):
			raise ValueError
		password = payload.get('password', '')
		if not isinstance(password, str) or len(password) > 512:
			return web.json_response({'error': '密码错误'}, status=401)
		encoded = password.encode()
		if self._login_busy:
			return self.login_limited()
		self._login_busy = True
		verification = asyncio.create_task(
			asyncio.to_thread(hashlib.scrypt, encoded, salt=self.salt, n=16384, r=8, p=1), name='web-password-check'
		)
		verification.add_done_callback(self.password_check_finished)
		digest = await asyncio.shield(verification)
		if not hmac.compare_digest(digest, self.digest):
			return web.json_response({'error': '密码错误'}, status=401)
		old_token = request.cookies.get('checkin_web_session', '')
		await self.revoke(old_token)
		self.sessions = {token: value for token, value in self.sessions.items() if value['expires'] > now}
		if len(self.sessions) >= 16:
			await self.revoke(next(iter(self.sessions)))
		token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
		self.sessions[token] = {'csrf': csrf, 'expires': now + 8 * 3600, 'origin': request[WEB_ORIGIN]}
		response = web.json_response({'authenticated': True, 'csrf': csrf})
		response.set_cookie(
			'checkin_web_session',
			token,
			httponly=True,
			samesite='Strict',
			secure=request[WEB_ORIGIN].startswith('https://'),
			max_age=8 * 3600,
		)
		return response

	async def revoke(self, token: str) -> None:
		self.sessions.pop(token, None)

	async def logout(self, request):
		await self.revoke(request.cookies.get('checkin_web_session', ''))
		response = web.json_response({'authenticated': False})
		response.set_cookie(
			'checkin_web_session',
			'',
			httponly=True,
			samesite='Strict',
			secure=request[WEB_ORIGIN].startswith('https://'),
			max_age=0,
			expires='Thu, 01 Jan 1970 00:00:00 GMT',
		)
		return response

	async def get_config(self, request):
		result = self.store.public()
		result['migration'] = self.store.migration_info()
		return web.json_response(result)

	async def save_config(self, request):
		if self.backup_operation.locked():
			raise BusyError('请等待备份操作结束后保存配置')
		body = await request.json()
		if (
			not isinstance(body, dict)
			or type(body.get('revision')) is not int
			or not isinstance(body.get('config'), dict)
		):
			raise ValueError
		result = self.store.save(body['config'], body['revision'])
		self.jobs.schedule_changed()
		self.backups.schedule_changed()
		return web.json_response(result)

	async def start_run(self, request):
		body = await request.json()
		if (
			not isinstance(body, dict)
			or set(body) - {'revision', 'account_id'}
			or type(body.get('revision')) is not int
			or (
				'account_id' in body
				and (not isinstance(body['account_id'], str) or not body['account_id'] or len(body['account_id']) > 128)
			)
		):
			raise ValueError
		return web.json_response(
			{'run': await self.jobs.start(body['revision'], account_id=body.get('account_id'))}, status=202
		)

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

	async def balances(self, request):
		return web.json_response(self.jobs.balance_snapshot())

	async def automation(self, request):
		return web.json_response(self.jobs.automation_snapshot())

	async def send_summary(self, request):
		body = await request.json()
		if (
			not isinstance(body, dict)
			or set(body) != {'revision'}
			or type(body.get('revision')) is not int
			or body['revision'] < 0
		):
			raise ValueError
		return web.json_response({'run': await self.jobs.start_summary(body['revision'])}, status=202)

	async def backup_status(self, request):
		if self.backup_operation.locked():
			raise BusyError('备份操作正在处理中, 请稍后重新读取')
		return web.json_response(self.backups.status())

	async def create_backup(self, request):
		body = await request.json()
		if not isinstance(body, dict) or set(body) != {'revision'} or type(body.get('revision')) is not int:
			raise ValueError
		if self.backup_operation.locked():
			raise BusyError('已有备份操作正在处理')
		async with self.backup_operation:
			return web.json_response({'backup': await self.backups.create(body['revision'])}, status=201)

	async def download_backup(self, request):
		path = self.backups.manager.read(request.match_info['backup_id'])
		return web.FileResponse(
			path,
			headers={
				'Content-Type': 'application/octet-stream',
				'Content-Disposition': 'attachment; filename="' + path.name + '"',
			},
		)

	async def preview_backup(self, request):
		if self.backup_operation.locked() or self.jobs.active_id is not None or self.jobs._lock.locked():
			raise BusyError('请等待当前任务结束后再预览恢复')
		async with self.backup_operation, self.jobs._lock:
			reader = await request.clone(client_max_size=MAX_BACKUP_BYTES + 8192).multipart()
			fields: dict[str, bytes] = {}
			async for part in reader:
				if part.name not in {'revision', 'password', 'file'} or part.name in fields:
					raise BackupError('恢复上传字段无效')
				limit = MAX_BACKUP_BYTES if part.name == 'file' else 4096
				value = bytearray()
				while chunk := await part.read_chunk(65536):
					value.extend(chunk)
					if len(value) > limit:
						raise BackupError('备份文件或字段超出大小限制')
				fields[part.name] = bytes(value)
			if set(fields) != {'revision', 'password', 'file'}:
				raise BackupError('请提供备份文件和恢复密码')
			try:
				revision = int(fields['revision'].decode('ascii'))
				password = fields['password'].decode('utf-8')
			except (ValueError, UnicodeError):
				raise BackupError('恢复上传字段无效') from None
			operation = asyncio.create_task(
				asyncio.to_thread(self.backups.manager.preview, fields['file'], password, revision)
			)
			try:
				preview = await asyncio.shield(operation)
			except asyncio.CancelledError:
				await operation
				raise
			self.restore_context = {
				key: context for key, context in self.restore_context.items() if context['expires'] > time.monotonic()
			}
			self.restore_context[preview['ticket']] = {'password': password, 'expires': time.monotonic() + 600}
			return web.json_response(preview)

	async def reauthenticate(self, request, password: object) -> None:
		if not isinstance(password, str) or not 1 <= len(password) <= 512:
			raise BackupError('当前管理员密码错误')
		now = time.monotonic()
		self.attempts = [value for value in self.attempts if now - value < 60]
		ip = self.access.client_ip(request)
		attempts = [value for value in self.client_attempts.get(ip, []) if now - value < 60]
		if self._login_busy or len(self.attempts) >= 30 or len(attempts) >= 5:
			raise web.HTTPTooManyRequests(
				text=json.dumps({'error': '验证次数过多, 请在 60 秒后重试'}),
				content_type='application/json',
				headers={'Retry-After': '60'},
			)
		self.attempts.append(now)
		self.client_attempts[ip] = [*attempts, now]
		self._login_busy = True
		verification = asyncio.create_task(
			asyncio.to_thread(hashlib.scrypt, password.encode(), salt=self.salt, n=16384, r=8, p=1)
		)
		verification.add_done_callback(self.password_check_finished)
		digest = await asyncio.shield(verification)
		if not hmac.compare_digest(digest, self.digest):
			raise BackupError('当前管理员密码错误, 未替换数据')

	async def restore_backup(self, request):
		body = await request.json()
		if (
			not isinstance(body, dict)
			or set(body) != {'revision', 'ticket', 'admin_password'}
			or type(body.get('revision')) is not int
			or not isinstance(body.get('ticket'), str)
		):
			raise ValueError
		if self.backup_operation.locked() or self.jobs.active_id is not None or self.jobs._lock.locked():
			raise BusyError('请等待当前任务结束后再恢复')
		await self.reauthenticate(request, body['admin_password'])
		context = self.restore_context.pop(body['ticket'], None)
		if context is None or context['expires'] <= time.monotonic():
			raise BackupError('恢复预览已失效, 请重新上传并预览')
		async with self.backup_operation, self.jobs._lock:
			if self.jobs.active_id is not None:
				raise BusyError('请等待当前任务结束后再恢复')
			config, revision = self.store.load()
			if revision != body['revision']:
				raise ConflictError('配置已更新, 请重新预览恢复')
			# A pre-restore snapshot is independently encrypted and remains downloadable.
			password = config['backups']['password'] or context['password']

			async def commit_restore():
				staged = await asyncio.to_thread(self.backups.manager.prepare_restore, body['ticket'], revision)
				try:
					before = await asyncio.to_thread(
						self.backups.manager.create, password, config['backups']['retain_count']
					)
					await self.install_restore(staged)
					return before
				finally:
					staged.unlink(missing_ok=True)

			operation = asyncio.create_task(commit_restore(), name='restore-database')
			try:
				before = await asyncio.shield(operation)
			except asyncio.CancelledError:
				await operation
				raise
		return web.json_response({'restored': True, 'before_backup': before['id'], 'automatic_tasks_disabled': True})

	async def install_restore(self, staged: Path) -> None:
		self.maintenance = True
		original = self.data_dir / ('.restore-rollback-' + secrets.token_hex(16) + '.sqlite3')
		lease = self.jobs._instance_lock
		self.jobs._instance_lock = None
		installed = False
		moved_original = False
		try:
			await self.backups.close()
			await self.jobs.close()
			self.store.close()
			self.db.close()
			os.replace(self.data_dir / 'webui.sqlite3', original)
			moved_original = True
			os.replace(staged, self.data_dir / 'webui.sqlite3')
			await self.open_restored(lease)
			installed = True
		except BaseException:
			# Close partial replacement connections before rolling back, including on Windows.
			await self.backups.close()
			self.jobs._instance_lock = None
			await self.jobs.close()
			self.store.close()
			self.db.close()
			if moved_original:
				os.replace(original, self.data_dir / 'webui.sqlite3')
			await self.open_restored(lease)
			raise BackupError('恢复失败, 已恢复替换前的数据') from None
		finally:
			if installed:
				original.unlink(missing_ok=True)
			self.sessions.clear()
			self.restore_context.clear()
			self.maintenance = False

	async def open_restored(self, lease) -> None:
		self.store = ConfigStore(self.data_dir / 'webui.sqlite3', self.key)
		self.store.load()
		self.jobs = JobManager(self.store, self.data_dir, self.key, instance_lock=lease)
		self.db = sqlite3.connect(self.data_dir / 'webui.sqlite3')
		self.salt, self.digest = self.db.execute('SELECT salt,digest FROM web_auth WHERE id=1').fetchone()
		self.backups = BackupRuntime(self.store, self.data_dir, self.key, self.jobs)
		if self.scheduler_enabled:
			await self.jobs.open()
			await self.backups.open()

	async def refresh_balances(self, request):
		body = await request.json()
		if (
			not isinstance(body, dict)
			or set(body) - {'revision', 'account_id'}
			or type(body.get('revision')) is not int
			or body['revision'] < 0
			or (
				'account_id' in body
				and (not isinstance(body['account_id'], str) or not body['account_id'] or len(body['account_id']) > 128)
			)
		):
			raise ValueError
		return web.json_response(
			{'run': await self.jobs.start(body['revision'], kind='balance', account_id=body.get('account_id'))},
			status=202,
		)

	async def runs(self, request):
		return web.json_response({'runs': self.jobs.history()})

	async def static(self, request):
		name = (
			'index.html'
			if request.path in {'/', '/status'}
			else 'backups.html'
			if request.path == '/backups'
			else request.path.lstrip('/')
		)
		return web.FileResponse(STATIC_ROOT / name)

	async def health(self, request):
		return web.json_response({'ok': True})

	async def lifecycle(self, app):
		if self.scheduler_enabled:
			await self.jobs.open()
			await self.backups.open()
		try:
			yield
		finally:
			for token in tuple(self.sessions):
				await self.revoke(token)
			await self.backups.close()
			await self.jobs.close()
			self.store.close()
			self.db.close()


SERVICE = web.AppKey('service', WebService)


def create_app(
	data_dir: Path,
	key: bytes,
	password: str | None = None,
	*,
	scheduler: bool = True,
	public_origin: str = '',
	trusted_proxy_ips: tuple[str, ...] = (),
) -> web.Application:
	access = WebAccess(public_origin, trusted_proxy_ips)
	data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
	service = WebService(data_dir, key, password, scheduler=scheduler, access=access)
	app = web.Application(middlewares=[service.guard], client_max_size=1024 * 1024)
	app[SERVICE] = service
	app.on_response_prepare.append(service.headers)
	app.cleanup_ctx.append(service.lifecycle)
	app.router.add_get('/healthz', service.health)
	for path in ('/', '/status', '/backups', '/app.js', '/backups.js', '/style.css'):
		app.router.add_get(path, service.static)
	app.router.add_get('/api/session', service.session_status)
	app.router.add_post('/api/login', service.login)
	app.router.add_post('/api/logout', service.logout)
	app.router.add_get('/api/config', service.get_config)
	app.router.add_put('/api/config', service.save_config)
	app.router.add_get('/api/status', service.status)
	app.router.add_get('/api/balances', service.balances)
	app.router.add_get('/api/automation', service.automation)
	app.router.add_post('/api/automation/summary', service.send_summary)
	app.router.add_get('/api/backups', service.backup_status)
	app.router.add_post('/api/backups', service.create_backup)
	app.router.add_post('/api/backups/preview', service.preview_backup)
	app.router.add_post('/api/backups/restore', service.restore_backup)
	app.router.add_get('/api/backups/{backup_id}', service.download_backup)
	app.router.add_post('/api/balances/refresh', service.refresh_balances)
	app.router.add_get('/api/runs', service.runs)
	app.router.add_post('/api/runs', service.start_run)
	app.router.add_post('/api/runs/stop', service.stop_run)
	app.router.add_post('/api/accounts/resolve', service.resolve_attention)
	return app
