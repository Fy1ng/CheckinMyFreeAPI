"""Password-protected WebUI with explicit loopback or HTTPS ingress and CSRF checks."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlsplit

from aiohttp import web

from server.backup import MAX_BACKUP_BYTES, BackupError
from server.backup_runtime import BackupRuntime
from server.config_store import ConfigError, ConfigStore, ConflictError
from server.jobs import BusyError, JobManager, acquire_file_lock
from server.passkeys import PasskeyCeremonies, SecurityError, SecurityStore, binding
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
		self.security = SecurityStore(data_dir / 'webui.sqlite3')
		self.passkeys = PasskeyCeremonies(self.security)

	def session(self, request: web.Request) -> dict | None:
		token = request.cookies.get('checkin_web_session', '')
		session = self.sessions.get(token)
		if (
			session
			and session['expires'] > time.monotonic()
			and session['origin'] == request.get(WEB_ORIGIN)
			and session.get('auth_revision') == self.security.policy()['revision']
		):
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
			if mutating and self.backup_operation.locked() and request.path.startswith('/api/security/'):
				raise BusyError('请等待备份或恢复操作结束后修改登录安全设置')
			session = self.session(request)
			public = request.path in {
				'/',
				'/status',
				'/backups',
				'/security',
				'/app.js',
				'/backups.js',
				'/security.js',
				'/passkeys.js',
				'/style.css',
				'/logo.png',
				'/favicon.ico',
				'/api/login',
				'/api/passkey/login/options',
				'/api/passkey/login/verify',
				'/api/session',
				'/healthz',
			}
			if not public and session is None:
				return web.json_response({'error': '请先登录'}, status=401)
			if mutating and request.path not in {
				'/api/login',
				'/api/passkey/login/options',
				'/api/passkey/login/verify',
			}:
				if session is None or not hmac.compare_digest(request.headers.get('X-CSRF-Token', ''), session['csrf']):
					return web.json_response({'error': '页面凭据已失效, 请重新登录'}, status=403)
			return await handler(request)
		except ConflictError as error:
			return web.json_response({'error': str(error)}, status=409)
		except (ConfigError, ValueError, TypeError, RecursionError, json.JSONDecodeError) as error:
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
		return web.json_response(
			{
				'authenticated': session is not None,
				'csrf': session['csrf'] if session else '',
				**self.auth_capabilities(request),
			}
		)

	def passkey_origin(self, request) -> str:
		return self.access.public_origin or request[WEB_ORIGIN]

	def private_recovery(self, request) -> bool:
		if urlsplit(request[WEB_ORIGIN]).hostname not in {'localhost', '127.0.0.1', '::1'}:
			return False
		if any(name.lower() == 'forwarded' or name.lower().startswith('x-forwarded-') for name in request.headers):
			return False
		try:
			return ipaddress.ip_address(request.remote or '').is_loopback or self.access.trusted_peer(request)
		except ValueError:
			return False

	def auth_capabilities(self, request) -> dict:
		policy = self.security.policy()
		origin = self.passkey_origin(request)
		allowed = request[WEB_ORIGIN] == origin and (
			origin.startswith('https://') or urlsplit(origin).hostname == 'localhost'
		)
		return {
			'auth_mode': policy['mode'],
			'password_login_allowed': policy['mode'] == 'password' or self.private_recovery(request),
			'passkey_available': self.security.public(origin)['passkey_available'],
			'passkey_origin_allowed': allowed,
			'reauth_method': 'passkey'
			if policy['mode'] == 'passkey' and not self.private_recovery(request)
			else 'password',
		}

	def require_passkey_origin(self, request) -> str:
		if not self.auth_capabilities(request)['passkey_origin_allowed']:
			raise SecurityError('请使用配置的 HTTPS 管理地址进行 Passkey 操作')
		if not self.passkeys.check_limit(self.access.client_ip(request)):
			raise web.HTTPTooManyRequests(
				text=json.dumps({'error': 'Passkey 验证请求过多, 请稍后重试'}),
				content_type='application/json',
				headers={'Retry-After': '60'},
			)
		return self.passkey_origin(request)

	def session_binding(self, request) -> str:
		return binding(request.cookies.get('checkin_web_session', ''))

	def issue_session(self, request, *, method: str, credential_id: str | None = None, extra: dict | None = None):
		now = time.monotonic()
		self.sessions.pop(request.cookies.get('checkin_web_session', ''), None)
		self.sessions = {
			token: session
			for token, session in self.sessions.items()
			if session['expires'] > now and session.get('auth_revision') == self.security.policy()['revision']
		}
		if len(self.sessions) >= 16:
			self.sessions.pop(next(iter(self.sessions)))
		token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
		self.sessions[token] = {
			'csrf': csrf,
			'expires': now + 8 * 3600,
			'origin': request[WEB_ORIGIN],
			'auth_revision': self.security.policy()['revision'],
			'method': method,
			'credential_id': credential_id,
		}
		response = web.json_response(
			{'authenticated': True, 'csrf': csrf, **self.auth_capabilities(request), **(extra or {})}
		)
		response.set_cookie(
			'checkin_web_session',
			token,
			httponly=True,
			samesite='Strict',
			secure=request[WEB_ORIGIN].startswith('https://'),
			max_age=8 * 3600,
		)
		return response

	@staticmethod
	def login_limited():
		return web.json_response({'error': '尝试次数过多, 请在 60 秒后重试'}, status=429, headers={'Retry-After': '60'})

	def password_check_finished(self, task: asyncio.Task) -> None:
		self._login_busy = False
		# Retrieve an exception even if its HTTP handler was disconnected/cancelled.
		if not task.cancelled():
			task.exception()

	async def login(self, request):
		if self.security.policy()['mode'] == 'passkey' and not self.private_recovery(request):
			return web.json_response({'error': '当前已启用 Passkey 登录, 公网密码登录已关闭'}, status=403)
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
		return self.issue_session(request, method='password')

	async def passkey_login_options(self, request):
		origin = self.require_passkey_origin(request)
		if await request.json() != {}:
			raise ValueError
		browser = secrets.token_urlsafe(32)
		result = self.passkeys.begin('login', origin, binding(browser))
		response = web.json_response(result)
		response.set_cookie(
			'checkin_passkey_challenge',
			browser,
			httponly=True,
			samesite='Strict',
			secure=origin.startswith('https://'),
			max_age=180,
		)
		return response

	async def passkey_login_verify(self, request):
		origin = self.require_passkey_origin(request)
		body = await request.json()
		if not isinstance(body, dict) or set(body) != {'ticket', 'credential'}:
			raise ValueError
		identifier = self.passkeys.complete(
			'login',
			body['ticket'],
			body['credential'],
			origin,
			binding(request.cookies.get('checkin_passkey_challenge', '')),
		)
		response = self.issue_session(request, method='passkey', credential_id=identifier)
		response.set_cookie(
			'checkin_passkey_challenge',
			'',
			httponly=True,
			samesite='Strict',
			secure=origin.startswith('https://'),
			max_age=0,
		)
		return response

	async def security_status(self, request):
		return web.json_response(
			{
				**self.security.public(self.passkey_origin(request)),
				**self.auth_capabilities(request),
				'can_register': self.auth_capabilities(request)['passkey_origin_allowed'],
				'private_recovery_access': self.private_recovery(request),
			}
		)

	async def security_reauth(self, request):
		body = await request.json()
		if not isinstance(body, dict) or set(body) != {'password'}:
			raise ValueError
		await self.reauthenticate(request, body['password'])
		return web.json_response(
			{'reauth_token': self.passkeys.proof(request[WEB_ORIGIN], self.session_binding(request), 'password')}
		)

	async def security_reauth_options(self, request):
		origin = self.require_passkey_origin(request)
		if await request.json() != {}:
			raise ValueError
		return web.json_response(self.passkeys.begin('reauth', origin, self.session_binding(request)))

	async def security_reauth_verify(self, request):
		origin = self.require_passkey_origin(request)
		body = await request.json()
		if not isinstance(body, dict) or set(body) != {'ticket', 'credential'}:
			raise ValueError
		identifier = self.passkeys.complete(
			'reauth', body['ticket'], body['credential'], origin, self.session_binding(request)
		)
		return web.json_response(
			{'reauth_token': self.passkeys.proof(origin, self.session_binding(request), 'passkey', identifier)}
		)

	def consume_reauth(self, request, token, *, require_passkey: bool | None = None) -> dict:
		if require_passkey is None:
			require_passkey = self.auth_capabilities(request)['reauth_method'] == 'passkey'
		return self.passkeys.consume(
			token, request[WEB_ORIGIN], self.session_binding(request), require_passkey=require_passkey
		)

	async def security_register_options(self, request):
		origin = self.require_passkey_origin(request)
		body = await request.json()
		if not isinstance(body, dict) or set(body) != {'label', 'reauth_token'}:
			raise ValueError
		self.consume_reauth(request, body['reauth_token'])
		return web.json_response(
			self.passkeys.begin('register', origin, self.session_binding(request), label=body['label'])
		)

	async def security_register_verify(self, request):
		origin = self.require_passkey_origin(request)
		body = await request.json()
		if not isinstance(body, dict) or set(body) != {'ticket', 'credential'}:
			raise ValueError
		current = self.session(request)
		method = current['method'] if current else 'password'
		identifier = self.passkeys.complete(
			'register', body['ticket'], body['credential'], origin, self.session_binding(request)
		)
		self.passkeys.clear()
		return self.issue_session(request, method=method, extra={'registered': True, 'credential_id': identifier})

	async def security_mode(self, request):
		body = await request.json()
		if (
			not isinstance(body, dict)
			or set(body) != {'mode', 'revision', 'reauth_token'}
			or type(body.get('revision')) is not int
			or body.get('mode') not in {'password', 'passkey'}
		):
			raise ValueError
		proof = self.consume_reauth(
			request,
			body['reauth_token'],
			require_passkey=body['mode'] == 'passkey' or self.auth_capabilities(request)['reauth_method'] == 'passkey',
		)
		self.security.set_mode(body['mode'], body['revision'], self.passkey_origin(request), proof['method'])
		self.sessions.clear()
		self.passkeys.clear()
		return self.issue_session(
			request,
			method=proof['method'],
			credential_id=proof['credential_id'],
			extra={'mode': body['mode'], 'revision': self.security.policy()['revision']},
		)

	async def security_remove(self, request):
		body = await request.json()
		if (
			not isinstance(body, dict)
			or set(body) != {'revision', 'reauth_token'}
			or type(body.get('revision')) is not int
		):
			raise ValueError
		proof = self.consume_reauth(request, body['reauth_token'])
		self.security.remove(request.match_info['credential_id'], body['revision'], self.passkey_origin(request))
		self.sessions.clear()
		self.passkeys.clear()
		return self.issue_session(request, method=proof['method'], extra={'deleted': True})

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
		if self.auth_capabilities(request)['reauth_method'] == 'passkey':
			raise web.HTTPForbidden(
				text=json.dumps({'error': '当前操作需要重新验证 Passkey, 公网密码验证已关闭'}),
				content_type='application/json',
			)
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
			or set(body) not in ({'revision', 'ticket', 'admin_password'}, {'revision', 'ticket', 'reauth_token'})
			or type(body.get('revision')) is not int
			or not isinstance(body.get('ticket'), str)
		):
			raise ValueError
		if self.backup_operation.locked() or self.jobs.active_id is not None or self.jobs._lock.locked():
			raise BusyError('请等待当前任务结束后再恢复')
		if 'reauth_token' in body:
			self.consume_reauth(request, body['reauth_token'])
		else:
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
			self.security.close()
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
			self.security.close()
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
		self.security = SecurityStore(self.data_dir / 'webui.sqlite3')
		self.passkeys = PasskeyCeremonies(self.security)
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
			else 'security.html'
			if request.path == '/security'
			else 'logo.png'
			if request.path == '/favicon.ico'
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
			self.security.close()


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
	for path in (
		'/',
		'/status',
		'/backups',
		'/security',
		'/app.js',
		'/backups.js',
		'/security.js',
		'/passkeys.js',
		'/style.css',
		'/logo.png',
		'/favicon.ico',
	):
		app.router.add_get(path, service.static)
	app.router.add_get('/api/session', service.session_status)
	app.router.add_post('/api/login', service.login)
	app.router.add_post('/api/logout', service.logout)
	app.router.add_post('/api/passkey/login/options', service.passkey_login_options)
	app.router.add_post('/api/passkey/login/verify', service.passkey_login_verify)
	app.router.add_get('/api/security', service.security_status)
	app.router.add_post('/api/security/reauth', service.security_reauth)
	app.router.add_post('/api/security/reauth/options', service.security_reauth_options)
	app.router.add_post('/api/security/reauth/verify', service.security_reauth_verify)
	app.router.add_post('/api/security/register/options', service.security_register_options)
	app.router.add_post('/api/security/register/verify', service.security_register_verify)
	app.router.add_post('/api/security/mode', service.security_mode)
	app.router.add_delete('/api/security/passkeys/{credential_id}', service.security_remove)
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
