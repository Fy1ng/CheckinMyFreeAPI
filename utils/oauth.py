"""Browser-native OAuth transactions with exact callback and state validation."""

from __future__ import annotations

import asyncio
import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlencode, urlsplit

if TYPE_CHECKING:
	from playwright.async_api import CDPSession


class AuthError(RuntimeError):
	def __init__(self, reason: str):
		self.reason = reason
		super().__init__(reason)


class ManualLoginRequired(AuthError):
	def __init__(self):
		super().__init__('MANUAL_LOGIN_REQUIRED')


def origin_of(url: str) -> str:
	parsed = urlsplit(url)
	if parsed.scheme not in {'http', 'https'} or not parsed.hostname or parsed.username or parsed.password:
		raise AuthError('INVALID_ORIGIN')
	return f'{parsed.scheme}://{parsed.netloc}'


def provider_path(path: str) -> str:
	if not isinstance(path, str) or not path.startswith('/') or path.startswith('//') or '\\' in path:
		raise AuthError('INVALID_PROVIDER_PATH')
	if any(ord(character) < 32 for character in path):
		raise AuthError('INVALID_PROVIDER_PATH')
	return path


async def browser_json(page, origin: str, path: str, *, method: str = 'GET', headers: dict | None = None) -> dict:
	if origin_of(page.url) != origin:
		raise AuthError('PROVIDER_ORIGIN_MISMATCH')
	result = await page.evaluate(
		"""async ({url, method, headers}) => {
		  try {
		    const response = await fetch(url, {
		      method, headers, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
		      referrerPolicy: 'no-referrer', signal: AbortSignal.timeout(30000)
		    });
		    const text = await response.text();
		    if (text.length > 1048576) return {status: response.status, data: null};
		    let data = null; try { data = JSON.parse(text); } catch {}
		    return {status: response.status, data};
		  } catch { return {status: 0, data: null}; }
		}""",
		{'url': origin + provider_path(path), 'method': method, 'headers': headers or {}},
	)
	status = result.get('status', 0)
	if status == 429:
		raise AuthError('RATE_LIMITED')
	if status == 403:
		raise AuthError('ACCESS_BLOCKED')
	if status == 0 or status >= 500:
		raise AuthError('NETWORK_OR_SERVICE_ERROR')
	if status == 401:
		raise AuthError('SESSION_EXPIRED')
	if status != 200 or not isinstance(result.get('data'), dict):
		raise AuthError('INVALID_API_RESPONSE')
	return dict(result['data'])


@dataclass(frozen=True, repr=False)
class OAuthAttempt:
	kind: str
	origin: str
	client_id: str
	state: str

	@property
	def authorization_url(self) -> str:
		query = {'response_type': 'code', 'client_id': self.client_id, 'state': self.state}
		if self.kind == 'linuxdo':
			base = 'https://connect.linux.do/oauth2/authorize'
		elif self.kind == 'github':
			base = 'https://github.com/login/oauth/authorize'
			query['scope'] = 'user:email'
		else:
			raise AuthError('UNSUPPORTED_OAUTH_PROVIDER')
		return base + '?' + urlencode(query)

	def callback_code(self, url: str) -> str:
		parsed = urlsplit(url)
		if origin_of(url) != self.origin or parsed.path not in {f'/oauth/{self.kind}', f'/api/oauth/{self.kind}'}:
			raise AuthError('OAUTH_CALLBACK_MISMATCH')
		query = parse_qs(parsed.query, keep_blank_values=True)
		states = query.get('state', [])
		if len(states) != 1 or not hmac.compare_digest(states[0].encode(), self.state.encode()):
			raise AuthError('OAUTH_STATE_MISMATCH')
		if 'error' in query:
			raise AuthError('OAUTH_DENIED')
		codes = query.get('code', [])
		if len(codes) != 1 or not codes[0] or len(codes[0]) > 4096:
			raise AuthError('INVALID_OAUTH_CODE')
		return codes[0]

	def can_approve(self, url: str) -> bool:
		expected = urlsplit(self.authorization_url)
		actual = urlsplit(url)
		if (actual.scheme, actual.netloc, actual.path) != (expected.scheme, expected.netloc, expected.path):
			return False
		query = parse_qs(actual.query)
		if query.get('client_id') != [self.client_id] or query.get('state') != [self.state]:
			return False
		return self.kind != 'github' or query.get('scope', ['user:email']) == ['user:email']


class OAuthFlow:
	def __init__(self, context, attempt: OAuthAttempt):
		self.context = context
		self.attempt = attempt
		self.completed: asyncio.Future[tuple[str | None, AuthError | None]] = asyncio.get_running_loop().create_future()
		self._patterns = [
			f'{attempt.origin}/oauth/{attempt.kind}*',
			f'{attempt.origin}/api/oauth/{attempt.kind}*',
		]
		self._consumed = False
		self._cdp: CDPSession | None = None

	async def install(self, page=None) -> None:
		if page is not None:
			# Playwright routes skip URLs reached inside HTTP redirect chains. Block the
			# callback at the browser network layer before the provider can consume it.
			session: CDPSession = await self.context.new_cdp_session(page)
			self._cdp = session
			session.on('Fetch.requestPaused', self._intercept_navigation)
			await session.send(
				'Fetch.enable',
				{
					'patterns': [
						{'urlPattern': pattern, 'resourceType': 'Document', 'requestStage': 'Request'}
						for pattern in self._patterns
					]
				},
			)
			return
		for pattern in self._patterns:
			await self.context.route(pattern, self._callback)

	async def _intercept_navigation(self, event: dict) -> None:
		session = self._cdp
		if session is None:
			return
		url = event.get('request', {}).get('url', '')
		await session.send('Fetch.failRequest', {'requestId': event['requestId'], 'errorReason': 'BlockedByClient'})
		self._capture(url)

	def _capture(self, url: str) -> None:
		if self.completed.done():
			return
		try:
			self.completed.set_result((self.attempt.callback_code(url), None))
		except AuthError as error:
			self.completed.set_result((None, error))

	async def open(self, page):
		try:
			return await page.goto(self.attempt.authorization_url, wait_until='domcontentloaded', timeout=60_000)
		except Exception:
			if not self.completed.done():
				raise
			# A captured callback intentionally ends navigation with ERR_BLOCKED_BY_CLIENT.
			return None

	async def _callback(self, route) -> None:
		try:
			code = self.attempt.callback_code(route.request.url)
			error = None
		except AuthError as failure:
			code, error = None, failure
		await route.fulfill(
			status=200,
			content_type='text/html',
			headers={'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer'},
			body='<meta charset="utf-8"><title>授权已接收</title><p>授权已接收，程序正在验证账号。请勿刷新。</p>',
		)
		if not self.completed.done():
			self.completed.set_result((code, error))

	async def approve_if_expected(self, page) -> bool:
		if not self.attempt.can_approve(page.url):
			return False
		if self.attempt.kind == 'linuxdo':
			button = page.locator('a[href^="/oauth2/approve"]').first
		else:
			button = page.locator('form[action="/login/oauth/authorize"] button[name="authorize"][value="1"]').first
		if await button.count() and await button.is_visible():
			await button.click(timeout=5000)
			return True
		return False

	async def wait(self, page, seconds: float, *, automatic: bool) -> bool:
		deadline = asyncio.get_running_loop().time() + seconds
		while not self.completed.done() and asyncio.get_running_loop().time() < deadline:
			if automatic:
				await self.approve_if_expected(page)
			await asyncio.wait([self.completed], timeout=min(0.5, max(0, deadline - asyncio.get_running_loop().time())))
		return self.completed.done()

	async def exchange(self, api_page) -> dict:
		if self._consumed or not self.completed.done():
			raise AuthError('OAUTH_CALLBACK_NOT_AVAILABLE')
		self._consumed = True
		code, error = self.completed.result()
		if error:
			raise error
		await self.close()
		query = urlencode({'code': code, 'state': self.attempt.state})
		payload = await browser_json(api_page, self.attempt.origin, f'/api/oauth/{self.attempt.kind}?{query}')
		if not payload.get('success') or not isinstance(payload.get('data'), dict):
			raise AuthError('OAUTH_EXCHANGE_FAILED')
		return dict(payload['data'])

	async def close(self) -> None:
		for pattern in self._patterns:
			await self.context.unroute(pattern, self._callback)
		if self._cdp is not None:
			session, self._cdp = self._cdp, None
			try:
				await session.send('Fetch.disable')
			finally:
				await session.detach()
