"""浏览器登录辅助函数"""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from utils.popups import dismiss_popups, setup_popup_guard
from utils.proxy import get_playwright_proxy

if TYPE_CHECKING:
	from playwright.async_api import BrowserContext, Locator, Page

EMAIL_LOGIN_BUTTON_NAMES = (
	re.compile(r'邮箱或用户名'),
	re.compile(r'使用.*邮箱'),
	re.compile(r'Email or Username', re.I),
	re.compile(r'Sign in with Email', re.I),
	re.compile(r'Sign in with Email or Username', re.I),
)
EMAIL_LOGIN_ENTRY_SELECTORS = (
	'.semi-card button:has(.semi-icon-mail):not(form.semi-form button)',
	'.semi-card button:has([aria-label="mail"]):not(form.semi-form button)',
	'.semi-card button.semi-button-primary:has(.semi-icon-mail)',
	'button:has(.semi-icon-mail):not(form.semi-form button)',
)
LOGIN_PAGE_READY_SELECTORS = (
	'.semi-card button:has(.semi-icon-mail)',
	'.semi-card',
	'button:has(.semi-icon-mail)',
)
LOGIN_FORM_SELECTOR = 'form.semi-form'
USERNAME_SELECTORS = ('#username', 'input[name="username"]', 'input[name="email"]', 'input[type="email"]')
PASSWORD_SELECTORS = ('#password', 'input[name="password"]', 'input[type="password"]')  # nosec B105
SUBMIT_SELECTORS = (
	f'{LOGIN_FORM_SELECTOR} button[type="submit"]',
	'button[type="submit"]',
)
SESSION_COOKIE_NAME = 'session'
DEFAULT_SCREENSHOT_DIR = 'checkin_screenshots'
DEFAULT_TIMEOUT_MS = 60_000
_pending_notify_screenshots: list[Path] = []
FORM_ACTION_TIMEOUT_MS = 15_000
EMAIL_TAB_TIMEOUT_MS = 8_000
WAF_READY_TIMEOUT_MS = 30_000
SESSION_WAIT_TIMEOUT_MS = 45_000

_VISIBLE_CHECK_JS = """
	const isVisible = (el) => {
		if (!el || !el.isConnected) return false;
		const style = window.getComputedStyle(el);
		if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) {
			return false;
		}
		const rect = el.getBoundingClientRect();
		return rect.width > 0 && rect.height > 0;
	};
	const countVisible = (selector) => [...document.querySelectorAll(selector)].filter(isVisible).length;
"""

_SITE_READY_JS = f"""() => {{
{_VISIBLE_CHECK_JS}
	const text = document.body?.innerText || '';
	const blocked = /请进行验证|为了更好的访问体验|访问受限|Access denied|verify you are human/i.test(text);
	if (blocked) return false;
	const wafBlockers = document.querySelector(
		'iframe[src*="captcha"], iframe[src*="verify"], iframe[src*="slide"], .nc-container, #nocaptcha'
	);
	if (wafBlockers) {{
		const rect = wafBlockers.getBoundingClientRect?.();
		if (rect && rect.width > 0 && rect.height > 0) return false;
	}}
	if (/\\/login/.test(location.pathname)) {{
		return countVisible('.semi-card') > 0 || countVisible('#username') > 0 || countVisible('button') >= 2;
	}}
	return countVisible('a') > 0 || countVisible('button') > 0;
}}"""

_LOGIN_SHELL_READY_JS = f"""() => {{
{_VISIBLE_CHECK_JS}
	const text = document.body?.innerText || '';
	const blocked = /请进行验证|为了更好的访问体验|访问受限|Access denied|verify you are human/i.test(text);
	if (blocked) return false;
	return countVisible('.semi-card') > 0 || countVisible('#username') > 0 || countVisible('button') >= 2;
}}"""

_OPEN_EMAIL_FORM_JS = """() => {
	const isVisible = (el) => {
		if (!el || !el.isConnected) return false;
		const style = window.getComputedStyle(el);
		if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) {
			return false;
		}
		const rect = el.getBoundingClientRect();
		return rect.width > 0 && rect.height > 0;
	};

	const inDialog = (el) => !!el?.closest('[role="dialog"][aria-modal="true"], .semi-modal-content[role="dialog"]');

	const usernameSelectors = ['#username', 'input[name="username"]', 'input[name="email"]', 'input[type="email"]'];
	const findUsername = () => {
		for (const selector of usernameSelectors) {
			const el = document.querySelector(selector);
			if (isVisible(el)) return el;
		}
		return null;
	};

	if (findUsername()) return true;

	const entrySelectors = [
		'.semi-card button:has(.semi-icon-mail)',
		'.semi-card button:has([aria-label="mail"])',
	];
	for (const selector of entrySelectors) {
		for (const btn of document.querySelectorAll(selector)) {
			if (!isVisible(btn) || inDialog(btn) || btn.closest('form.semi-form')) continue;
			btn.click();
			if (findUsername()) return true;
		}
	}

	for (const tab of document.querySelectorAll('.semi-card .semi-tabs-tab')) {
		if (!isVisible(tab) || inDialog(tab)) continue;
		tab.click();
		if (findUsername()) return true;
	}

	return !!findUsername();
}"""


@dataclass(frozen=True)
class BrowserLoginSettings:
	headless: bool
	humanize: bool
	wait_timeout_ms: int
	profile_dir: Path
	cloakbrowser_binary_path: str | None


def _env_bool(name: str, default: bool) -> bool:
	raw = os.getenv(name)
	if raw is None:
		return default
	return raw.strip().lower() in {'1', 'true', 'yes', 'on'}


def load_browser_login_settings(account_name: str, provider: str) -> BrowserLoginSettings:
	profile_base = Path(os.getenv('CHECKIN_BROWSER_PROFILE_DIR', '.browser_profiles'))
	profile_dir = profile_base / provider / account_name
	humanize = _env_bool('CHECKIN_HUMANIZE', True)
	if provider == 'agentrouter':
		humanize = _env_bool('CHECKIN_HUMANIZE_AGENTROUTER', humanize)
	return BrowserLoginSettings(
		headless=_env_bool('CHECKIN_HEADLESS', True),
		humanize=humanize,
		wait_timeout_ms=int(os.getenv('CHECKIN_WAIT_TIMEOUT_MS', str(DEFAULT_TIMEOUT_MS))),
		profile_dir=profile_dir,
		cloakbrowser_binary_path=os.getenv('CLOAKBROWSER_BINARY_PATH', '').strip() or None,
	)


def _ensure_binary_path(settings: BrowserLoginSettings) -> None:
	if settings.cloakbrowser_binary_path:
		os.environ['CLOAKBROWSER_BINARY_PATH'] = settings.cloakbrowser_binary_path


async def launch_login_context(settings: BrowserLoginSettings) -> BrowserContext:
	from cloakbrowser import launch_persistent_context_async

	_ensure_binary_path(settings)
	settings.profile_dir.mkdir(parents=True, exist_ok=True)

	launch_kwargs: dict = {
		'headless': settings.headless,
		'humanize': settings.humanize,
		'viewport': {'width': 1920, 'height': 1080},
	}
	if settings.humanize:
		launch_kwargs['human_preset'] = 'careful'

	proxy = get_playwright_proxy()
	if proxy:
		launch_kwargs['proxy'] = proxy
		print(f'[INFO] Browser proxy enabled: {proxy["server"]}')

	return await launch_persistent_context_async(str(settings.profile_dir), **launch_kwargs)


def get_screenshot_dir() -> Path:
	return Path(os.getenv('CHECKIN_SCREENSHOT_DIR', DEFAULT_SCREENSHOT_DIR))


def _sanitize_screenshot_part(value: str) -> str:
	cleaned = re.sub(r'[^\w.-]+', '_', value.strip())
	return cleaned or 'unknown'


async def save_login_screenshot(
	page: Page,
	provider: str,
	account_name: str,
	label: str,
) -> Path | None:
	screenshot_dir = get_screenshot_dir()
	screenshot_dir.mkdir(parents=True, exist_ok=True)
	timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
	filename = (
		f'{_sanitize_screenshot_part(provider)}_{_sanitize_screenshot_part(account_name)}'
		f'_{timestamp}_{_sanitize_screenshot_part(label)}.png'
	)
	path = screenshot_dir / filename
	try:
		await page.screenshot(path=str(path), full_page=True, timeout=15_000)
		_pending_notify_screenshots.append(path)
		print(f'[INFO] Screenshot saved: {path}')
		return path
	except Exception as exc:
		print(f'[WARN] Failed to save screenshot ({label}): {exc}')
		return None


def take_pending_screenshots() -> list[Path]:
	"""取出待推送的登录截图列表并清空缓存。"""
	paths = list(_pending_notify_screenshots)
	_pending_notify_screenshots.clear()
	return paths


async def prepare_browser_page(page: Page) -> None:
	await setup_popup_guard(page)


async def wait_for_site_ready(page: Page, timeout_ms: int = WAF_READY_TIMEOUT_MS) -> None:
	"""等待 WAF 通过并关闭弹窗。"""
	waf_timeout = min(timeout_ms, WAF_READY_TIMEOUT_MS)
	await page.wait_for_load_state('domcontentloaded', timeout=waf_timeout)
	try:
		await page.wait_for_function(_SITE_READY_JS, timeout=waf_timeout)
	except Exception:
		await asyncio.sleep(3)
	closed = await dismiss_popups(page)
	if closed:
		print(f'[INFO] Dismissed {closed} popup dialog(s)')


async def _wait_for_login_shell(page: Page, timeout_ms: int) -> bool:
	shell_timeout = min(timeout_ms, 60_000)
	try:
		await page.wait_for_function(_LOGIN_SHELL_READY_JS, timeout=shell_timeout)
		return True
	except Exception:  # nosec B110
		return False


async def navigate_login_page(
	page: Page,
	login_url: str,
	timeout_ms: int,
	*,
	provider: str = '',
	account_name: str = '',
) -> None:
	"""预热站点、导航登录页并等待 SPA 渲染完成。"""
	from urllib.parse import urlparse

	parsed = urlparse(login_url)
	base_url = f'{parsed.scheme}://{parsed.netloc}/'
	attempt_timeout = min(timeout_ms, 60_000)

	try:
		print(f'[INFO] Warming up {base_url} before login')
		await page.goto(base_url, wait_until='load', timeout=attempt_timeout)
		await asyncio.sleep(3)
		try:
			await page.wait_for_load_state('networkidle', timeout=15_000)
		except Exception:  # nosec B110
			pass
		closed = await dismiss_popups(page)
		if closed:
			print(f'[INFO] Dismissed {closed} popup dialog(s) during warmup')
	except Exception as exc:
		print(f'[WARN] Warmup navigation failed: {exc}')

	for attempt in range(3):
		print(f'[INFO] Navigating login page (attempt {attempt + 1}/3): {login_url}')
		await page.goto(login_url, wait_until='load', timeout=attempt_timeout)
		await asyncio.sleep(5)
		try:
			await page.wait_for_load_state('networkidle', timeout=20_000)
		except Exception:  # nosec B110
			pass

		if await _wait_for_login_shell(page, attempt_timeout):
			await wait_for_site_ready(page, timeout_ms)
			if await page.evaluate(_LOGIN_SHELL_READY_JS):
				return

		print(f'[WARN] Login page shell not ready on attempt {attempt + 1}')
		await _log_login_page_state(page)
		if provider and account_name:
			await save_login_screenshot(page, provider, account_name, f'login-shell-attempt-{attempt + 1}')
		if attempt < 2:
			await asyncio.sleep(5)
			try:
				await page.reload(wait_until='load', timeout=attempt_timeout)
			except Exception:  # nosec B110
				pass

	raise TimeoutError(f'Login page never rendered: {login_url}')


async def has_session_cookie(page: Page) -> bool:
	cookies = await page.context.cookies()
	return any(c.get('name') == SESSION_COOKIE_NAME and c.get('value') for c in cookies)


async def wait_for_session_cookie(page: Page, timeout_ms: int = SESSION_WAIT_TIMEOUT_MS) -> bool:
	deadline = time.monotonic() + timeout_ms / 1000
	while time.monotonic() < deadline:
		if await has_session_cookie(page):
			return True
		await asyncio.sleep(0.5)
	return False


async def ensure_session_after_login(page: Page, console_url: str, timeout_ms: int) -> bool:
	"""提交登录后等待 session；若仍未拿到则跳转 console 再试。"""
	session_timeout = min(timeout_ms, SESSION_WAIT_TIMEOUT_MS)
	if await wait_for_session_cookie(page, session_timeout):
		return True

	print(f'[INFO] Session cookie not found yet, navigating to {console_url}')
	try:
		await page.goto(console_url, wait_until='load', timeout=min(timeout_ms, 60_000))
		try:
			await page.wait_for_load_state('networkidle', timeout=20_000)
		except Exception:  # nosec B110
			pass
	except Exception as exc:
		print(f'[WARN] Console navigation failed: {exc}')
		return False

	return await wait_for_session_cookie(page, session_timeout)


async def wait_for_waf_ready(page: Page, timeout_ms: int = WAF_READY_TIMEOUT_MS) -> None:
	await wait_for_site_ready(page, timeout_ms)


async def _first_visible_locator(page: Page, selectors: tuple[str, ...]) -> Locator | None:
	for selector in selectors:
		locator = page.locator(selector).first
		try:
			if await locator.is_visible():
				return locator
		except Exception:  # nosec B112
			continue
	return None


async def _is_email_form_visible(page: Page) -> bool:
	return await _first_visible_locator(page, USERNAME_SELECTORS) is not None


async def _dismiss_blocking_overlays(page: Page) -> None:
	if await _is_email_form_visible(page):
		return
	for _ in range(3):
		closed = await dismiss_popups(page)
		if closed == 0:
			break
		await asyncio.sleep(0.3)


async def _click_locator(button: Locator) -> bool:
	try:
		await button.scroll_into_view_if_needed()
		await button.click(timeout=FORM_ACTION_TIMEOUT_MS)
		return True
	except Exception:
		try:
			await button.click(force=True, timeout=FORM_ACTION_TIMEOUT_MS)
			return True
		except Exception:  # nosec B112
			return False


async def _wait_for_login_page_ready(page: Page, timeout_ms: int) -> None:
	if await _is_email_form_visible(page):
		return

	remaining_ms = timeout_ms
	for selector in LOGIN_PAGE_READY_SELECTORS:
		if remaining_ms <= 0:
			break
		try:
			await page.locator(selector).first.wait_for(state='visible', timeout=remaining_ms)
			return
		except Exception:  # nosec B112
			continue

	for pattern in EMAIL_LOGIN_BUTTON_NAMES:
		if remaining_ms <= 0:
			break
		try:
			await page.get_by_role('button', name=pattern).first.wait_for(state='visible', timeout=remaining_ms)
			return
		except Exception:  # nosec B112
			continue


async def _click_email_login_entry(page: Page) -> bool:
	for selector in EMAIL_LOGIN_ENTRY_SELECTORS:
		buttons = page.locator(selector)
		button_count = await buttons.count()
		for index in range(button_count):
			button = buttons.nth(index)
			try:
				if await button.is_visible():
					if await _click_locator(button):
						return True
			except Exception:  # nosec B112
				continue

	for pattern in EMAIL_LOGIN_BUTTON_NAMES:
		for scope in (page.locator('.semi-card'), page):
			try:
				button = scope.get_by_role('button', name=pattern).first
				if await button.is_visible() and await _click_locator(button):
					return True
			except Exception:  # nosec B112
				continue

	return False


async def _wait_for_username_input(page: Page, timeout_ms: int) -> bool:
	if timeout_ms <= 0:
		return await _is_email_form_visible(page)

	for selector in USERNAME_SELECTORS:
		try:
			await page.locator(selector).first.wait_for(state='visible', timeout=timeout_ms)
			return True
		except Exception:  # nosec B112
			continue
	return False


async def _log_login_page_state(page: Page) -> None:
	state = await page.evaluate(
		"""() => {
			const isVisible = (el) => {
				if (!el || !el.isConnected) return false;
				const style = window.getComputedStyle(el);
				if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) return false;
				const rect = el.getBoundingClientRect();
				return rect.width > 0 && rect.height > 0;
			};
			const buttons = [...document.querySelectorAll('button')]
				.filter(isVisible)
				.map((b) => (b.innerText || '').trim().replace(/\\s+/g, ' ').slice(0, 60));
			return {
				title: document.title || '',
				readyState: document.readyState,
				bodySnippet: (document.body?.innerText || '').trim().replace(/\\s+/g, ' ').slice(0, 300),
				scriptCount: document.querySelectorAll('script').length,
				hasSemiCard: !!document.querySelector('.semi-card'),
				mailEntryCount: document.querySelectorAll('.semi-card button:has(.semi-icon-mail)').length,
				usernameVisible: isVisible(document.querySelector('#username')),
				modalVisible: [...document.querySelectorAll('div[role="dialog"][aria-modal="true"]')].some(isVisible),
				buttons: buttons.slice(0, 8),
			};
		}"""
	)
	print(f'[INFO] Login page state: {state}')


async def _open_email_login_form(
	page: Page,
	timeout_ms: int,
	*,
	provider: str = '',
	account_name: str = '',
) -> None:
	deadline = time.monotonic() + timeout_ms / 1000

	await _dismiss_blocking_overlays(page)
	if await _is_email_form_visible(page):
		return

	ready_timeout = min(timeout_ms, WAF_READY_TIMEOUT_MS)
	try:
		await _wait_for_login_page_ready(page, ready_timeout)
	except Exception:  # nosec B110
		pass

	while time.monotonic() < deadline:
		remaining_ms = int((deadline - time.monotonic()) * 1000)
		if remaining_ms <= 0:
			break

		await _dismiss_blocking_overlays(page)
		if await _is_email_form_visible(page):
			return

		if await _click_email_login_entry(page):
			await asyncio.sleep(1)
			wait_ms = min(remaining_ms, FORM_ACTION_TIMEOUT_MS)
			if await _wait_for_username_input(page, wait_ms):
				return

		tabs = page.locator('.semi-card .semi-tabs-tab')
		tab_count = await tabs.count()
		for index in range(tab_count):
			tab = tabs.nth(index)
			if not await tab.is_visible():
				continue
			await tab.click(timeout=EMAIL_TAB_TIMEOUT_MS)
			wait_ms = min(int((deadline - time.monotonic()) * 1000), EMAIL_TAB_TIMEOUT_MS)
			if await _wait_for_username_input(page, wait_ms):
				return

		if await page.evaluate(_OPEN_EMAIL_FORM_JS):
			await asyncio.sleep(1)
			wait_ms = min(int((deadline - time.monotonic()) * 1000), FORM_ACTION_TIMEOUT_MS)
			if await _wait_for_username_input(page, wait_ms):
				return

		await asyncio.sleep(0.5)

	remaining_ms = int((deadline - time.monotonic()) * 1000)
	if remaining_ms > 0 and await _wait_for_username_input(page, remaining_ms):
		return

	print(f'[INFO] Login page URL: {page.url}')
	await _log_login_page_state(page)
	if provider and account_name:
		await save_login_screenshot(page, provider, account_name, 'email-form-timeout')
	raise TimeoutError(f'Cannot open email login form, selectors: {USERNAME_SELECTORS}')


async def _set_input_value(locator: Locator, value: str, timeout_ms: int) -> None:
	click_timeout = min(timeout_ms, 5000)
	try:
		await locator.click(timeout=click_timeout)
	except Exception:
		try:
			await locator.click(force=True, timeout=click_timeout)
		except Exception:  # nosec B110
			pass

	try:
		await locator.fill(value, timeout=timeout_ms)
		if await locator.input_value(timeout=2000) == value:
			return
	except Exception:  # nosec B110
		pass

	await locator.evaluate(
		"""(el, v) => {
			const setter = Object.getOwnPropertyDescriptor(
				window.HTMLInputElement.prototype, 'value'
			)?.set;
			setter?.call(el, v);
			el.dispatchEvent(new Event('input', { bubbles: true }));
			el.dispatchEvent(new Event('change', { bubbles: true }));
		}""",
		value,
	)


async def fill_email_credentials(page: Page, email: str, password: str, timeout_ms: int) -> None:
	await _dismiss_blocking_overlays(page)
	action_timeout = min(timeout_ms, FORM_ACTION_TIMEOUT_MS)

	username_input = await _first_visible_locator(page, USERNAME_SELECTORS)
	if not username_input:
		for selector in USERNAME_SELECTORS:
			locator = page.locator(selector).first
			try:
				await locator.wait_for(state='visible', timeout=action_timeout)
				username_input = locator
				break
			except Exception:  # nosec B112
				continue
	if not username_input:
		raise TimeoutError(f'Cannot find username input: {USERNAME_SELECTORS}')

	password_input = await _first_visible_locator(page, PASSWORD_SELECTORS)
	if not password_input:
		for selector in PASSWORD_SELECTORS:
			locator = page.locator(selector).first
			try:
				await locator.wait_for(state='visible', timeout=action_timeout)
				password_input = locator
				break
			except Exception:  # nosec B112
				continue
	if not password_input:
		raise TimeoutError(f'Cannot find password input: {PASSWORD_SELECTORS}')

	await _set_input_value(username_input, email, action_timeout)
	await _set_input_value(password_input, password, action_timeout)


async def submit_login_form(page: Page, timeout_ms: int) -> None:
	action_timeout = min(timeout_ms, FORM_ACTION_TIMEOUT_MS)
	submit = await _first_visible_locator(page, SUBMIT_SELECTORS)
	if not submit:
		for selector in SUBMIT_SELECTORS:
			locator = page.locator(selector).first
			try:
				await locator.wait_for(state='visible', timeout=action_timeout)
				submit = locator
				break
			except Exception:  # nosec B112
				continue
	if not submit:
		raise TimeoutError(f'Cannot find submit button: {SUBMIT_SELECTORS}')
	try:
		await submit.click(timeout=action_timeout)
	except Exception:
		await submit.click(force=True, timeout=action_timeout)
	try:
		await page.wait_for_load_state('domcontentloaded', timeout=action_timeout)
	except Exception:  # nosec B110
		pass
	try:
		await page.wait_for_load_state('networkidle', timeout=min(timeout_ms, 30_000))
	except Exception:  # nosec B110
		pass
	await wait_for_session_cookie(page, SESSION_WAIT_TIMEOUT_MS)


async def login_with_email_form(
	page: Page,
	email: str,
	password: str,
	timeout_ms: int,
	*,
	provider: str = '',
	account_name: str = '',
) -> None:
	await _open_email_login_form(
		page,
		timeout_ms,
		provider=provider,
		account_name=account_name,
	)
	await fill_email_credentials(page, email, password, timeout_ms)
	await submit_login_form(page, timeout_ms)
