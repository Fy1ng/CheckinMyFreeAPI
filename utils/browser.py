"""浏览器登录辅助函数"""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from utils.popups import dismiss_popups, setup_popup_guard

if TYPE_CHECKING:
	from playwright.async_api import BrowserContext, Locator, Page

EMAIL_LOGIN_BUTTON = re.compile(r'邮箱|用户名|email|username|mail', re.I)
EMAIL_LOGIN_ENTRY_SELECTORS = (
	'button:has(.semi-icon-mail)',
	'button:has([aria-label="mail"])',
	'.semi-card button.semi-button-primary',
)
LOGIN_FORM_SELECTOR = 'form.semi-form'
USERNAME_SELECTORS = ('#username', 'input[name="username"]', 'input[name="email"]', 'input[type="email"]')
PASSWORD_SELECTORS = ('#password', 'input[name="password"]', 'input[type="password"]')  # nosec B105
SUBMIT_SELECTORS = (
	f'{LOGIN_FORM_SELECTOR} button[type="submit"]',
	'button[type="submit"]',
)
SESSION_COOKIE_NAME = 'session'
DEFAULT_TIMEOUT_MS = 60_000
FORM_ACTION_TIMEOUT_MS = 15_000
EMAIL_TAB_TIMEOUT_MS = 8_000
WAF_READY_TIMEOUT_MS = 30_000
SESSION_WAIT_TIMEOUT_MS = 15_000

_SITE_READY_JS = """() => {
	const wafBlockers = document.querySelector(
		'iframe[src*="captcha"], iframe[src*="verify"], iframe[src*="slide"], .nc-container, #nocaptcha'
	);
	if (wafBlockers) {
		const rect = wafBlockers.getBoundingClientRect?.();
		if (rect && rect.width > 0 && rect.height > 0) return false;
	}
	return !!document.querySelector('a, button');
}"""

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

	const mailIcon = document.querySelector('.semi-icon-mail, [aria-label="mail"]');
	const mailBtn = mailIcon?.closest('button');
	if (mailBtn && isVisible(mailBtn) && !inDialog(mailBtn)) {
		mailBtn.click();
		if (findUsername()) return true;
	}

	const clickables = [
		...document.querySelectorAll('.semi-card button'),
		...document.querySelectorAll('.semi-card .semi-tabs-tab'),
		...document.querySelectorAll('form.semi-form ~ button'),
	];

	for (const el of clickables) {
		if (!isVisible(el) || inDialog(el)) continue;
		el.click();
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
	return BrowserLoginSettings(
		headless=_env_bool('CHECKIN_HEADLESS', True),
		humanize=_env_bool('CHECKIN_HUMANIZE', True),
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
	}
	if settings.humanize:
		launch_kwargs['human_preset'] = 'careful'

	return await launch_persistent_context_async(str(settings.profile_dir), **launch_kwargs)


async def prepare_browser_page(page: Page) -> None:
	await setup_popup_guard(page)


async def wait_for_site_ready(page: Page, timeout_ms: int = WAF_READY_TIMEOUT_MS) -> None:
	"""等待 WAF 通过并关闭弹窗。"""
	waf_timeout = min(timeout_ms, WAF_READY_TIMEOUT_MS)
	await page.wait_for_load_state('domcontentloaded', timeout=waf_timeout)
	try:
		await page.wait_for_function(_SITE_READY_JS, timeout=waf_timeout)
	except Exception:
		await asyncio.sleep(2)
	closed = await dismiss_popups(page)
	if closed:
		print(f'[INFO] Dismissed {closed} popup dialog(s)')


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
	for _ in range(3):
		closed = await dismiss_popups(page)
		if closed == 0:
			break
		await asyncio.sleep(0.3)


async def _click_email_login_entry(page: Page) -> bool:
	for selector in EMAIL_LOGIN_ENTRY_SELECTORS:
		button = page.locator(selector).first
		try:
			if await button.is_visible():
				await button.click(timeout=FORM_ACTION_TIMEOUT_MS)
				return True
		except Exception:  # nosec B112
			continue

	try:
		button = page.get_by_role('button', name=EMAIL_LOGIN_BUTTON)
		if await button.is_visible():
			await button.click(timeout=FORM_ACTION_TIMEOUT_MS)
			return True
	except Exception:  # nosec B110
		pass

	return False


async def _open_email_login_form(page: Page, timeout_ms: int) -> None:
	deadline = time.monotonic() + timeout_ms / 1000

	while time.monotonic() < deadline:
		await _dismiss_blocking_overlays(page)
		if await _is_email_form_visible(page):
			return

		await _click_email_login_entry(page)
		if await _is_email_form_visible(page):
			return

		tabs = page.locator('.semi-card .semi-tabs-tab')
		tab_count = await tabs.count()
		for i in range(tab_count):
			tab = tabs.nth(i)
			if not await tab.is_visible():
				continue
			await tab.click(timeout=FORM_ACTION_TIMEOUT_MS)
			if await _is_email_form_visible(page):
				return

		if await page.evaluate(_OPEN_EMAIL_FORM_JS):
			await _dismiss_blocking_overlays(page)
			if await _is_email_form_visible(page):
				return

		await asyncio.sleep(2)

	remaining_ms = int((deadline - time.monotonic()) * 1000)
	if remaining_ms > 0:
		for selector in USERNAME_SELECTORS:
			try:
				await page.locator(selector).first.wait_for(state='visible', timeout=remaining_ms)
				await _dismiss_blocking_overlays(page)
				return
			except Exception:  # nosec B112
				continue

	print(f'[INFO] Login page URL: {page.url}')
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
	await wait_for_session_cookie(page, SESSION_WAIT_TIMEOUT_MS)


async def login_with_email_form(page: Page, email: str, password: str, timeout_ms: int) -> None:
	await _open_email_login_form(page, timeout_ms)
	await fill_email_credentials(page, email, password, timeout_ms)
	await submit_login_form(page, timeout_ms)
	await wait_for_site_ready(page, timeout_ms)
