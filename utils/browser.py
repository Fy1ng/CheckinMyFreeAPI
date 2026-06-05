"""浏览器登录辅助函数"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

from utils.popups import setup_popup_guard

if TYPE_CHECKING:
	from playwright.async_api import Locator, Page

LOGIN_FORM_SELECTOR = 'form.semi-form'
USERNAME_SELECTORS = ('#username', 'input[name="username"]', 'input[name="email"]', 'input[type="email"]')
PASSWORD_SELECTORS = ('#password', 'input[name="password"]', 'input[type="password"]')  # nosec B105
SUBMIT_SELECTORS = (
	f'{LOGIN_FORM_SELECTOR} button[type="submit"]',
	'button[type="submit"]',
)

DEFAULT_TIMEOUT_MS = 30_000
SESSION_COOKIE_NAME = 'session'

# 页面可交互判定：基于 DOM 结构
_SITE_READY_JS = """() => {
	const wafBlockers = document.querySelector(
		'iframe[src*="captcha"], iframe[src*="verify"], iframe[src*="slide"], .nc-container, #nocaptcha'
	);
	if (wafBlockers) {
		const rect = wafBlockers.getBoundingClientRect?.();
		if (rect && rect.width > 0 && rect.height > 0) return false;
	}
	return !!document.querySelector(
		'form.semi-form, #username, #password, input[name="username"], input[name="email"], a[href], button:not([disabled])'
	);
}"""


async def prepare_browser_page(page: Page) -> None:
	"""初始化浏览器页面：注入弹窗自动关闭脚本。"""
	await setup_popup_guard(page)


async def wait_for_waf_ready(page: Page, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> None:
	"""等待 WAF 挑战完成（仅用于不登录、只取 cookie 的场景）。"""
	await page.wait_for_load_state('domcontentloaded', timeout=timeout_ms)
	try:
		await page.wait_for_function(_SITE_READY_JS, timeout=timeout_ms)
	except Exception:
		await asyncio.sleep(5)


async def _first_visible_locator(page: Page, selectors: tuple[str, ...]) -> Locator | None:
	for selector in selectors:
		locator = page.locator(selector).first
		try:
			if await locator.is_visible():
				return locator
		except Exception:  # nosec B112
			continue
	return None


async def has_session_cookie(page: Page) -> bool:
	cookies = await page.context.cookies()
	return any(c.get('name') == SESSION_COOKIE_NAME and c.get('value') for c in cookies)


async def wait_for_session_cookie(page: Page, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> bool:
	"""等待 httpOnly session cookie 写入（只能通过 context.cookies 检测）。"""
	deadline = time.monotonic() + timeout_ms / 1000
	while time.monotonic() < deadline:
		if await has_session_cookie(page):
			return True
		await asyncio.sleep(0.5)
	return False


async def _wait_for_visible_locator(page: Page, selectors: tuple[str, ...], timeout_ms: int) -> Locator:
	last_error: Exception | None = None
	per_selector_timeout = max(timeout_ms // len(selectors), 2000)
	for selector in selectors:
		locator = page.locator(selector).first
		try:
			await locator.wait_for(state='visible', timeout=per_selector_timeout)
			return locator
		except Exception as exc:
			last_error = exc
	raise TimeoutError(f'Cannot find visible element for selectors: {selectors}') from last_error


async def _is_email_form_visible(page: Page) -> bool:
	return await _first_visible_locator(page, USERNAME_SELECTORS) is not None


async def _open_email_login_form(page: Page, timeout_ms: int) -> None:
	if await _is_email_form_visible(page):
		return

	tabs = page.locator('.semi-tabs-tab')
	tab_count = await tabs.count()
	for i in range(tab_count):
		tab = tabs.nth(i)
		if not await tab.is_visible():
			continue
		await tab.click(timeout=timeout_ms)
		if await _is_email_form_visible(page):
			return

	alt_buttons = page.locator(f'{LOGIN_FORM_SELECTOR} ~ button, .semi-button-group button')
	alt_count = await alt_buttons.count()
	for i in range(alt_count):
		btn = alt_buttons.nth(i)
		if not await btn.is_visible():
			continue
		await btn.click(timeout=timeout_ms)
		if await _is_email_form_visible(page):
			return

	await _wait_for_visible_locator(page, USERNAME_SELECTORS, timeout_ms)


async def _set_input_value(locator: Locator, value: str, timeout_ms: int) -> None:
	await locator.click(timeout=timeout_ms)
	await locator.fill(value, timeout=timeout_ms)
	try:
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
	username_input = await _first_visible_locator(page, USERNAME_SELECTORS)
	if not username_input:
		username_input = await _wait_for_visible_locator(page, USERNAME_SELECTORS, timeout_ms)

	password_input = await _first_visible_locator(page, PASSWORD_SELECTORS)
	if not password_input:
		password_input = await _wait_for_visible_locator(page, PASSWORD_SELECTORS, timeout_ms)

	await _set_input_value(username_input, email, timeout_ms)
	await _set_input_value(password_input, password, timeout_ms)


async def submit_login_form(page: Page, timeout_ms: int) -> None:
	submit = await _first_visible_locator(page, SUBMIT_SELECTORS)
	if not submit:
		submit = await _wait_for_visible_locator(page, SUBMIT_SELECTORS, timeout_ms)

	await submit.click(timeout=timeout_ms)
	try:
		await page.wait_for_load_state('networkidle', timeout=timeout_ms)
	except Exception:
		await asyncio.sleep(2)


async def login_with_email_form(page: Page, email: str, password: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> None:
	await wait_for_waf_ready(page, timeout_ms)
	await _open_email_login_form(page, timeout_ms)
	await fill_email_credentials(page, email, password, timeout_ms)
	await submit_login_form(page, timeout_ms)
	await wait_for_session_cookie(page, timeout_ms)
