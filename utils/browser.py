"""浏览器登录辅助函数"""

from __future__ import annotations

import asyncio
import re
from typing import TYPE_CHECKING

from utils.popups import dismiss_popups

if TYPE_CHECKING:
	from playwright.async_api import Locator, Page

EMAIL_LOGIN_BUTTON = re.compile(r'邮箱或用户名')
LOGIN_FORM_SELECTOR = 'form.semi-form'
USERNAME_SELECTOR = '#username'
PASSWORD_SELECTOR = '#password'  # nosec B105
SUBMIT_SELECTOR = f'{LOGIN_FORM_SELECTOR} button[type="submit"]'
LOGGED_IN_HINTS = re.compile(
	r'console|dashboard|panel|控制台|退出|logout|api\s*key|令牌|token',
	re.I,
)

DEFAULT_TIMEOUT_MS = 30_000


async def wait_for_site_ready(page: Page, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> None:
	"""等待 WAF 挑战通过并关闭公告弹窗。"""
	await page.wait_for_load_state('domcontentloaded', timeout=timeout_ms)
	try:
		await page.wait_for_function(
			"""() => {
				const text = document.body?.innerText || '';
				const blocked = text.includes('请进行验证') || text.includes('为了更好的访问体验');
				const hasAction = !!document.querySelector('a, button');
				return hasAction && !blocked;
			}""",
			timeout=timeout_ms,
		)
	except Exception:
		await asyncio.sleep(5)
	await dismiss_popups(page)


async def is_logged_in(page: Page) -> bool:
	url = page.url.lower()
	if any(path in url for path in ('/console', '/dashboard', '/panel')):
		return True
	try:
		body = await page.locator('body').inner_text(timeout=3000)
	except Exception:
		return False
	return bool(LOGGED_IN_HINTS.search(body))


async def _is_email_form_visible(page: Page) -> bool:
	return bool(await page.locator(USERNAME_SELECTOR).is_visible())


async def _open_email_login_form(page: Page, timeout_ms: int) -> None:
	if await _is_email_form_visible(page):
		return

	button = page.get_by_role('button', name=EMAIL_LOGIN_BUTTON)
	await button.wait_for(state='visible', timeout=timeout_ms)
	await button.click(timeout=timeout_ms)
	await page.locator(USERNAME_SELECTOR).wait_for(state='visible', timeout=timeout_ms)


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
	username_input = page.locator(USERNAME_SELECTOR)
	password_input = page.locator(PASSWORD_SELECTOR)

	await username_input.wait_for(state='visible', timeout=timeout_ms)
	await _set_input_value(username_input, email, timeout_ms)

	await password_input.wait_for(state='visible', timeout=timeout_ms)
	await _set_input_value(password_input, password, timeout_ms)


async def submit_login_form(page: Page, timeout_ms: int) -> None:
	submit = page.locator(SUBMIT_SELECTOR)
	await submit.wait_for(state='visible', timeout=timeout_ms)
	await submit.click(timeout=timeout_ms)
	await page.wait_for_load_state('networkidle', timeout=timeout_ms)


async def login_with_email_form(page: Page, email: str, password: str, timeout_ms: int = DEFAULT_TIMEOUT_MS) -> None:
	await _open_email_login_form(page, timeout_ms)
	await fill_email_credentials(page, email, password, timeout_ms)
	await submit_login_form(page, timeout_ms)
	await wait_for_site_ready(page, timeout_ms)
