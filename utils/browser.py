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

EMAIL_LOGIN_BUTTON = re.compile(r'邮箱或用户名')
LOGIN_FORM_SELECTOR = 'form.semi-form'
USERNAME_SELECTOR = '#username'
PASSWORD_SELECTOR = '#password'  # nosec B105
SUBMIT_SELECTOR = f'{LOGIN_FORM_SELECTOR} button[type="submit"]'
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


async def _is_email_form_visible(page: Page) -> bool:
	return bool(await page.locator(USERNAME_SELECTOR).is_visible())


async def _open_email_login_form(page: Page, timeout_ms: int) -> None:
	if await _is_email_form_visible(page):
		return

	try:
		button = page.get_by_role('button', name=EMAIL_LOGIN_BUTTON)
		await button.wait_for(state='visible', timeout=EMAIL_TAB_TIMEOUT_MS)
		await button.click(timeout=FORM_ACTION_TIMEOUT_MS)
	except Exception:
		tabs = page.locator('.semi-tabs-tab')
		tab_count = await tabs.count()
		for i in range(tab_count):
			tab = tabs.nth(i)
			if not await tab.is_visible():
				continue
			await tab.click(timeout=FORM_ACTION_TIMEOUT_MS)
			if await _is_email_form_visible(page):
				break

	await page.locator(USERNAME_SELECTOR).wait_for(
		state='visible',
		timeout=min(timeout_ms, FORM_ACTION_TIMEOUT_MS),
	)


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
	action_timeout = min(timeout_ms, FORM_ACTION_TIMEOUT_MS)
	username_input = page.locator(USERNAME_SELECTOR)
	password_input = page.locator(PASSWORD_SELECTOR)

	await username_input.wait_for(state='visible', timeout=action_timeout)
	await _set_input_value(username_input, email, action_timeout)

	await password_input.wait_for(state='visible', timeout=action_timeout)
	await _set_input_value(password_input, password, action_timeout)


async def submit_login_form(page: Page, timeout_ms: int) -> None:
	action_timeout = min(timeout_ms, FORM_ACTION_TIMEOUT_MS)
	submit = page.locator(SUBMIT_SELECTOR)
	await submit.wait_for(state='visible', timeout=action_timeout)
	await submit.click(timeout=action_timeout)
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
