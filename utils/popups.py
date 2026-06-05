"""Semi Design 模态弹窗关闭"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

if TYPE_CHECKING:
	from playwright.async_api import Locator, Page

# Semi Design modal 结构特征：
# - role="dialog" + aria-modal="true" + .semi-modal
# - 右上角 .semi-modal-close（aria-label="close"）
# - 底部 .semi-modal-footer 内的操作按钮
MODAL_SELECTOR = 'div.semi-modal[role="dialog"][aria-modal="true"]'
CLOSE_BUTTON_SELECTORS = (
	'button.semi-modal-close',
	'button[aria-label="close"]',
	'.semi-modal-header button',
)
FOOTER_BUTTON_SELECTORS = (
	'.semi-modal-footer button.semi-button-primary',
	'.semi-modal-footer button:last-child',
	'.semi-modal-footer button',
)


async def _visible_modal_indices(modals: Locator) -> list[int]:
	indices: list[int] = []
	count = await modals.count()
	for i in range(count):
		try:
			if await modals.nth(i).is_visible():
				indices.append(i)
		except Exception:  # nosec B112
			continue
	return indices


async def _try_click(locator: Locator, timeout_ms: int) -> bool:
	if await locator.count() == 0:
		return False
	target = locator.first
	try:
		if not await target.is_visible():
			return False
		await target.click(timeout=timeout_ms)
		return True
	except Exception:
		return False


async def _try_click_first_match(modal: Locator, selectors: tuple[str, ...], timeout_ms: int) -> bool:
	for selector in selectors:
		if await _try_click(modal.locator(selector), timeout_ms):
			return True
	return False


async def dismiss_modal(modal: Locator, timeout_ms: int = 5000) -> bool:
	if await _try_click_first_match(modal, CLOSE_BUTTON_SELECTORS, timeout_ms):
		return True
	return await _try_click_first_match(modal, FOOTER_BUTTON_SELECTORS, timeout_ms)


async def dismiss_popups(
	page: Page,
	*,
	timeout_ms: int = 5000,
	max_rounds: int = 5,
	wait_between_ms: int = 400,
) -> int:
	"""关闭页面上所有 Semi Design 模态弹窗，返回成功关闭次数。"""
	closed = 0

	for _ in range(max_rounds):
		modals = page.locator(MODAL_SELECTOR)
		visible = await _visible_modal_indices(modals)
		if not visible:
			break

		round_closed = False
		for index in reversed(visible):
			if await dismiss_modal(modals.nth(index), timeout_ms):
				closed += 1
				round_closed = True

		if not round_closed:
			break

		await asyncio.sleep(wait_between_ms / 1000)

	return closed
