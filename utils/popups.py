"""弹窗自动关闭：注入 JS 动态发现模态框特征并处理"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
	from playwright.async_api import Page

# 在页面内动态发现模态框并点击关闭按钮
_DISMISS_MODALS_JS = """() => {
	const isVisible = (el) => {
		if (!el || !el.isConnected) return false;
		const style = window.getComputedStyle(el);
		if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) {
			return false;
		}
		const rect = el.getBoundingClientRect();
		return rect.width > 0 && rect.height > 0;
	};

	const modalSelectors = [
		'div[role="dialog"][aria-modal="true"]',
		'div.semi-modal[role="dialog"]',
		'div.semi-modal[aria-modal="true"]',
	];

	const closeSelectors = [
		'button.semi-modal-close',
		'button[aria-label="close"]',
		'button[aria-label="Close"]',
		'.semi-modal-header button',
		'.semi-modal-footer button.semi-button-primary',
		'.semi-modal-footer button:last-child',
		'.semi-modal-footer button',
	];

	const findModals = () => {
		const seen = new Set();
		const modals = [];
		for (const selector of modalSelectors) {
			for (const el of document.querySelectorAll(selector)) {
				if (isVisible(el) && !seen.has(el)) {
					seen.add(el);
					modals.push(el);
				}
			}
		}
		return modals.sort((a, b) => {
			const za = parseInt(window.getComputedStyle(a).zIndex, 10) || 0;
			const zb = parseInt(window.getComputedStyle(b).zIndex, 10) || 0;
			return zb - za;
		});
	};

	const findCloseButton = (modal) => {
		for (const selector of closeSelectors) {
			const btn = modal.querySelector(selector);
			if (btn && isVisible(btn)) return btn;
		}
		return null;
	};

	const dismissOnce = () => {
		let closed = 0;
		const modals = findModals();
		for (const modal of [...modals].reverse()) {
			const btn = findCloseButton(modal);
			if (btn) {
				btn.click();
				closed += 1;
			}
		}
		return closed;
	};

	let total = 0;
	for (let round = 0; round < 5; round += 1) {
		const closed = dismissOnce();
		if (closed === 0) break;
		total += closed;
	}
	return total;
}"""

# 页面加载前注入：MutationObserver 监听 DOM 变化，防抖后自动关闭弹窗
_POPUP_GUARD_INIT_SCRIPT = """() => {
	if (window.__popupGuardInstalled) return;
	window.__popupGuardInstalled = true;

	const isVisible = (el) => {
		if (!el || !el.isConnected) return false;
		const style = window.getComputedStyle(el);
		if (style.display === 'none' || style.visibility === 'hidden' || parseFloat(style.opacity) === 0) {
			return false;
		}
		const rect = el.getBoundingClientRect();
		return rect.width > 0 && rect.height > 0;
	};

	const modalSelectors = [
		'div[role="dialog"][aria-modal="true"]',
		'div.semi-modal[role="dialog"]',
		'div.semi-modal[aria-modal="true"]',
	];

	const closeSelectors = [
		'button.semi-modal-close',
		'button[aria-label="close"]',
		'button[aria-label="Close"]',
		'.semi-modal-header button',
		'.semi-modal-footer button.semi-button-primary',
		'.semi-modal-footer button:last-child',
		'.semi-modal-footer button',
	];

	const findModals = () => {
		const seen = new Set();
		const modals = [];
		for (const selector of modalSelectors) {
			for (const el of document.querySelectorAll(selector)) {
				if (isVisible(el) && !seen.has(el)) {
					seen.add(el);
					modals.push(el);
				}
			}
		}
		return modals;
	};

	const findCloseButton = (modal) => {
		for (const selector of closeSelectors) {
			const btn = modal.querySelector(selector);
			if (btn && isVisible(btn)) return btn;
		}
		return null;
	};

	const dismissOnce = () => {
		let closed = 0;
		const modals = findModals();
		for (const modal of [...modals].reverse()) {
			const btn = findCloseButton(modal);
			if (btn) {
				btn.click();
				closed += 1;
			}
		}
		return closed;
	};

	const dismissLoop = () => {
		for (let round = 0; round < 3; round += 1) {
			if (dismissOnce() === 0) break;
		}
	};

	let timer = null;
	const scheduleDismiss = () => {
		clearTimeout(timer);
		timer = setTimeout(dismissLoop, 300);
	};

	const observer = new MutationObserver(scheduleDismiss);
	const startObserver = () => {
		if (!document.documentElement) return;
		observer.observe(document.documentElement, {
			childList: true,
			subtree: true,
			attributes: true,
			attributeFilter: ['class', 'style', 'aria-hidden', 'aria-modal'],
		});
		scheduleDismiss();
	};

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', startObserver, { once: true });
	} else {
		startObserver();
	}

	window.__dismissModals = dismissLoop;
}"""


async def setup_popup_guard(page: Page) -> None:
	"""为页面注入弹窗自动关闭脚本，后续弹窗由 MutationObserver 处理。"""
	await page.add_init_script(_POPUP_GUARD_INIT_SCRIPT)


async def dismiss_popups(page: Page) -> int:
	"""手动触发一次 JS 弹窗关闭（通常仅在需要立即清理时调用）。"""
	result = await page.evaluate(_DISMISS_MODALS_JS)
	return int(result) if result else 0
