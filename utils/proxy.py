"""代理配置：读取环境变量并供浏览器 / HTTP 客户端使用。"""

from __future__ import annotations

import os


def get_proxy_server() -> str | None:
	"""仅使用 CHECKIN_PROXY_URL，避免污染 GitHub Actions 等全局 HTTP_PROXY。"""
	server = os.getenv('CHECKIN_PROXY_URL', '').strip()
	return server or None


def get_playwright_proxy() -> dict[str, str] | None:
	server = get_proxy_server()
	if not server:
		return None
	return {'server': server}


def apply_proxy_env() -> None:
	"""仅在当前 Python 进程内为 httpx 设置代理，不写入 shell 全局环境。"""
	server = os.getenv('CHECKIN_PROXY_URL', '').strip()
	if not server:
		return
	os.environ['HTTP_PROXY'] = server
	os.environ['HTTPS_PROXY'] = server
	os.environ['http_proxy'] = server
	os.environ['https_proxy'] = server
	os.environ['NO_PROXY'] = '127.0.0.1,localhost'
	os.environ['no_proxy'] = '127.0.0.1,localhost'
