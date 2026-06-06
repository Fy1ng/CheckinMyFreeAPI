"""代理配置：读取环境变量并供浏览器 / HTTP 客户端使用。"""

from __future__ import annotations

import os


def get_proxy_server() -> str | None:
	server = os.getenv('CHECKIN_PROXY_URL', '').strip() or os.getenv('HTTPS_PROXY', '').strip()
	return server or None


def get_playwright_proxy() -> dict[str, str] | None:
	server = get_proxy_server()
	if not server:
		return None
	return {'server': server}


def apply_proxy_env() -> None:
	"""将 CHECKIN_PROXY_URL 同步到标准代理环境变量。"""
	server = os.getenv('CHECKIN_PROXY_URL', '').strip()
	if not server:
		return
	os.environ.setdefault('HTTP_PROXY', server)
	os.environ.setdefault('HTTPS_PROXY', server)
	os.environ.setdefault('http_proxy', server)
	os.environ.setdefault('https_proxy', server)
	no_proxy = os.getenv('NO_PROXY', '127.0.0.1,localhost')
	os.environ.setdefault('NO_PROXY', no_proxy)
	os.environ.setdefault('no_proxy', no_proxy)
