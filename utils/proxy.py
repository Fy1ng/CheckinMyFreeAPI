"""Explicit network policy shared by HTTP, WAF, OAuth and interactive browsers."""

from __future__ import annotations

import os
from urllib.parse import unquote, urlsplit, urlunsplit


def resolve_proxy(value: str | None, *, use_proxy: bool = False) -> str | None:
	if value == 'direct':
		return None
	if value is None and not use_proxy:
		return None
	server = os.getenv('CHECKIN_PROXY_URL', '').strip() if value is None or value == 'default' else value.strip()
	if not server:
		raise ValueError('Proxy is required but CHECKIN_PROXY_URL is not configured')
	try:
		parsed = urlsplit(server)
		valid = parsed.scheme in {'http', 'https', 'socks5'} and parsed.hostname and parsed.port
		if not valid or parsed.query or parsed.fragment or parsed.path not in {'', '/'}:
			raise ValueError
		if parsed.scheme == 'socks5' and (parsed.username is not None or parsed.password is not None):
			raise ValueError
	except ValueError:
		raise ValueError('Invalid proxy configuration; use an HTTP(S) proxy or unauthenticated SOCKS5 proxy') from None
	return server


def get_proxy_server(*, use_proxy: bool = True) -> str | None:
	return resolve_proxy(None, use_proxy=use_proxy)


def playwright_proxy(server: str | None) -> dict[str, str] | None:
	if not server:
		return None
	parsed = urlsplit(server)
	host = parsed.hostname or ''
	if ':' in host:
		host = f'[{host}]'
	result = {'server': urlunsplit((parsed.scheme, f'{host}:{parsed.port}', '', '', ''))}
	if parsed.username is not None:
		result['username'] = unquote(parsed.username)
	if parsed.password is not None:
		result['password'] = unquote(parsed.password)
	return result


def get_playwright_proxy(*, use_proxy: bool = True) -> dict[str, str] | None:
	return playwright_proxy(get_proxy_server(use_proxy=use_proxy))
