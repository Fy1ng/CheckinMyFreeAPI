"""Explicit HTTPS ingress policy; proxy headers are trusted only from named peers."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from urllib.parse import urlsplit

from aiohttp import web


def _ip(value: str) -> str:
	address = ipaddress.ip_address(value)
	if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
		return str(address.ipv4_mapped)
	return str(address)


class WebAccess:
	def __init__(self, public_origin: str = '', trusted_proxy_ips: Iterable[str] = ()):
		self.public_origin = ''
		self.public_authority = ''
		if public_origin:
			try:
				parsed = urlsplit(public_origin)
				if (
					parsed.scheme != 'https'
					or not parsed.hostname
					or parsed.username is not None
					or parsed.password is not None
					or parsed.path
					or parsed.query
					or parsed.fragment
					or any(ord(char) <= 32 or ord(char) >= 127 or char == '\\' for char in public_origin)
				):
					raise ValueError
				authority = self._authority(parsed.netloc, default_port=443)
				if parsed.hostname.lower() in {'localhost', '127.0.0.1', '::1'}:
					raise ValueError
				self.public_authority = authority
				self.public_origin = 'https://' + authority
			except ValueError:
				raise ValueError(
					'CHECKIN_WEB_PUBLIC_URL must be an HTTPS origin without a path, query or credentials'
				) from None
		try:
			peers = list(trusted_proxy_ips)
			if len(peers) > 32 or any(not isinstance(peer, str) or not peer for peer in peers):
				raise ValueError
			self.trusted_proxy_ips = frozenset(_ip(peer) for peer in peers)
		except (ValueError, TypeError):
			raise ValueError('CHECKIN_WEB_TRUSTED_PROXY_IPS must contain at most 32 individual IP addresses') from None

	@staticmethod
	def _authority(value: str, *, default_port: int | None = None) -> str:
		if not value or any(ord(char) <= 32 or ord(char) >= 127 or char == '\\' for char in value):
			raise ValueError
		parsed = urlsplit('http://' + value)
		if (
			not parsed.hostname
			or parsed.netloc != value
			or parsed.username is not None
			or parsed.password is not None
			or parsed.path
			or parsed.query
			or parsed.fragment
			or parsed.port == 0
			or value.endswith(':')
		):
			raise ValueError
		host = parsed.hostname.lower()
		if ':' in host:
			ipaddress.IPv6Address(host)
			host = '[' + host + ']'
		elif any(not (char.isalnum() or char in '.-') for char in host):
			raise ValueError
		return host + (f':{parsed.port}' if parsed.port is not None and parsed.port != default_port else '')

	def trusted_peer(self, request: web.Request) -> bool:
		try:
			return _ip(request.remote or '') in self.trusted_proxy_ips
		except ValueError:
			return False

	def origin(self, request: web.Request) -> str:
		try:
			authority = self._authority(request.host)
			if self.public_origin and self._authority(request.host, default_port=443) == self.public_authority:
				if not request.secure and not (
					self.trusted_peer(request) and request.headers.get('X-Forwarded-Proto') == 'https'
				):
					raise web.HTTPForbidden(text='公网访问需要通过受信任的 HTTPS 入口')
				return self.public_origin
			if urlsplit('http://' + authority).hostname in {'127.0.0.1', 'localhost', '::1'}:
				return f'{request.scheme}://{request.host}'
		except ValueError:
			pass
		raise web.HTTPForbidden(text='请求域名未获允许')

	def client_ip(self, request: web.Request) -> str:
		if self.trusted_peer(request):
			try:
				# Caddy must replace this header, not append to an untrusted chain.
				return _ip(request.headers.get('X-Forwarded-For', ''))
			except ValueError:
				pass
		try:
			return _ip(request.remote or '')
		except ValueError:
			return 'unknown'
