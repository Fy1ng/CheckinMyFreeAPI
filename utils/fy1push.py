"""Fy1Push request limits and configuration checks shared by CLI and WebUI."""

from urllib.parse import urlsplit, urlunsplit


def fy1push_endpoint(server: str) -> str:
	try:
		parsed = urlsplit(server.strip())
		if (
			parsed.scheme not in {'https', 'http'}
			or not parsed.hostname
			or parsed.username is not None
			or parsed.password is not None
			or parsed.query
			or parsed.fragment
			or parsed.path.rstrip('/') not in {'', '/v1/push'}
			or '\\' in server
			or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in server.strip())
			or parsed.port == 0
			or parsed.netloc.endswith(':')
		):
			raise ValueError
		if parsed.scheme == 'http' and parsed.hostname not in {'localhost', '127.0.0.1', '::1'}:
			raise ValueError
		return urlunsplit((parsed.scheme, parsed.netloc, '/v1/push', '', ''))
	except ValueError:
		raise ValueError(
			'Fy1Push 服务地址须为 HTTPS 根地址或 /v1/push, HTTP 仅允许本机地址, 不可包含凭据或查询参数'
		) from None


def fy1push_channel(channel: str) -> str:
	value = channel or '签到'
	if not 1 <= len(value) <= 24 or not all(char.isalnum() or char in '-_.' for char in value):
		raise ValueError('Fy1Push 分组须为 1 到 24 个字母, 数字或 -_.')
	return value


def validate_fy1push_token(token: str) -> None:
	if token and (not token.isascii() or any(not 33 <= ord(char) <= 126 for char in token)):
		raise ValueError('Fy1Push 发送 token 不可包含空白, 控制字符或非 ASCII 字符')


def fy1push_summary(text: str, limit: int) -> str:
	if not text.strip() or any(
		0xD800 <= ord(char) <= 0xDFFF or (ord(char) < 32 and char not in '\n\r\t') for char in text
	):
		raise ValueError('Fy1Push 标题和正文不可为空白或包含不可显示字符')
	return text if len(text) <= limit else text[: limit - 3] + '...'
