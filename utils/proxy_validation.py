"""Shared, credential-free validation for optional SOCKS5 authentication."""

import re
from urllib.parse import SplitResult, unquote


def valid_socks5_credentials(parsed: SplitResult) -> bool:
	"""Accept no userinfo, or two RFC 1929 credentials encoded as UTF-8."""
	if parsed.username is None and parsed.password is None:
		return True
	if parsed.username is None or parsed.password is None:
		return False
	try:
		for value in (parsed.username, parsed.password):
			if re.search(r'%(?![0-9a-fA-F]{2})', value):
				return False
			decoded = unquote(value, encoding='utf-8', errors='strict')
			if not 1 <= len(decoded.encode('utf-8')) <= 255:
				return False
			if any(ord(char) < 32 or ord(char) == 127 for char in decoded):
				return False
	except UnicodeError:
		return False
	return True
