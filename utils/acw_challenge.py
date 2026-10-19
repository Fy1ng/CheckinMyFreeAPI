"""Statically decode the known AnyRouter acw challenge, without running JavaScript.

The permutation/XOR calculation is adapted from Metapi's MIT-licensed
``newApiShield.ts``. Unlike its VM-based decoder, this implementation only
accepts the complete known challenge template and decodes its string table
with Python's base64 decoder. Unknown templates deliberately fail closed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

_MAX_HTML_LENGTH = 16_384
_MAX_TABLE_ENTRIES = 64
_MAX_ENCODED_STRING_LENGTH = 256
_HEX40 = re.compile(r'[0-9a-fA-F]{40}')
_ARG1 = re.compile(r"var\s+arg1\s*=\s*(['\"])([0-9a-fA-F]+)\1;")
_MAPPING = re.compile(r'for\(var m=\[([^\]]+)\],p=L\(0x115\)')
_TABLE = re.compile(r'function a0i\(\)\{var N=\[([^\]]+)\];')
_TABLE_ITEM = re.compile(r"'([a-zA-Z0-9+/]+)'")
_NUMBER = re.compile(r'(?:0[xX][0-9a-fA-F]+|[0-9]+)')
_ENVELOPE = re.compile(r'\s*<html>\s*<script>\s*(.*?)\s*</script>\s*</html>\s*', re.DOTALL)
_BASE64_TRANSLATION = str.maketrans(
	'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/',
	'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
)
# Fingerprint of the complete known script with only arg1, permutation and the
# unique encoded XOR seed replaced by placeholders. In particular, the HTML,
# cookie write/reload logic, helper functions and all other strings are fixed.
# A challenge is never accepted just because it happens to contain acw markers.
_KNOWN_TEMPLATE_SHA256 = 'ffee4ea88fa2701ab12030014c7687d83464c40a6b31c42ce1ca78a0109713f4'


def is_acw_challenge(html: str) -> bool:
	"""Recognize bounded acw-like HTML; this alone does not authorize a retry."""
	return len(html) <= _MAX_HTML_LENGTH and 'acw_sc__v2' in html and re.search(r'\bvar\s+arg1\s*=', html) is not None


def _decode_table(body: str) -> tuple[str, str] | None:
	"""Return the unique hex seed and its encoded literal, within fixed budgets."""
	items = body.split(',')
	if not 1 <= len(items) <= _MAX_TABLE_ENTRIES:
		return None
	seeds: list[tuple[str, str]] = []
	for item in items:
		match = _TABLE_ITEM.fullmatch(item)
		if not match:
			return None
		encoded = match[1]
		if len(encoded) > _MAX_ENCODED_STRING_LENGTH:
			return None
		try:
			decoded = base64.b64decode(
				encoded.translate(_BASE64_TRANSLATION) + '=' * (-len(encoded) % 4), validate=True
			).decode('ascii')
		except (binascii.Error, UnicodeDecodeError):
			return None
		if _HEX40.fullmatch(decoded):
			seeds.append((decoded, item))
	return seeds[0] if len(seeds) == 1 else None


def solve_acw_sc_v2(html: str) -> str | None:
	"""Solve only the complete supported template, or return None without I/O.

	The accepted family allows different 40-character arg1 values, valid 40-item
	permutations and XOR seeds. Extra scripts, business HTML, malformed/ambiguous
	tables, changed decoder code and oversized input are unsupported. No script,
	including the known challenge's anti-debugging helpers, is ever executed.
	"""
	if not is_acw_challenge(html):
		return None
	envelope = _ENVELOPE.fullmatch(html)
	if not envelope:
		return None
	script = envelope[1]
	arguments = list(_ARG1.finditer(script))
	mappings = list(_MAPPING.finditer(script))
	tables = list(_TABLE.finditer(script))
	if len(arguments) != 1 or len(mappings) != 1 or len(tables) != 1:
		return None
	argument, mapping, table = arguments[0], mappings[0], tables[0]
	arg1 = argument[2]
	if not _HEX40.fullmatch(arg1):
		return None
	values = mapping[1].split(',')
	if len(values) != 40 or any(not _NUMBER.fullmatch(value.strip()) for value in values):
		return None
	# Cap the token length before int() as well as the overall page length.
	if any(len(value.strip()) > 4 for value in values):
		return None
	permutation = [int(value, 16) if value.strip().lower().startswith('0x') else int(value) for value in values]
	if sorted(permutation) != list(range(1, 41)):
		return None
	decoded = _decode_table(table[1])
	if decoded is None:
		return None
	seed, seed_literal = decoded
	# Normalize spans from right to left so replacing one cannot shift another.
	seed_offset = table.start(1) + table[1].index(seed_literal)
	replacements = [
		(argument.start(), argument.end(), "var arg1='<ARG1>';"),
		(mapping.start(1), mapping.end(1), '<MAPPING>'),
		(seed_offset, seed_offset + len(seed_literal), "'<XOR_SEED>'"),
	]
	normalized = script
	for start, end, replacement in sorted(replacements, reverse=True):
		normalized = normalized[:start] + replacement + normalized[end:]
	try:
		fingerprint = hashlib.sha256(normalized.encode('ascii')).hexdigest()
	except UnicodeEncodeError:
		return None
	if fingerprint != _KNOWN_TEMPLATE_SHA256:
		return None
	source = bytes.fromhex(''.join(arg1[index - 1] for index in permutation))
	return bytes(left ^ right for left, right in zip(source, bytes.fromhex(seed), strict=True)).hex()
