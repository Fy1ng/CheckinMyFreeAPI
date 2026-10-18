"""Defense-in-depth redaction; callers must still avoid logging authentication data."""

from __future__ import annotations

import json
import os
import re
import sys
from urllib.parse import unquote

SENSITIVE_NAME = re.compile(r'password|passwd|secret|token|cookie|session|otp|webhook|proxy|state_key|email_pass', re.I)


def sensitive_values() -> set[str]:
	values: set[str] = set()

	def visit(payload, sensitive: bool = False) -> None:
		if isinstance(payload, dict):
			for name, item in payload.items():
				visit(item, sensitive or bool(SENSITIVE_NAME.search(str(name))))
		elif isinstance(payload, list):
			for item in payload:
				visit(item, sensitive)
		elif sensitive and isinstance(payload, str) and payload:
			values.add(payload)
			values.add(unquote(payload))

	for name, value in os.environ.items():
		if SENSITIVE_NAME.search(name) and value:
			values.add(value)
		if name in {'ANYROUTER_ACCOUNTS', 'CHECKIN_IDENTITIES', 'PROVIDERS'}:
			try:
				visit(json.loads(value))
			except ValueError:
				values.add(value)
	return values


def redact(text: str, values: set[str]) -> str:
	for value in sorted(values, key=len, reverse=True):
		if value:
			text = text.replace(value, '[REDACTED]')
	text = re.sub(r'(https?://)[^/\s@]+@', r'\1[REDACTED]@', text)
	return re.sub(r'([?&](?:code|state|token|access_token|password|otp)=)[^&\s]+', r'\1[REDACTED]', text, flags=re.I)


class RedactingStream:
	def __init__(self, stream, values: set[str]):
		self.stream = stream
		self.values = values
		self.pending = ''

	def write(self, text: str) -> int:
		self.pending += text
		while '\n' in self.pending:
			line, self.pending = self.pending.split('\n', 1)
			self.stream.write(redact(line, self.values) + '\n')
		return len(text)

	def flush(self) -> None:
		if self.pending:
			self.stream.write(redact(self.pending, self.values))
			self.pending = ''
		self.stream.flush()

	def __getattr__(self, name):
		return getattr(self.stream, name)


def install_redaction() -> None:
	values = sensitive_values()
	sys.stdout = RedactingStream(sys.stdout, values)
	sys.stderr = RedactingStream(sys.stderr, values)
