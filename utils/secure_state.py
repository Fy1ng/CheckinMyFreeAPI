"""Atomic private progress publication; no browser profile handling."""

import os
import tempfile
from pathlib import Path


def atomic_write(path: Path, data: bytes) -> None:
	path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
	descriptor, temporary_name = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
	temporary = Path(temporary_name)
	try:
		with os.fdopen(descriptor, 'wb') as stream:
			stream.write(data)
			stream.flush()
			os.fsync(stream.fileno())
		os.replace(temporary, path)
	finally:
		temporary.unlink(missing_ok=True)
