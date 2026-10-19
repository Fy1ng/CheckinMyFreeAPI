"""Read last-verified identity metadata without changing live authentication state."""

import base64
import copy
import hmac
import os
import shutil
import tempfile
import threading
from importlib.metadata import version
from pathlib import Path

from cloakbrowser.config import get_chromium_version

from utils.secure_state import MAX_FILES, MAX_SNAPSHOT_BYTES, SnapshotStore, StateError, state_key


class IdentityStateReader:
	def __init__(self, data_dir: Path, key: bytes):
		self.data_dir = data_dir
		self.secret = base64.urlsafe_b64encode(hmac.digest(key, b'checkin-server-login-state-v1', 'sha256')).decode()
		self._stamp: tuple | None = None
		self._state: dict = {}
		self._lock = threading.Lock()

	def read(self, config: dict) -> dict:
		with self._lock:
			return self._read(config)

	def _read(self, config: dict) -> dict:
		identities = config['identities']
		if not identities:
			return {}
		files = [self.data_dir / 'auth-cache' / name for name in ('auth-state.enc', 'auth-state.previous.enc')]
		compatibility = f'{os.name}:{version("cloakbrowser")}:{get_chromium_version()}'
		stamps: list[tuple[int, int, int] | None] = []
		for file in files:
			if file.is_symlink():
				raise StateError('Identity state cache cannot be a symbolic link')
			try:
				info = file.stat()
				stamps.append((info.st_mtime_ns, info.st_size, info.st_ino))
			except FileNotFoundError:
				stamps.append(None)
		stamp = (
			tuple(stamps),
			tuple(sorted((alias, item['type']) for alias, item in identities.items())),
			compatibility,
		)
		if stamp == self._stamp:
			return copy.deepcopy(self._state)
		result = {
			alias: {'state': 'unverified', 'username': None, 'user_id': None, 'verified_at': None}
			for alias in identities
		}
		if any(item is not None for item in stamps):
			# SnapshotStore removes a publication marker on construction. Work on a
			# private copy so this GET never changes cache bytes, markers or live profiles.
			with tempfile.TemporaryDirectory(prefix='identity-inspect-', dir=self.data_dir) as folder:
				root = Path(folder)
				cache = root / 'cache' / 'auth-state.enc'
				cache.parent.mkdir(mode=0o700)
				for source in files:
					if source.exists():
						if source.stat().st_size > MAX_SNAPSHOT_BYTES + MAX_FILES * 1024:
							raise StateError('Identity state snapshot exceeds size limit')
						shutil.copyfile(source, cache.parent / source.name)
				store = SnapshotStore(
					root / 'state', cache, self.secret, scope='checkin-server-v1', compatibility=compatibility
				)
				try:
					store.restore()
					for alias, identity in identities.items():
						metadata = (
							store.read_record('metadata', state_key(f'identity:{identity["type"]}:{alias}')) or {}
						)
						record = metadata.get('identity_login')
						if not isinstance(record, dict) or record.get('type') != identity['type']:
							continue
						if not all(
							isinstance(record.get(name), str) and record[name]
							for name in ('user_id', 'username', 'verified_at')
						):
							continue
						result[alias] = {
							'state': 'verified',
							**{name: record[name] for name in ('user_id', 'username', 'verified_at')},
						}
				finally:
					store.close()
		self._stamp, self._state = stamp, result
		return copy.deepcopy(result)
