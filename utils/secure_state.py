"""Authenticated, bounded snapshots of validated browser profiles and site sessions."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b'ANYROUTER-AUTH-1\x00'
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_FILES = 20_000
EXCLUDED = frozenset(
	{
		'Cache',
		'Code Cache',
		'GPUCache',
		'ShaderCache',
		'GrShaderCache',
		'DawnCache',
		'Crashpad',
		'Crash Reports',
		'BrowserMetrics',
		'SingletonLock',
		'SingletonSocket',
		'SingletonCookie',
		'DevToolsActivePort',
		'LOCK',
		'lockfile',
		'History',
		'History-journal',
		'Sessions',
		'Current Session',
		'Current Tabs',
		'Last Session',
		'Last Tabs',
	}
)


class StateError(RuntimeError):
	pass


def state_key(value: str) -> str:
	return hashlib.sha256(value.encode()).hexdigest()


def remove_owned_tree(path: Path, owner: Path) -> None:
	resolved_owner = owner.resolve()
	resolved_path = path.resolve()
	if path.is_symlink() or resolved_path == resolved_owner or not resolved_path.is_relative_to(resolved_owner):
		raise StateError('Refusing to remove a path outside the state directory')
	if path.exists():
		shutil.rmtree(path)


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


def _checked_key(key: str) -> str:
	if not re.fullmatch('[a-f0-9]{64}', key):
		raise StateError('Invalid state identifier')
	return key


def replace_owned_tree(staging: Path, destination: Path, owner: Path) -> None:
	backup = Path(tempfile.mkdtemp(prefix='previous-', dir=owner))
	backup.rmdir()
	try:
		if destination.exists():
			destination.replace(backup)
		try:
			staging.replace(destination)
		except BaseException:
			if backup.exists():
				backup.replace(destination)
			raise
	finally:
		remove_owned_tree(backup, owner)


def _profile_ignore(directory: str, names: list[str]) -> list[str]:
	return [name for name in names if name in EXCLUDED or (Path(directory) / name).is_symlink()]


class SnapshotStore:
	def __init__(self, root: Path, cache_file: Path, secret: str, *, scope: str, compatibility: str):
		if root.is_symlink() or cache_file.is_symlink() or cache_file.parent.is_symlink():
			raise StateError('State roots cannot be symbolic links')
		try:
			key = base64.b64decode(secret.encode('ascii'), altchars=b'-_', validate=True)
			if len(key) != 32:
				raise ValueError
		except (ValueError, UnicodeError):
			raise StateError('CHECKIN_STATE_KEY must be a base64-encoded random 32-byte key') from None
		self._cipher = AESGCM(key)
		self.root = root.resolve()
		self.cache_file = cache_file.resolve()
		self.previous_file = self.cache_file.with_suffix('.previous.enc')
		self.saved = self.root / 'saved'
		self.live = self.root / 'live'
		self.aad = MAGIC + scope.encode('utf-8')
		self.compatibility = compatibility
		self.dirty = False
		self._valid_ciphertext: bytes | None = None
		(self.cache_file.parent / 'ready').unlink(missing_ok=True)
		for directory in (self.saved, self.live):
			if directory.is_symlink():
				raise StateError('State directories cannot be symbolic links')
			directory.mkdir(parents=True, exist_ok=True, mode=0o700)

	def restore(self) -> str:
		found = False
		for candidate in (self.cache_file, self.previous_file):
			if not candidate.exists():
				continue
			found = True
			try:
				if candidate.stat().st_size > MAX_SNAPSHOT_BYTES + MAX_FILES * 1024:
					raise StateError('Snapshot exceeds size limit')
				ciphertext = candidate.read_bytes()
				if not ciphertext.startswith(MAGIC) or len(ciphertext) < len(MAGIC) + 28:
					raise StateError('Invalid snapshot envelope')
				nonce = ciphertext[len(MAGIC) : len(MAGIC) + 12]
				plaintext = self._cipher.decrypt(nonce, ciphertext[len(MAGIC) + 12 :], self.aad)
				self._restore_archive(plaintext)
				self._valid_ciphertext = ciphertext
				return 'restored' if candidate == self.cache_file else 'previous'
			except (InvalidTag, StateError, OSError, ValueError, zipfile.BadZipFile):
				continue
		if found:
			raise StateError('No valid compatible encrypted snapshot; refusing to overwrite existing state')
		return 'missing'

	def _restore_archive(self, plaintext: bytes) -> None:
		with zipfile.ZipFile(io.BytesIO(plaintext)) as archive:
			entries = archive.infolist()
			if len(entries) > MAX_FILES or sum(entry.file_size for entry in entries) > MAX_SNAPSHOT_BYTES:
				raise StateError('Snapshot exceeds extraction limits')
			seen = set()
			for entry in entries:
				path = PurePosixPath(entry.filename)
				if (
					not path.parts
					or path.is_absolute()
					or '..' in path.parts
					or '\\' in entry.filename
					or ':' in entry.filename
					or '\x00' in entry.filename
					or entry.filename in seen
					or entry.file_size > MAX_FILE_BYTES
					or stat.S_ISLNK(entry.external_attr >> 16)
					or path.parts[0] not in {'manifest.json', 'profiles', 'accounts', 'metadata'}
				):
					raise StateError('Snapshot contains an unsafe entry')
				seen.add(entry.filename)
			if 'manifest.json' not in seen:
				raise StateError('Missing snapshot manifest')
			manifest = json.loads(archive.read('manifest.json'))
			if manifest != {'schema': 1, 'compatibility': self.compatibility}:
				raise StateError('Snapshot compatibility mismatch')
			staging = Path(tempfile.mkdtemp(prefix='restore-', dir=self.root))
			try:
				for entry in entries:
					if entry.filename == 'manifest.json' or entry.is_dir():
						continue
					destination = staging.joinpath(*PurePosixPath(entry.filename).parts)
					atomic_write(destination, archive.read(entry))
				replace_owned_tree(staging, self.saved, self.root)
			finally:
				remove_owned_tree(staging, self.root)

	def prepare_profile(self, key: str) -> Path:
		key = _checked_key(key)
		destination = self.live / key
		remove_owned_tree(destination, self.root)
		source = self.saved / 'profiles' / key
		if source.exists():
			shutil.copytree(source, destination, ignore=_profile_ignore)
		else:
			destination.mkdir(mode=0o700)
		return destination

	def commit_profile(self, key: str, profile: Path) -> None:
		key = _checked_key(key)
		if profile.resolve() != (self.live / key).resolve():
			raise StateError('Only owned browser profiles can be committed')
		staging = Path(tempfile.mkdtemp(prefix='profile-', dir=self.root))
		try:
			shutil.copytree(profile, staging, dirs_exist_ok=True, ignore=_profile_ignore)
			destination = self.saved / 'profiles' / key
			destination.parent.mkdir(exist_ok=True, mode=0o700)
			replace_owned_tree(staging, destination, self.root)
			self.dirty = True
		finally:
			remove_owned_tree(staging, self.root)

	def read_record(self, category: str, key: str) -> dict | None:
		path = self._record_path(category, key)
		if not path.exists():
			return None
		try:
			payload = json.loads(path.read_text(encoding='utf-8'))
		except (ValueError, OSError):
			raise StateError('Invalid authenticated state record') from None
		if not isinstance(payload, dict):
			raise StateError('Invalid authenticated state record')
		return payload

	def write_record(self, category: str, key: str, payload: dict) -> None:
		atomic_write(self._record_path(category, key), json.dumps(payload, separators=(',', ':')).encode())
		self.dirty = True

	def _record_path(self, category: str, key: str) -> Path:
		if category not in {'accounts', 'metadata'}:
			raise StateError('Invalid record category')
		return self.saved / category / f'{_checked_key(key)}.json'

	def save(self) -> bool:
		if not self.dirty:
			return False
		buffer = io.BytesIO()
		total_size = 0
		file_count = 0
		with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
			archive.writestr('manifest.json', json.dumps({'schema': 1, 'compatibility': self.compatibility}))
			for path in sorted(self.saved.rglob('*')):
				if path.is_symlink() or not path.is_file():
					continue
				if not path.resolve().is_relative_to(self.saved.resolve()):
					raise StateError('State file escapes the snapshot directory')
				file_size = path.stat().st_size
				total_size += file_size
				file_count += 1
				if file_size > MAX_FILE_BYTES or total_size > MAX_SNAPSHOT_BYTES or file_count > MAX_FILES - 1:
					raise StateError('State exceeds snapshot limits')
				archive.write(path, path.relative_to(self.saved).as_posix())
		nonce = os.urandom(12)
		ciphertext = MAGIC + nonce + self._cipher.encrypt(nonce, buffer.getvalue(), self.aad)
		if self._valid_ciphertext is not None:
			atomic_write(self.previous_file, self._valid_ciphertext)
		atomic_write(self.cache_file, ciphertext)
		atomic_write(self.cache_file.parent / 'ready', b'validated\n')
		self._valid_ciphertext = ciphertext
		self.dirty = False
		return True

	def close(self) -> None:
		for directory in (self.live, self.saved):
			remove_owned_tree(directory, self.root)
