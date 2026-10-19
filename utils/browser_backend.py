"""Browser selection, installed Chrome discovery and snapshot compatibility."""

from __future__ import annotations

import ctypes
import os
import sys
from importlib.metadata import version
from pathlib import Path

from utils.oauth import AuthError

BROWSER_ENGINES = frozenset({'cloakbrowser', 'chrome'})


def get_browser_engine() -> str:
	engine = os.getenv('CHECKIN_BROWSER_ENGINE', 'cloakbrowser').strip().lower()
	if engine not in BROWSER_ENGINES:
		raise AuthError('INVALID_BROWSER_ENGINE')
	return engine


def browser_storage_paths(root: Path, cache_file: Path, engine: str) -> tuple[Path, Path]:
	if engine == 'cloakbrowser':
		return root, cache_file
	if engine == 'chrome':
		return root / 'chrome', cache_file.parent / 'chrome' / cache_file.name
	raise AuthError('INVALID_BROWSER_ENGINE')


def _windows_chrome_candidates() -> list[Path]:
	roots = [
		Path(os.getenv('PROGRAMFILES', r'C:\Program Files')),
		Path(os.getenv('PROGRAMFILES(X86)', r'C:\Program Files (x86)')),
	]
	if local_app_data := os.getenv('LOCALAPPDATA'):
		roots.append(Path(local_app_data))
	return [root / 'Google' / 'Chrome' / 'Application' / 'chrome.exe' for root in roots]


def _windows_product_version(executable: Path) -> str | None:
	"""Read the version from the exact executable that Playwright will launch."""
	from ctypes import wintypes

	class FixedFileInfo(ctypes.Structure):
		_fields_ = [
			('signature', wintypes.DWORD),
			('struct_version', wintypes.DWORD),
			('file_version_ms', wintypes.DWORD),
			('file_version_ls', wintypes.DWORD),
			('product_version_ms', wintypes.DWORD),
			('product_version_ls', wintypes.DWORD),
			('file_flags_mask', wintypes.DWORD),
			('file_flags', wintypes.DWORD),
			('file_os', wintypes.DWORD),
			('file_type', wintypes.DWORD),
			('file_subtype', wintypes.DWORD),
			('file_date_ms', wintypes.DWORD),
			('file_date_ls', wintypes.DWORD),
		]

	try:
		library = ctypes.WinDLL('version', use_last_error=True)
		library.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
		library.GetFileVersionInfoSizeW.restype = wintypes.DWORD
		library.GetFileVersionInfoW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID]
		library.GetFileVersionInfoW.restype = wintypes.BOOL
		library.VerQueryValueW.argtypes = [
			wintypes.LPCVOID,
			wintypes.LPCWSTR,
			ctypes.POINTER(ctypes.c_void_p),
			ctypes.POINTER(wintypes.UINT),
		]
		library.VerQueryValueW.restype = wintypes.BOOL
		ignored = wintypes.DWORD()
		size = library.GetFileVersionInfoSizeW(str(executable), ctypes.byref(ignored))
		if not size:
			return None
		buffer = ctypes.create_string_buffer(size)
		if not library.GetFileVersionInfoW(str(executable), 0, size, buffer):
			return None
		pointer = ctypes.c_void_p()
		length = wintypes.UINT()
		if not library.VerQueryValueW(buffer, '\\', ctypes.byref(pointer), ctypes.byref(length)):
			return None
		if not pointer.value or length.value < ctypes.sizeof(FixedFileInfo):
			return None
		info = ctypes.cast(pointer, ctypes.POINTER(FixedFileInfo)).contents
		if info.signature != 0xFEEF04BD:
			return None
		parts = (
			info.product_version_ms >> 16,
			info.product_version_ms & 0xFFFF,
			info.product_version_ls >> 16,
			info.product_version_ls & 0xFFFF,
		)
		return '.'.join(str(part) for part in parts) if any(parts) else None
	except (AttributeError, OSError, ValueError):
		return None


def system_chrome_details() -> tuple[Path, str]:
	if sys.platform != 'win32':
		raise AuthError('SYSTEM_CHROME_WINDOWS_ONLY')
	for candidate in _windows_chrome_candidates():
		if not candidate.is_file():
			continue
		executable = candidate.resolve()
		product_version = _windows_product_version(executable)
		if product_version is None:
			raise AuthError('SYSTEM_CHROME_VERSION_UNAVAILABLE')
		return executable, product_version
	raise AuthError('SYSTEM_CHROME_NOT_INSTALLED')


def browser_compatibility(engine: str) -> str:
	if engine == 'cloakbrowser':
		from cloakbrowser.config import get_chromium_version

		return f'{os.name}:{version("cloakbrowser")}:{get_chromium_version()}'
	if engine == 'chrome':
		_, product_version = system_chrome_details()
		return f'{os.name}:chrome:{product_version}'
	raise AuthError('INVALID_BROWSER_ENGINE')
