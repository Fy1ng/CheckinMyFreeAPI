import os
from importlib.metadata import version

import pytest
from cloakbrowser.config import get_chromium_version

from utils import browser_backend
from utils.browser_backend import (
	browser_compatibility,
	browser_storage_paths,
	get_browser_engine,
	system_chrome_details,
)
from utils.oauth import AuthError


def test_browser_engine_defaults_to_cloak_and_validates(monkeypatch):
	monkeypatch.delenv('CHECKIN_BROWSER_ENGINE', raising=False)
	assert get_browser_engine() == 'cloakbrowser'
	monkeypatch.setenv('CHECKIN_BROWSER_ENGINE', ' CHROME ')
	assert get_browser_engine() == 'chrome'
	monkeypatch.setenv('CHECKIN_BROWSER_ENGINE', 'custom-executable')
	with pytest.raises(AuthError, match='^INVALID_BROWSER_ENGINE$'):
		get_browser_engine()


def test_browser_storage_namespaces_do_not_share_snapshots(tmp_path):
	root = tmp_path / 'state'
	cache_file = tmp_path / 'cache' / 'state.enc'
	assert browser_storage_paths(root, cache_file, 'cloakbrowser') == (root, cache_file)
	assert browser_storage_paths(root, cache_file, 'chrome') == (
		root / 'chrome',
		cache_file.parent / 'chrome' / cache_file.name,
	)
	with pytest.raises(AuthError, match='^INVALID_BROWSER_ENGINE$'):
		browser_storage_paths(root, cache_file, 'other')


def test_cloak_compatibility_remains_exactly_backward_compatible():
	assert browser_compatibility('cloakbrowser') == f'{os.name}:{version("cloakbrowser")}:{get_chromium_version()}'


def test_chrome_compatibility_records_actual_full_version(monkeypatch, tmp_path):
	monkeypatch.setattr(browser_backend, 'system_chrome_details', lambda: (tmp_path / 'chrome.exe', '155.0.8123.7'))
	assert browser_compatibility('chrome') == f'{os.name}:chrome:155.0.8123.7'
	with pytest.raises(AuthError, match='^INVALID_BROWSER_ENGINE$'):
		browser_compatibility('other')


def test_chrome_is_windows_only(monkeypatch):
	monkeypatch.setattr(browser_backend.sys, 'platform', 'linux')
	with pytest.raises(AuthError, match='^SYSTEM_CHROME_WINDOWS_ONLY$'):
		system_chrome_details()


def test_chrome_candidates_are_only_standard_installs(monkeypatch, tmp_path):
	monkeypatch.setenv('PROGRAMFILES', str(tmp_path / 'program-files'))
	monkeypatch.setenv('PROGRAMFILES(X86)', str(tmp_path / 'program-files-x86'))
	monkeypatch.setenv('LOCALAPPDATA', str(tmp_path / 'local'))
	monkeypatch.setenv('CHECKIN_CHROME_EXECUTABLE', str(tmp_path / 'arbitrary.exe'))
	assert browser_backend._windows_chrome_candidates() == [
		tmp_path / root / 'Google' / 'Chrome' / 'Application' / 'chrome.exe'
		for root in ('program-files', 'program-files-x86', 'local')
	]


def test_chrome_missing_has_no_download_or_fallback(monkeypatch, tmp_path):
	monkeypatch.setattr(browser_backend.sys, 'platform', 'win32')
	monkeypatch.setattr(browser_backend, '_windows_chrome_candidates', lambda: [tmp_path / 'absent.exe'])
	with pytest.raises(AuthError, match='^SYSTEM_CHROME_NOT_INSTALLED$'):
		system_chrome_details()


def test_chrome_discovery_reads_the_selected_executable_version(monkeypatch, tmp_path):
	executable = tmp_path / 'chrome.exe'
	executable.touch()
	read_paths = []

	def read_version(path):
		read_paths.append(path)
		return '155.0.8123.7'

	monkeypatch.setattr(browser_backend.sys, 'platform', 'win32')
	monkeypatch.setattr(browser_backend, '_windows_chrome_candidates', lambda: [tmp_path / 'missing.exe', executable])
	monkeypatch.setattr(browser_backend, '_windows_product_version', read_version)
	assert system_chrome_details() == (executable.resolve(), '155.0.8123.7')
	assert read_paths == [executable.resolve()]


def test_chrome_unreadable_version_cannot_reuse_other_install(monkeypatch, tmp_path):
	executable = tmp_path / 'chrome.exe'
	executable.touch()
	monkeypatch.setattr(browser_backend.sys, 'platform', 'win32')
	monkeypatch.setattr(browser_backend, '_windows_chrome_candidates', lambda: [executable])
	monkeypatch.setattr(browser_backend, '_windows_product_version', lambda _: None)
	with pytest.raises(AuthError, match='^SYSTEM_CHROME_VERSION_UNAVAILABLE$'):
		system_chrome_details()


@pytest.mark.skipif(os.name != 'nt', reason='Requires Windows native file version API')
def test_windows_file_version_reader_rejects_unversioned_file(tmp_path):
	executable = tmp_path / 'not-a-real-chrome.exe'
	executable.write_bytes(b'not a Windows executable')
	assert browser_backend._windows_product_version(executable) is None
