import sys
from dataclasses import replace
from types import SimpleNamespace
from typing import cast

import pytest

from utils import browser
from utils.browser import launch_login_context, load_browser_login_settings
from utils.oauth import AuthError


def test_browser_login_settings_records_profile_persistence(monkeypatch, tmp_path):
	monkeypatch.setenv('CHECKIN_BROWSER_PROFILE_DIR', str(tmp_path))

	settings = load_browser_login_settings('Account 1', 'agentrouter', persist_profile=False)

	assert settings.persist_profile is False
	assert settings.profile_dir == tmp_path / 'agentrouter' / 'Account 1'


@pytest.mark.asyncio
async def test_launch_login_context_uses_persistent_context_when_enabled(monkeypatch, tmp_path):
	calls = {}
	context = SimpleNamespace()

	async def fake_launch_persistent_context_async(profile_dir, **kwargs):
		calls['profile_dir'] = profile_dir
		calls['kwargs'] = kwargs
		return context

	monkeypatch.setitem(
		sys.modules,
		'cloakbrowser',
		SimpleNamespace(launch_persistent_context_async=fake_launch_persistent_context_async),
	)

	settings = load_browser_login_settings('Account 1', 'anyrouter', persist_profile=True)
	settings = settings.__class__(
		headless=settings.headless,
		humanize=False,
		wait_timeout_ms=settings.wait_timeout_ms,
		profile_dir=tmp_path / 'profiles' / 'anyrouter' / 'Account 1',
		cloakbrowser_binary_path=settings.cloakbrowser_binary_path,
		persist_profile=settings.persist_profile,
	)

	result = await launch_login_context(settings)

	assert cast(object, result) is context
	assert calls['profile_dir'] == str(settings.profile_dir)


@pytest.mark.asyncio
async def test_launch_login_context_closes_browser_for_ephemeral_context(monkeypatch, tmp_path):
	class FakeContext:
		def __init__(self):
			self.closed = False

		async def close(self):
			self.closed = True

	class FakeBrowser:
		def __init__(self):
			self.context = FakeContext()
			self.closed = False
			self.context_kwargs = {}
			self.launch_kwargs = {}

		async def new_context(self, **kwargs):
			self.context_kwargs = kwargs
			return self.context

		async def close(self):
			self.closed = True

	browser = FakeBrowser()

	async def fake_launch_async(**kwargs):
		browser.launch_kwargs = kwargs
		return browser

	monkeypatch.setitem(
		sys.modules,
		'cloakbrowser',
		SimpleNamespace(launch_async=fake_launch_async),
	)

	settings = load_browser_login_settings('Account 1', 'agentrouter', persist_profile=False)
	settings = settings.__class__(
		headless=settings.headless,
		humanize=False,
		wait_timeout_ms=settings.wait_timeout_ms,
		profile_dir=tmp_path / 'profiles' / 'agentrouter' / 'Account 1',
		cloakbrowser_binary_path=settings.cloakbrowser_binary_path,
		persist_profile=settings.persist_profile,
	)

	context = await launch_login_context(settings)
	await context.close()

	assert browser.context.closed is True
	assert browser.closed is True
	assert not settings.profile_dir.exists()


def test_chrome_settings_use_separate_application_profile(monkeypatch, tmp_path):
	monkeypatch.setenv('CHECKIN_BROWSER_PROFILE_DIR', str(tmp_path / 'profiles'))
	monkeypatch.setenv('CHECKIN_BROWSER_ENGINE', 'chrome')
	settings = load_browser_login_settings('identity-1', 'linuxdo')
	assert settings.engine == 'chrome'
	assert settings.profile_dir == tmp_path / 'profiles' / 'chrome' / 'linuxdo' / 'identity-1'


class FakeChromeDriver:
	def __init__(self):
		self.calls = {}
		self.stopped = 0
		self.context_closed = 0
		self.browser_closed = 0
		self.failure = None
		self.chromium = self
		self.browser = SimpleNamespace(new_context=self.new_context, close=self.close_browser)
		self.context = SimpleNamespace(browser=self.browser, close=self.close_context, pages=['application-page'])

	async def start(self):
		return self

	async def stop(self):
		self.stopped += 1

	async def launch_persistent_context(self, profile_dir, **kwargs):
		self.calls['profile_dir'] = profile_dir
		self.calls['persistent_kwargs'] = kwargs
		if self.failure == 'launch':
			raise RuntimeError('Chrome launch failed')
		return self.context

	async def launch(self, **kwargs):
		self.calls['launch_kwargs'] = kwargs
		if self.failure == 'launch':
			raise RuntimeError('Chrome launch failed')
		return self.browser

	async def new_context(self, **kwargs):
		self.calls['context_kwargs'] = kwargs
		if self.failure == 'new_context':
			raise RuntimeError('Context creation failed')
		return self.context

	async def close_context(self):
		self.context_closed += 1
		if self.failure == 'close_context':
			raise RuntimeError('Context close failed')

	async def close_browser(self):
		self.browser_closed += 1
		if self.failure == 'close_browser':
			raise RuntimeError('Browser close failed')


@pytest.fixture
def chrome_driver(monkeypatch, tmp_path):
	import playwright.async_api

	driver = FakeChromeDriver()
	monkeypatch.setattr(playwright.async_api, 'async_playwright', lambda: driver)
	monkeypatch.setattr(
		browser, 'system_chrome_details', lambda: (tmp_path / 'installed' / 'chrome.exe', '155.0.8123.7')
	)
	monkeypatch.setenv('CHECKIN_BROWSER_ENGINE', 'chrome')
	monkeypatch.setenv('CHECKIN_BROWSER_PROFILE_DIR', str(tmp_path / 'application-profiles'))
	return driver


@pytest.mark.asyncio
async def test_chrome_launch_uses_only_supplied_profile_and_no_fingerprint_options(
	chrome_driver, monkeypatch, tmp_path
):
	monkeypatch.setenv('CHECKIN_STATE_KEY', 'must-not-reach-browser')
	settings = replace(load_browser_login_settings('identity-1', 'linuxdo'), headless=False)
	context = await launch_login_context(
		settings, secure=True, fingerprint_seed=12345, proxy_server='http://127.0.0.1:8080'
	)
	assert chrome_driver.calls['profile_dir'] == str(settings.profile_dir)
	assert settings.profile_dir.is_relative_to(tmp_path / 'application-profiles')
	assert context.pages == ['application-page']
	kwargs = chrome_driver.calls['persistent_kwargs']
	assert kwargs['executable_path'] == str(tmp_path / 'installed' / 'chrome.exe')
	assert kwargs['headless'] is False
	assert kwargs['proxy'] == {'server': 'http://127.0.0.1:8080'}
	assert kwargs['accept_downloads'] is False
	assert kwargs['service_workers'] == 'block'
	assert 'CHECKIN_STATE_KEY' not in kwargs['env']
	for key in ('args', 'humanize', 'human_preset', 'locale', 'timezone', 'timezone_id', 'channel'):
		assert key not in kwargs
	await context.close()
	await context.close()
	assert chrome_driver.context_closed == 1
	assert chrome_driver.browser_closed == 1
	assert chrome_driver.stopped == 1


@pytest.mark.asyncio
async def test_chrome_ephemeral_launch_separates_context_and_process_options(chrome_driver):
	settings = load_browser_login_settings('identity-1', 'linuxdo', persist_profile=False)
	context = await launch_login_context(settings, secure=True)
	assert 'env' in chrome_driver.calls['launch_kwargs']
	assert 'accept_downloads' not in chrome_driver.calls['launch_kwargs']
	assert chrome_driver.calls['context_kwargs'] == {
		'viewport': {'width': 1920, 'height': 1080},
		'accept_downloads': False,
		'service_workers': 'block',
	}
	assert not settings.profile_dir.exists()
	await context.close()
	assert chrome_driver.stopped == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('persist_profile', [True, False])
async def test_chrome_launch_failure_stops_playwright_driver(chrome_driver, persist_profile):
	chrome_driver.failure = 'launch'
	settings = load_browser_login_settings('identity-1', 'linuxdo', persist_profile=persist_profile)
	with pytest.raises(RuntimeError, match='Chrome launch failed'):
		await launch_login_context(settings)
	assert chrome_driver.stopped == 1


@pytest.mark.asyncio
async def test_chrome_context_creation_failure_closes_browser_and_driver(chrome_driver):
	chrome_driver.failure = 'new_context'
	settings = load_browser_login_settings('identity-1', 'linuxdo', persist_profile=False)
	with pytest.raises(RuntimeError, match='Context creation failed'):
		await launch_login_context(settings)
	assert chrome_driver.browser_closed == 1
	assert chrome_driver.stopped == 1


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['close_context', 'close_browser'])
async def test_chrome_close_failure_still_stops_driver(chrome_driver, failure):
	settings = load_browser_login_settings('identity-1', 'linuxdo')
	context = await launch_login_context(settings)
	chrome_driver.failure = failure
	with pytest.raises(RuntimeError, match='close failed'):
		await context.close()
	assert chrome_driver.context_closed == 1
	assert chrome_driver.browser_closed == 1
	assert chrome_driver.stopped == 1


@pytest.mark.asyncio
async def test_invalid_engine_is_rejected_before_launch(monkeypatch):
	monkeypatch.delenv('CHECKIN_BROWSER_ENGINE', raising=False)
	settings = replace(load_browser_login_settings('identity-1', 'linuxdo'), engine='unsupported')
	with pytest.raises(AuthError, match='^INVALID_BROWSER_ENGINE$'):
		await launch_login_context(settings)


@pytest.mark.asyncio
async def test_cloak_secure_launch_options_are_preserved(monkeypatch, tmp_path):
	monkeypatch.delenv('CHECKIN_BROWSER_ENGINE', raising=False)
	calls = {}
	context = SimpleNamespace()

	async def launch_persistent(profile_dir, **kwargs):
		calls.update(kwargs)
		return context

	monkeypatch.setitem(sys.modules, 'cloakbrowser', SimpleNamespace(launch_persistent_context_async=launch_persistent))
	settings = replace(load_browser_login_settings('identity-1', 'linuxdo'), profile_dir=tmp_path / 'cloak')
	assert cast(object, await launch_login_context(settings, secure=True, fingerprint_seed=123)) is context
	assert calls['humanize'] is True
	assert calls['human_preset'] == 'careful'
	assert calls['args'] == ['--fingerprint=123']
	assert calls['locale'] == 'en-US'
	assert calls['timezone'] == 'UTC'
	assert calls['service_workers'] == 'block'
	assert calls['accept_downloads'] is False
