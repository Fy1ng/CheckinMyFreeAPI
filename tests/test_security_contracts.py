import io
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import yaml

from utils.logging_safety import RedactingStream, redact, sensitive_values


def test_split_log_writes_are_redacted():
	output = io.StringIO()
	stream = RedactingStream(output, {'synthetic-password'})
	stream.write('secret: synthetic-')
	stream.write('password\n')
	stream.flush()
	assert output.getvalue() == 'secret: [REDACTED]\n'


def test_proxy_userinfo_and_oauth_queries_are_redacted():
	message = (
		'http://name:password@proxy.test:8080 https://provider.test/oauth/github?code=secret&state=secret&other=ok'
	)
	result = redact(message, set())
	assert 'password' not in result
	assert 'code=secret' not in result
	assert 'state=secret' not in result
	assert 'other=ok' in result


def test_account_json_secrets_are_collected(monkeypatch):
	monkeypatch.setenv(
		'ANYROUTER_ACCOUNTS', '[{"password":"synthetic-pass","cookies":{"session":"synthetic-session"}}]'
	)
	values = sensitive_values()
	assert {'synthetic-pass', 'synthetic-session'} <= values


def test_actions_never_run_real_checkin_or_receive_login_configuration():
	root = Path(__file__).resolve().parent.parent
	assert not (root / '.github/workflows/checkin.yml').exists()
	for path in (root / '.github/workflows').glob('*.yml'):
		text = path.read_text(encoding='utf-8')
		workflow = yaml.safe_load(text)
		assert 'schedule' not in workflow.get('on', workflow.get(True, {}))
		assert 'uv run checkin.py' not in text
		assert 'secrets.ANYROUTER_ACCOUNTS' not in text
		assert 'secrets.CHECKIN_STATE_KEY' not in text


@pytest.mark.asyncio
async def test_secure_mode_never_saves_login_screenshot_even_in_debug(monkeypatch):
	from utils.browser import save_login_screenshot

	monkeypatch.setenv('DEBUG_MODE', 'true')
	monkeypatch.setenv('CHECKIN_SECURE_MODE', 'true')
	page = AsyncMock()
	assert await save_login_screenshot(page, 'provider', 'alias', 'login') is None
	page.screenshot.assert_not_awaited()
