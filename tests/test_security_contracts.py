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


def test_production_workflow_caches_only_encrypted_authentication_state():
	root = Path(__file__).resolve().parent.parent
	workflow = yaml.safe_load((root / '.github/workflows/checkin.yml').read_text(encoding='utf-8'))
	job = workflow['jobs']['checkin']
	assert 'default_branch' in job['if']
	assert workflow['permissions'] == {'contents': 'read'}
	assert workflow['concurrency']['cancel-in-progress'] is False
	assert job['environment'] == 'production'
	assert job['env']['CHECKIN_SECURE_MODE'] == 'true'
	for step in job['steps']:
		uses = step.get('uses', '')
		assert 'upload-artifact' not in uses
		if 'cache' in uses:
			path = step['with']['path']
			assert '.browser_profiles' not in path
			assert '.auth-state' not in path
			if '.auth-cache' in path:
				assert path == '.auth-cache/*.enc'
				if 'restore' in uses:
					assert 'github.run_attempt' in step['with']['key']
					assert 'CHECKIN_STATE_EPOCH' in step['with']['key']
				if 'save' in uses:
					assert 'ready' in step['if']
		if uses:
			assert len(uses.rsplit('@', 1)[-1]) == 40


@pytest.mark.asyncio
async def test_secure_mode_never_saves_login_screenshot_even_in_debug(monkeypatch):
	from utils.browser import save_login_screenshot

	monkeypatch.setenv('DEBUG_MODE', 'true')
	monkeypatch.setenv('CHECKIN_SECURE_MODE', 'true')
	page = AsyncMock()
	assert await save_login_screenshot(page, 'provider', 'alias', 'login') is None
	page.screenshot.assert_not_awaited()
