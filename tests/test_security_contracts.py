import io
from pathlib import Path

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


def test_production_dependency_and_entry_points_are_browser_free():
	import ast
	import tomllib

	root = Path(__file__).resolve().parent.parent
	config = tomllib.loads((root / 'pyproject.toml').read_text(encoding='utf-8'))
	assert not any('cloakbrowser' in item or 'playwright' in item for item in config['project']['dependencies'])
	for folder in ('server', 'utils'):
		for path in (root / folder).glob('*.py'):
			tree = ast.parse(path.read_text(encoding='utf-8'))
			for node in ast.walk(tree):
				modules = (
					[item.name for item in node.names]
					if isinstance(node, ast.Import)
					else [node.module or '']
					if isinstance(node, ast.ImportFrom)
					else []
				)
				assert not any(module.startswith(('playwright', 'cloakbrowser', 'selenium')) for module in modules)
	docker = (root / 'Dockerfile').read_text(encoding='utf-8').lower()
	assert all(term not in docker for term in ('chromium', 'xvfb', 'novnc', 'x11vnc', 'cloakbrowser'))
