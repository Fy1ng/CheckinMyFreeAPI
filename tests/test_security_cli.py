"""Operator recovery takes the service lock and never opens a network connection."""

import json
import sys

import pytest

from server import security_cli
from server.jobs import acquire_file_lock
from server.passkeys import SecurityStore


def test_recovery_requires_confirmation_and_stopped_service(tmp_path, monkeypatch, capsys):
	store = SecurityStore(tmp_path / 'webui.sqlite3')
	store.db.execute("UPDATE web_security SET mode='passkey'")
	store.db.commit()
	store.close()
	monkeypatch.setattr(sys, 'argv', ['security_cli', 'reset', '--data-dir', str(tmp_path)])
	with pytest.raises(SystemExit):
		security_cli.main()
	lease = acquire_file_lock(tmp_path / 'service.lock')
	monkeypatch.setattr(sys, 'argv', ['security_cli', 'reset', '--data-dir', str(tmp_path), '--confirm'])
	try:
		with pytest.raises(SystemExit):
			security_cli.main()
	finally:
		lease.close()
	security_cli.main()
	assert json.loads(capsys.readouterr().out)['mode'] == 'password'
	store = SecurityStore(tmp_path / 'webui.sqlite3')
	assert store.policy()['revision'] == 2
	store.close()


def test_missing_directory_is_not_initialized_by_recovery(tmp_path, monkeypatch):
	directory = tmp_path / 'missing'
	monkeypatch.setattr(sys, 'argv', ['security_cli', 'reset', '--data-dir', str(directory), '--confirm'])
	with pytest.raises(SystemExit):
		security_cli.main()
	assert not directory.exists()
