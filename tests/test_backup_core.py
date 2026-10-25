"""Encrypted backup round trips use disposable instances and never send requests."""

import hmac
import json
import os
import sqlite3
import time
from contextlib import closing

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from server import backup
from server.app import SERVICE, create_app
from server.config_store import ConfigStore, default_config
from server.http_session_store import HttpSessionStore
from utils.http_checkin import account_binding

RECOVERY_PASSWORD = 'synthetic-recovery-password'


@pytest_asyncio.fixture
async def instances(tmp_path):
	services = []

	def create(name):
		root = tmp_path / name
		key = os.urandom(32)
		app = create_app(root, key, 'synthetic-admin-' + name, scheduler=False)
		service = app[SERVICE]
		services.append(service)
		config = default_config()
		config['accounts'] = [
			{
				'id': 'first',
				'name': 'private-account',
				'provider': 'anyrouter',
				'auth_type': 'cookie',
				'cookies': 'session=synthetic-session-cookie',
				'api_user': '7',
			}
		]
		config['webui_url'] = 'https://' + name + '.example'
		config['schedule']['enabled'] = True
		for settings in config.get('automation', {}).values():
			settings['enabled'] = True
		if 'backups' in config:
			config['backups'].update(enabled=True, password=RECOVERY_PASSWORD)
		service.store.save(config, 0)
		config, revision = service.store.load()
		session_key = hmac.digest(key, b'newapi-http-sessions-v1', 'sha256')
		sessions = HttpSessionStore(root / 'webui.sqlite3', session_key)
		sessions.save(
			'first',
			account_binding(config['accounts'][0], config),
			{
				'api_user': '7',
				'cookies': [
					{'name': 'session', 'value': 'synthetic-session-cookie', 'domain': 'anyrouter.top', 'path': '/'}
				],
			},
		)
		sessions.close()
		with closing(sqlite3.connect(root / 'webui.sqlite3')) as db, db:
			row = db.execute('SELECT revision,document FROM config').fetchone()
			db.execute(
				'INSERT INTO config_archive VALUES (?,?,?)',
				(
					row[0],
					row[1],
					json.dumps(
						{
							'from_schema': 2,
							'source_revision': row[0],
							'converted_accounts': 1,
							'disabled_accounts': 1,
							'omitted_accounts': 0,
							'schedule_disabled': False,
						}
					),
				),
			)
			db.execute(
				"INSERT INTO runs(id,state,started_at,finished_at,revision,kind) VALUES (1,'succeeded',?,?,?,'checkin')",
				(time.time() - 10, time.time(), revision),
			)
		return service, key, config

	yield create
	for service in reversed(services):
		await service.backups.close()
		await service.jobs.close()
		service.security.close()
		service.store.close()
		service.db.close()


def package(service):
	metadata = service.backups.manager.create(RECOVERY_PASSWORD)
	return service.backups.manager.read(metadata['id']).read_bytes()


def test_package_encrypts_key_and_sensitive_data_and_lists_safe_metadata(instances):
	service, key, _ = instances('source')
	metadata = service.backups.manager.create(RECOVERY_PASSWORD)
	data = service.backups.manager.read(metadata['id']).read_bytes()
	assert key not in data and b'synthetic-session-cookie' not in data
	assert 'password' not in json.dumps(metadata) and 'master_key' not in json.dumps(metadata)
	assert service.backups.manager.list()[0]['id'] == metadata['id']
	assert backup.inspect_backup(data, RECOVERY_PASSWORD)['accounts'] == 1
	assert backup.inspect_backup(data, RECOVERY_PASSWORD)['runs'] == 1


def test_restore_across_master_keys_preserves_current_admin_public_url_and_rekeys_archives_sessions(instances):
	source, source_key, original = instances('source')
	target, target_key, current = instances('target')
	manager = target.backups.manager
	with closing(sqlite3.connect(target.data_dir / 'webui.sqlite3')) as db:
		current_auth = db.execute('SELECT salt,digest FROM web_auth').fetchone()
	preview = manager.preview(package(source), RECOVERY_PASSWORD, 1)
	assert preview['accounts'] == 1 and preview['automatic_tasks_disabled']
	assert source_key.hex() not in json.dumps(preview)
	path = manager.prepare_restore(preview['ticket'], 1)
	try:
		with pytest.raises(backup.BackupError):
			manager.prepare_restore(preview['ticket'], 1)
		store = ConfigStore(path, target_key)
		restored, revision = store.load()
		assert revision == 2
		assert restored['webui_url'] == current['webui_url']
		assert restored['accounts'] == original['accounts']
		assert not restored['schedule']['enabled'] and not restored['monitoring']['enabled']
		assert all(not item['enabled'] for item in restored.get('automation', {}).values())
		if 'backups' in restored:
			assert not restored['backups']['enabled']
		store.close()
		with closing(sqlite3.connect(path)) as db:
			assert db.execute('SELECT salt,digest FROM web_auth').fetchone() == current_auth
			archived_revision, encrypted = db.execute('SELECT source_revision,document FROM config_archive').fetchone()
			plain = AESGCM(target_key).decrypt(
				encrypted[:12], encrypted[12:], b'anyrouter.server.configuration.v1:' + str(archived_revision).encode()
			)
			assert json.loads(plain)['webui_url'] == original['webui_url']
			assert db.execute('SELECT next_at FROM scheduler').fetchone()[0] is None
		sessions = HttpSessionStore(path, hmac.digest(target_key, b'newapi-http-sessions-v1', 'sha256'))
		session = sessions.load('first', account_binding(restored['accounts'][0], restored))
		assert session is not None and session['api_user'] == '7'
		sessions.close()
	finally:
		path.unlink(missing_ok=True)


@pytest.mark.parametrize('mutate', ['wrong_password', 'bitflip', 'truncated', 'unknown_version', 'too_large'])
def test_invalid_envelopes_do_not_change_live_database_or_leave_preview_files(instances, mutate, monkeypatch):
	service, _, _ = instances('source')
	data = package(service)
	password = RECOVERY_PASSWORD
	if mutate == 'wrong_password':
		password = 'different-recovery-password'
	elif mutate == 'bitflip':
		data = data[:-1] + bytes([data[-1] ^ 1])
	elif mutate == 'truncated':
		data = data[:50]
	elif mutate == 'unknown_version':
		data = b'unsupported' + data
	else:
		monkeypatch.setattr(backup, 'MAX_BACKUP_BYTES', len(data) - 1)
	before = (service.data_dir / 'webui.sqlite3').read_bytes()
	with pytest.raises(backup.BackupError):
		service.backups.manager.preview(data, password, 1)
	assert (service.data_dir / 'webui.sqlite3').read_bytes() == before
	assert not list(service.data_dir.glob('.restore-preview-*'))


@pytest.mark.parametrize(
	'sql',
	[
		'CREATE TABLE injected (data TEXT)',
		'CREATE VIEW injected AS SELECT * FROM web_auth',
		'CREATE TRIGGER injected AFTER INSERT ON config BEGIN DELETE FROM runs; END',
	],
)
def test_authenticated_package_with_untrusted_schema_is_rejected(instances, sql):
	service, key, _ = instances('source')
	path = backup._stage(service.data_dir, (service.data_dir / 'webui.sqlite3').read_bytes())
	try:
		with closing(sqlite3.connect(path)) as db, db:
			db.execute(sql)
		data = backup._encode(path.read_bytes(), key, RECOVERY_PASSWORD, time.time())
		with pytest.raises(backup.BackupError, match='数据库结构'):
			service.backups.manager.preview(data, RECOVERY_PASSWORD, 1)
	finally:
		path.unlink(missing_ok=True)


def test_preview_is_revision_bound_expiring_and_limited(instances):
	service, _, config = instances('source')
	manager = service.backups.manager
	data = package(service)
	with pytest.raises(backup.BackupError):
		manager.preview(data, RECOVERY_PASSWORD, True)
	preview = manager.preview(data, RECOVERY_PASSWORD, 1)
	service.store.save(config, 1)
	with pytest.raises(backup.BackupError, match='配置已更新'):
		manager.prepare_restore(preview['ticket'], 1)
	preview = manager.preview(data, RECOVERY_PASSWORD, 2)
	manager._previews[preview['ticket']]['expires'] = 0
	with pytest.raises(backup.BackupError, match='失效'):
		manager.prepare_restore(preview['ticket'], 2)
	for _ in range(backup._MAX_PREVIEWS):
		manager.preview(data, RECOVERY_PASSWORD, 2)
	with pytest.raises(backup.BackupError, match='预览过多'):
		manager.preview(data, RECOVERY_PASSWORD, 2)
	manager.close()
	assert not list(service.data_dir.glob('.restore-preview-*'))


def test_rotation_retains_valid_packages_and_failed_create_does_not_delete_last_good(instances, monkeypatch):
	service, _, _ = instances('source')
	manager = service.backups.manager
	for _ in range(3):
		manager.create(RECOVERY_PASSWORD, retain_count=2)
	assert len(manager.list()) == 2
	(manager.directory / 'unrelated.txt').write_text('retain me')
	(manager.directory / 'backup-20269999T999999Z-0000000000000000.nab').write_bytes(backup.MAGIC)
	assert len(manager.list()) == 2
	before = {item['id'] for item in manager.list()}
	monkeypatch.setattr(backup, '_encode', lambda *args: (_ for _ in ()).throw(backup.BackupError('synthetic')))
	with pytest.raises(backup.BackupError):
		manager.create(RECOVERY_PASSWORD, retain_count=1)
	assert {item['id'] for item in manager.list()} == before
	assert (manager.directory / 'unrelated.txt').read_text() == 'retain me'
	assert not list(service.data_dir.glob('.backup-snapshot-*'))
	for bad in ('../webui.sqlite3', '/tmp/file', '', 'backup-invalid.nab'):
		with pytest.raises(backup.BackupError):
			manager.read(bad)


def test_offline_restore_needs_no_old_key_and_never_overwrites_existing_paths(instances, tmp_path):
	service, source_key, _ = instances('source')
	data = package(service)
	root, key_file = tmp_path / 'new-instance', tmp_path / 'keys' / 'master.key'
	result = backup.restore_offline(data, RECOVERY_PASSWORD, root, key_file)
	assert result['accounts'] == 1 and key_file.read_bytes() == source_key
	store = ConfigStore(root / 'webui.sqlite3', key_file.read_bytes())
	assert not store.load()[0]['schedule']['enabled']
	store.close()
	before = (root / 'webui.sqlite3').read_bytes()
	with pytest.raises(backup.BackupError, match='不覆盖'):
		backup.restore_offline(data, RECOVERY_PASSWORD, root, key_file)
	assert (root / 'webui.sqlite3').read_bytes() == before


def test_pending_notifications_and_inflight_writes_are_not_replayed_after_restore(instances):
	service, _, config = instances('source')
	with closing(sqlite3.connect(service.data_dir / 'webui.sqlite3')) as db, db:
		db.execute("UPDATE runs SET state='running' WHERE id=1")
		db.execute(
			"INSERT INTO automation_notifications(event_key,kind,state,created_at,title,message) VALUES ('synthetic','daily_summary','pending',?,'summary','safe')",
			(time.time(),),
		)
	data = package(service)
	preview = service.backups.manager.preview(data, RECOVERY_PASSWORD, 1)
	path = service.backups.manager.prepare_restore(preview['ticket'], 1)
	try:
		with closing(sqlite3.connect(path)) as db:
			assert db.execute('SELECT state FROM automation_notifications').fetchone()[0] == 'unknown'
			assert db.execute('SELECT state FROM runs').fetchone()[0] == 'interrupted'
			assert db.execute('SELECT outcome FROM account_attention').fetchone()[0] == 'uncertain'
	finally:
		path.unlink(missing_ok=True)


def test_core_and_inspection_use_writable_data_directory_when_system_tmp_is_unavailable(
	instances, tmp_path, monkeypatch
):
	service, _, _ = instances('source')
	monkeypatch.setattr(backup.tempfile, 'tempdir', str(tmp_path / 'unavailable-system-temp'))
	monkeypatch.setenv('CHECKIN_WEB_DATA_DIR', str(service.data_dir))
	data = package(service)
	assert backup.inspect_backup(data, RECOVERY_PASSWORD)['accounts'] == 1
	assert not list(service.data_dir.glob('.backup-schema-*'))
	assert not list(service.data_dir.glob('.backup-inspect-*'))


def test_symlinked_backup_files_and_directory_cannot_be_read_or_pruned(instances, tmp_path):
	service, _, _ = instances('source')
	manager = service.backups.manager
	outside = tmp_path / 'outside.nab'
	outside.write_bytes(backup.MAGIC + b'untouched')
	link = manager.directory / 'backup-20260101T000000Z-0000000000000000.nab'
	try:
		link.symlink_to(outside)
	except OSError:
		pytest.skip('Symbolic link creation is unavailable on this Windows instance')
	assert manager.list() == []
	with pytest.raises(backup.BackupError):
		manager.read(link.name)
	manager.create(RECOVERY_PASSWORD, retain_count=1)
	assert outside.read_bytes() == backup.MAGIC + b'untouched'
	link.unlink()
	for item in manager.list():
		manager.read(item['id']).unlink()
	manager.directory.rmdir()
	external_directory = tmp_path / 'external'
	external_directory.mkdir()
	manager.directory.symlink_to(external_directory, target_is_directory=True)
	try:
		with pytest.raises(backup.BackupError):
			manager.list()
		with pytest.raises(backup.BackupError):
			manager.create(RECOVERY_PASSWORD)
	finally:
		manager.directory.unlink()
		manager.directory.mkdir()


def test_offline_cli_inspects_and_restores_without_password_arguments(instances, tmp_path, monkeypatch, capsys):
	from server import backup_cli

	service, _, _ = instances('source')
	path = tmp_path / 'download.nab'
	path.write_bytes(package(service))
	monkeypatch.setattr(backup_cli.getpass, 'getpass', lambda prompt: RECOVERY_PASSWORD)
	monkeypatch.setattr(backup_cli, '__name__', 'not_main')
	monkeypatch.setattr('sys.argv', ['backup_cli', 'inspect', str(path)])
	backup_cli.main()
	output = capsys.readouterr().out
	assert json.loads(output)['accounts'] == 1
	assert RECOVERY_PASSWORD not in output and 'master_key' not in output
	monkeypatch.setattr(
		'sys.argv',
		[
			'backup_cli',
			'restore',
			str(path),
			'--data-dir',
			str(tmp_path / 'restored'),
			'--key-file',
			str(tmp_path / 'new-key'),
		],
	)
	backup_cli.main()
	assert json.loads(capsys.readouterr().out)['automatic_tasks_disabled']
	assert (tmp_path / 'restored' / 'webui.sqlite3').is_file()
	monkeypatch.setattr(
		'sys.argv',
		[
			'backup_cli',
			'restore',
			str(path),
			'--data-dir',
			str(tmp_path / 'restored'),
			'--key-file',
			str(tmp_path / 'new-key'),
		],
	)
	with pytest.raises(SystemExit) as error:
		backup_cli.main()
	assert error.value.code == 1
