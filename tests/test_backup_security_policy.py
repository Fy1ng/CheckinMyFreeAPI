"""Account restores preserve the current instance's authentication trust boundary."""

import hashlib
import os
import sqlite3

import pytest_asyncio
from aiohttp import CookieJar
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.webauthn import AttestedCredentialData, AuthenticatorData

from server.app import SERVICE, create_app
from server.config_store import default_config
from server.passkeys import SecurityStore

ORIGIN = 'https://security.example.test'
RECOVERY = 'synthetic-backup-security-password'


def add_verified(store, label):
	credential = AttestedCredentialData.create(
		bytes(16), os.urandom(32), ES256.from_cryptography_key(ec.generate_private_key(ec.SECP256R1()).public_key())
	)
	rp_hash = hashlib.sha256(b'security.example.test').digest()
	flags = AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.UV
	identifier = store.add(
		ORIGIN,
		'security.example.test',
		label,
		AuthenticatorData.create(rp_hash, flags | AuthenticatorData.FLAG.AT, 0, credential),
	)
	store.record_assertion(identifier, ORIGIN, AuthenticatorData.create(rp_hash, flags, 5))
	return identifier


@pytest_asyncio.fixture
async def security_instances(tmp_path):
	services = []

	def make(name):
		service = create_app(tmp_path / name, os.urandom(32), 'synthetic-admin-password', scheduler=False)[SERVICE]
		service.store.save(default_config(), 0)
		services.append(service)
		return service

	yield make
	for service in reversed(services):
		await service.backups.close()
		await service.jobs.close()
		service.security.close()
		service.store.close()
		service.db.close()


def test_restoring_password_backup_cannot_downgrade_current_passkey_policy(security_instances):
	source = security_instances('source')
	old_identifier = add_verified(source.security, 'Old backup key')
	item = source.backups.manager.create(RECOVERY)
	data = source.backups.manager.read(item['id']).read_bytes()
	target = security_instances('target')
	current_identifier = add_verified(target.security, 'Current key')
	target.security.set_mode('passkey', target.security.policy()['revision'], ORIGIN, 'passkey')
	before_revision = target.security.policy()['revision']
	before_keys = [tuple(row) for row in target.security.db.execute('SELECT * FROM web_passkeys')]
	preview = target.backups.manager.preview(data, RECOVERY, 1)
	path = target.backups.manager.prepare_restore(preview['ticket'], 1)
	try:
		restored = SecurityStore(path)
		try:
			assert restored.policy()['mode'] == 'passkey'
			assert restored.policy()['revision'] == before_revision + 1
			assert [row['id'] for row in restored.keys(ORIGIN)] == [current_identifier]
			assert old_identifier not in [row['id'] for row in restored.keys(ORIGIN)]
			assert [tuple(row) for row in restored.db.execute('SELECT * FROM web_passkeys')] == before_keys
		finally:
			restored.close()
	finally:
		path.unlink(missing_ok=True)


def test_legacy_backup_without_passkey_tables_keeps_current_authenticators(security_instances):
	source = security_instances('legacy')
	with sqlite3.connect(source.data_dir / 'webui.sqlite3') as db:
		db.execute('DROP TABLE web_passkeys')
		db.execute('DROP TABLE web_security')
	item = source.backups.manager.create(RECOVERY)
	data = source.backups.manager.read(item['id']).read_bytes()
	target = security_instances('target')
	identifier = add_verified(target.security, 'Retained key')
	target.security.set_mode('passkey', target.security.policy()['revision'], ORIGIN, 'passkey')
	preview = target.backups.manager.preview(data, RECOVERY, 1)
	path = target.backups.manager.prepare_restore(preview['ticket'], 1)
	try:
		restored = SecurityStore(path)
		try:
			assert restored.policy()['mode'] == 'passkey'
			assert restored.keys(ORIGIN)[0]['id'] == identifier
		finally:
			restored.close()
	finally:
		path.unlink(missing_ok=True)


async def test_security_policy_changes_are_blocked_during_restore_snapshot(tmp_path):
	app = create_app(tmp_path, os.urandom(32), 'synthetic-admin-password', scheduler=False)
	service = app[SERVICE]
	client = TestClient(TestServer(app), cookie_jar=CookieJar(unsafe=True))
	await client.start_server()
	try:
		origin = str(client.make_url('')).rstrip('/')
		response = await client.post(
			'/api/login', json={'password': 'synthetic-admin-password'}, headers={'Origin': origin}
		)
		assert response.status == 200
		headers = {'Origin': origin, 'X-CSRF-Token': (await response.json())['csrf']}
		before = service.security.policy()['revision']
		async with service.backup_operation:
			response = await client.post(
				'/api/security/mode',
				json={'mode': 'password', 'revision': before, 'reauth_token': 'unused'},
				headers=headers,
			)
			assert response.status == 409
			assert service.security.policy()['revision'] == before
			response = await client.post('/api/security/reauth/options', json={}, headers=headers)
			assert response.status == 409
		response = await client.post(
			'/api/security/reauth', json={'password': 'synthetic-admin-password'}, headers=headers
		)
		assert response.status == 200
	finally:
		await client.close()
