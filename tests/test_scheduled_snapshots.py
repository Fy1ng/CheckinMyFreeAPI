"""Snapshot deadlines survive normal jobs and cancellation keeps the executor locked."""

import asyncio
import os
import threading
import time
from datetime import datetime
from unittest.mock import AsyncMock

import pytest

import server.backup_runtime as backup_module
from server.backup_runtime import BackupRuntime, next_backup_at
from server.balance_store import STAT_TIMEZONE
from server.config_store import ConfigStore, default_config
from server.jobs import BusyError, JobManager


def test_daily_snapshot_time_is_strictly_future_in_utc8():
	now = datetime(2026, 10, 25, 3, 0, tzinfo=STAT_TIMEZONE).timestamp()
	assert next_backup_at('03:00', now) == now + 86400
	assert next_backup_at('03:01', now) == now + 60


async def test_cancelled_snapshot_does_not_release_job_lock_while_thread_is_writing(tmp_path, monkeypatch):
	key = os.urandom(32)
	store = ConfigStore(tmp_path / 'webui.sqlite3', key)
	config = default_config()
	config['backups']['password'] = 'synthetic-recovery-password'
	store.save(config, 0)
	jobs = JobManager(store, tmp_path, key)
	backups = BackupRuntime(store, tmp_path, key, jobs)
	started, finished = threading.Event(), threading.Event()

	def create(*args):
		started.set()
		assert finished.wait(5)
		return {'id': 'synthetic'}

	monkeypatch.setattr(backups.manager, 'create', create)
	task = asyncio.create_task(backups.create(1))
	try:
		assert await asyncio.to_thread(started.wait, 2)
		task.cancel()
		await asyncio.sleep(0.02)
		assert jobs._lock.locked() and backups.busy
		with pytest.raises(BusyError):
			await backups.create(1)
		finished.set()
		with pytest.raises(asyncio.CancelledError):
			await task
		assert not jobs._lock.locked() and not backups.busy
		assert backups.status()['last_state'] == 'succeeded'
	finally:
		finished.set()
		await asyncio.gather(task, return_exceptions=True)
		await backups.close()
		await jobs.close()
		store.close()


async def test_snapshot_deadline_is_persistent_and_disabled_without_password(tmp_path):
	key = os.urandom(32)
	store = ConfigStore(tmp_path / 'webui.sqlite3', key)
	store.save(default_config(), 0)
	jobs = JobManager(store, tmp_path, key)
	backups = BackupRuntime(store, tmp_path, key, jobs)
	try:
		backups.schedule_changed()
		assert backups.status()['next_at'] is None
		config, revision = store.load()
		config['backups'].update(enabled=True, password='synthetic-recovery-password')
		store.save(config, revision)
		backups.schedule_changed()
		due = backups.db.execute('SELECT next_at FROM backup_scheduler WHERE id=1').fetchone()[0]
		assert due > time.time()
		await backups.open()
		assert backups.db.execute('SELECT next_at FROM backup_scheduler WHERE id=1').fetchone()[0] == due
	finally:
		await backups.close()
		await jobs.close()
		store.close()


@pytest.mark.parametrize('busy', [False, True])
async def test_due_automatic_backup_runs_once_and_waits_for_account_jobs(tmp_path, monkeypatch, busy):
	key = os.urandom(32)
	store = ConfigStore(tmp_path / 'webui.sqlite3', key)
	config = default_config()
	config['backups'].update(enabled=True, password='synthetic-recovery-password')
	store.save(config, 0)
	jobs = JobManager(store, tmp_path, key)
	backups = BackupRuntime(store, tmp_path, key, jobs)
	due = time.time() - 10
	backups.db.execute('UPDATE backup_scheduler SET next_at=? WHERE id=1', (due,))
	backups.db.commit()
	jobs.active_id = 42 if busy else None
	create = AsyncMock(return_value={'id': 'synthetic'})
	monkeypatch.setattr(backups, 'create', create)
	ticks = 0

	async def tick(delay):
		nonlocal ticks
		ticks += 1
		if ticks > 1:
			raise asyncio.CancelledError

	monkeypatch.setattr(backup_module.asyncio, 'sleep', tick)
	try:
		with pytest.raises(asyncio.CancelledError):
			await backups.scheduler()
		next_at = backups.db.execute('SELECT next_at FROM backup_scheduler WHERE id=1').fetchone()[0]
		if busy:
			create.assert_not_called()
			assert next_at == due
		else:
			create.assert_awaited_once_with(1)
			assert next_at > time.time()
	finally:
		jobs.active_id = None
		await backups.close()
		await jobs.close()
		store.close()
