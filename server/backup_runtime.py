"""Daily encrypted snapshots share the existing executor's serial task lock."""

from __future__ import annotations

import asyncio
import sqlite3
import time
from datetime import datetime, timedelta

from server.backup import BackupManager
from server.balance_store import STAT_TIMEZONE, stamp
from server.jobs import BusyError

BACKUP_DEFAULTS = {'enabled': False, 'time': '03:00', 'retain_count': 7, 'password': str()}


def next_backup_at(clock: str, now: float) -> float:
	hour, minute = (int(part) for part in clock.split(':'))
	current = datetime.fromtimestamp(now, STAT_TIMEZONE)
	candidate = current.replace(hour=hour, minute=minute, second=0, microsecond=0)
	if candidate <= current:
		candidate += timedelta(days=1)
	return candidate.timestamp()


class BackupRuntime:
	def __init__(self, store, data_dir, key, jobs):
		self.store, self.jobs = store, jobs
		self.manager = BackupManager(data_dir, key, store)
		self.db = sqlite3.connect(data_dir / 'webui.sqlite3', timeout=10)
		self.db.execute(
			'CREATE TABLE IF NOT EXISTS backup_scheduler ('
			'id INTEGER PRIMARY KEY CHECK(id=1),next_at REAL,last_attempt_at REAL,last_state TEXT,error TEXT)'
		)
		self.db.execute('INSERT OR IGNORE INTO backup_scheduler VALUES (1,NULL,NULL,NULL,NULL)')
		self.db.commit()
		self.task: asyncio.Task | None = None
		self.busy = False

	def schedule_changed(self) -> None:
		config, _ = self.store.load()
		settings = config.get('backups', BACKUP_DEFAULTS)
		next_at = (
			next_backup_at(settings['time'], time.time()) if settings['enabled'] and settings['password'] else None
		)
		with self.db:
			self.db.execute('UPDATE backup_scheduler SET next_at=? WHERE id=1', (next_at,))

	def status(self) -> dict:
		next_at, attempted, state, error = self.db.execute(
			'SELECT next_at,last_attempt_at,last_state,error FROM backup_scheduler WHERE id=1'
		).fetchone()
		return {
			'busy': self.busy,
			'next_at': stamp(next_at),
			'last_attempt_at': stamp(attempted),
			'last_state': state,
			'error': error,
			'backups': self.manager.list(),
		}

	async def create(self, revision: int) -> dict:
		if self.busy or self.jobs.active_id is not None or self.jobs._lock.locked():
			raise BusyError('请等待当前任务结束后再备份')
		async with self.jobs._lock:
			config, current = self.store.load()
			if current != revision:
				raise BusyError('配置已更新, 请重新读取后再备份')
			settings = config.get('backups', BACKUP_DEFAULTS)
			if not settings['password']:
				raise BusyError('请先设置并保存备份恢复密码')
			self.busy = True
			with self.db:
				self.db.execute(
					"UPDATE backup_scheduler SET last_attempt_at=?,last_state='running',error=NULL WHERE id=1",
					(time.time(),),
				)
			try:
				operation = asyncio.create_task(
					asyncio.to_thread(self.manager.create, settings['password'], settings['retain_count'])
				)
				try:
					result = await asyncio.shield(operation)
				except asyncio.CancelledError:
					await operation
					with self.db:
						self.db.execute("UPDATE backup_scheduler SET last_state='succeeded',error=NULL WHERE id=1")
					raise
				with self.db:
					self.db.execute("UPDATE backup_scheduler SET last_state='succeeded',error=NULL WHERE id=1")
				return result
			except Exception:
				with self.db:
					self.db.execute(
						"UPDATE backup_scheduler SET last_state='failed',error='backup_creation_failed' WHERE id=1"
					)
				raise
			finally:
				self.busy = False

	async def scheduler(self) -> None:
		while True:
			await asyncio.sleep(5)
			config, revision = self.store.load()
			settings = config.get('backups', BACKUP_DEFAULTS)
			if not settings['enabled'] or not settings['password']:
				continue
			next_at = self.db.execute('SELECT next_at FROM backup_scheduler WHERE id=1').fetchone()[0]
			if next_at is None:
				self.schedule_changed()
			elif (
				next_at <= time.time()
				and self.jobs.active_id is None
				and not self.jobs._lock.locked()
				and not self.busy
			):
				# Persist the next day before attempting a snapshot; no catch-up retry loop.
				self.schedule_changed()
				try:
					await self.create(revision)
				except Exception:
					with self.db:
						self.db.execute(
							"UPDATE backup_scheduler SET last_state='failed',error='backup_creation_failed' WHERE id=1"
						)

	async def open(self) -> None:
		config, _ = self.store.load()
		next_at = self.db.execute('SELECT next_at FROM backup_scheduler WHERE id=1').fetchone()[0]
		if not config.get('backups', BACKUP_DEFAULTS)['enabled'] or next_at is None or next_at <= time.time():
			self.schedule_changed()
		self.task = asyncio.create_task(self.scheduler(), name='backup-scheduler')

	async def close(self) -> None:
		if self.task:
			self.task.cancel()
			await asyncio.gather(self.task, return_exceptions=True)
		self.manager.close()
		self.db.close()
