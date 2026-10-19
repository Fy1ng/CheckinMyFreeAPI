"""One isolated worker at a time, with persistent run history and scheduling."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import signal
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from server.execution_state import ExecutionState
from utils.http_checkin import account_binding
from utils.process_env import child_environment


class BusyError(RuntimeError):
	pass


def iso_time(timestamp: float | None) -> str | None:
	return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp is not None else None


def acquire_file_lock(path: Path) -> BinaryIO:
	stream = path.open('a+b')
	try:
		if os.name == 'nt':
			import msvcrt

			stream.seek(0)
			if not stream.read(1):
				stream.write(b'1')
				stream.flush()
			stream.seek(0)
			msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
		else:
			import fcntl

			getattr(fcntl, 'flock')(stream.fileno(), getattr(fcntl, 'LOCK_EX') | getattr(fcntl, 'LOCK_NB'))
	except OSError:
		stream.close()
		raise BusyError('该数据目录已有服务或任务运行') from None
	return stream


async def terminate_windows_tree(process) -> None:
	"""Terminate only the owned worker process tree."""
	killer = await asyncio.create_subprocess_exec(
		'taskkill',
		'/PID',
		str(process.pid),
		'/T',
		'/F',
		stdout=asyncio.subprocess.DEVNULL,
		stderr=asyncio.subprocess.DEVNULL,
	)
	await asyncio.wait_for(killer.wait(), timeout=5)
	await asyncio.wait_for(process.wait(), timeout=5)


class JobManager:
	def __init__(self, config_store, data_dir: Path, key: bytes, *, instance_lock: BinaryIO | None = None):
		self.config_store = config_store
		self.data_dir = data_dir.resolve()
		self.key = key
		self._instance_lock = instance_lock
		if self._instance_lock is None:
			self.acquire_instance_lock()
		self.db = sqlite3.connect(self.data_dir / 'webui.sqlite3')
		self.db.executescript("""
		CREATE TABLE IF NOT EXISTS runs (
		 id INTEGER PRIMARY KEY, state TEXT NOT NULL, started_at REAL NOT NULL,
		 finished_at REAL, error TEXT, summary TEXT, revision INTEGER NOT NULL
		);
		CREATE TABLE IF NOT EXISTS scheduler (id INTEGER PRIMARY KEY CHECK(id=1), next_at REAL);
		INSERT OR IGNORE INTO scheduler VALUES (1, NULL);
		""")
		columns = {column[1] for column in self.db.execute('PRAGMA table_info(runs)')}
		if 'kind' not in columns:
			self.db.execute("ALTER TABLE runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'checkin'")
		if 'identity' not in columns:
			self.db.execute('ALTER TABLE runs ADD COLUMN identity TEXT')
		config, _ = self.config_store.load()
		for run_id, kind in self.db.execute(
			"SELECT id,kind FROM runs WHERE state IN ('running','awaiting_login','stopping')"
		).fetchall():
			if kind == 'checkin':
				self._record_interrupted_account(self._progress(self.data_dir / f'run-{run_id}.json'), config)
		self.db.execute(
			"UPDATE runs SET state='interrupted',finished_at=?,error='服务重启, 请核对站点结果后再运行' WHERE state IN ('running','awaiting_login','stopping')",
			(time.time(),),
		)
		self.db.commit()
		self.task: asyncio.Task | None = None
		self.process: asyncio.subprocess.Process | None = None
		self.active_id: int | None = None
		self.manual: dict | None = None
		self.stopping = False
		self._scheduler_task: asyncio.Task | None = None
		self._lock = asyncio.Lock()

	def acquire_instance_lock(self) -> None:
		"""The OS releases this advisory lock even after an unclean service exit."""
		self._instance_lock = acquire_file_lock(self.data_dir / 'service.lock')

	def history(self) -> list[dict]:
		rows = self.db.execute(
			'SELECT id,state,started_at,finished_at,error,summary,revision,kind,identity FROM runs ORDER BY id DESC LIMIT 50'
		).fetchall()
		return [
			dict(
				id=row[0],
				state=row[1],
				started_at=iso_time(row[2]),
				finished_at=iso_time(row[3]),
				error=row[4],
				summary=json.loads(row[5]) if row[5] else None,
				revision=row[6],
				kind=row[7],
				identity=row[8],
			)
			for row in rows
		]

	def status(self) -> dict:
		runs = self.history()
		run = runs[0] if runs else None
		config, _ = self.config_store.load()
		state = ExecutionState(self.data_dir / 'webui.sqlite3')
		try:
			attention = {}
			for account in config['accounts']:
				pending = state.get(account['id'], account_binding(account, config))
				if pending:
					attention[account['id']] = pending
		finally:
			state.close()
		return {
			'running': self.active_id is not None,
			'run': run,
			'attention': attention,
			'next_run_at': iso_time(self.db.execute('SELECT next_at FROM scheduler WHERE id=1').fetchone()[0]),
		}

	def resolve_attention(self, account_id: str, revision: int) -> None:
		if self.active_id is not None:
			raise BusyError('请等待当前任务结束后再解除暂停')
		config, current = self.config_store.load()
		if current != revision or not any(account['id'] == account_id for account in config['accounts']):
			raise BusyError('配置已更新, 请重新读取')
		state = ExecutionState(self.data_dir / 'webui.sqlite3')
		try:
			state.clear(account_id)
		finally:
			state.close()

	def schedule_changed(self) -> None:
		config, _ = self.config_store.load()
		schedule = config['schedule']
		next_at = time.time() + schedule['interval_minutes'] * 60 if schedule['enabled'] else None
		self.db.execute('UPDATE scheduler SET next_at=? WHERE id=1', (next_at,))
		self.db.commit()

	async def start(self, revision: int, *, trigger: str = 'manual') -> dict:
		async with self._lock:
			if self.active_id is not None:
				raise BusyError('已有任务运行, 请等待完成或先停止')
			config, current_revision = self.config_store.load()
			if current_revision != revision:
				raise BusyError('配置已更新, 请重新读取后运行')
			if trigger not in {'manual', 'scheduled'}:
				raise BusyError('任务来源无效')
			if not any(account.get('enabled', True) for account in config['accounts']):
				raise BusyError('请先保存至少一个已启用账号')
			cursor = self.db.execute(
				"INSERT INTO runs(state,started_at,revision,kind,identity) VALUES ('running',?,?,?,?)",
				(time.time(), revision, 'checkin', None),
			)
			self.db.commit()
			assert cursor.lastrowid is not None
			self.active_id = cursor.lastrowid
			self.stopping = False
			self.task = asyncio.create_task(
				self._execute(self.active_id, config, trigger=trigger), name='checkin-worker'
			)
			return self.history()[0]

	async def _execute(self, run_id: int, config: dict, *, trigger: str = 'manual') -> None:
		event_file = self.data_dir / f'run-{run_id}.json'
		try:
			if self.stopping:
				self.db.execute(
					"UPDATE runs SET state='cancelled',finished_at=?,error='任务在执行前已停止' WHERE id=?",
					(time.time(), run_id),
				)
				return
			environment = child_environment()
			environment.update(PYTHONIOENCODING='utf-8', PYTHONUNBUFFERED='1')
			self.process = await asyncio.create_subprocess_exec(
				sys.executable,
				'-m',
				'server.worker',
				stdin=asyncio.subprocess.PIPE,
				stdout=asyncio.subprocess.DEVNULL,
				stderr=asyncio.subprocess.DEVNULL,
				cwd=Path(__file__).resolve().parent.parent,
				env=environment,
				start_new_session=os.name != 'nt',
			)
			assert self.process.stdin is not None
			payload = {
				'config': config,
				'key': base64.b64encode(self.key).decode(),
				'data_dir': str(self.data_dir),
				'event_file': str(event_file),
				'run_id': run_id,
				'trigger': trigger,
			}
			self.process.stdin.write(json.dumps(payload).encode())
			await self.process.stdin.drain()
			self.process.stdin.close()
			if self.stopping:
				await self._terminate()
			while self.process.returncode is None:
				self._read_progress(event_file, run_id)
				try:
					await asyncio.wait_for(self.process.wait(), timeout=0.5)
				except TimeoutError:
					pass
			self._read_progress(event_file, run_id)
			progress = self._progress(event_file)
			terminal = progress.get('state')
			state = (
				'cancelled'
				if self.stopping
				else (
					'succeeded'
					if self.process.returncode == 0 and terminal == 'succeeded'
					else terminal
					if terminal in {'needs_attention', 'uncertain', 'failed'}
					else 'failed'
				)
			)
			if state != 'succeeded':
				self._record_interrupted_account(progress, config)
			summary = progress.get('summary') if isinstance(progress.get('summary'), dict) else None
			error = (
				None
				if state == 'succeeded'
				else (
					'任务已停止, 部分操作可能已完成, 请核对后再运行'
					if self.stopping
					else progress.get('error', '任务未正常完成, 请检查执行记录和配置')
				)
			)
			self.db.execute(
				'UPDATE runs SET state=?,finished_at=?,error=?,summary=? WHERE id=?',
				(state, time.time(), error, json.dumps(summary) if summary else None, run_id),
			)
		except asyncio.CancelledError:
			await self._terminate()
			self._record_interrupted_account(self._progress(event_file), config)
			self.db.execute(
				"UPDATE runs SET state='interrupted',finished_at=?,error='服务关闭, 请核对站点结果' WHERE id=?",
				(time.time(), run_id),
			)
			raise
		except Exception:
			await self._terminate()
			self._record_interrupted_account(self._progress(event_file), config)
			self.db.execute(
				"UPDATE runs SET state=?,finished_at=?,error='执行器启动或运行失败, 请核对后再运行' WHERE id=?",
				('cancelled' if self.stopping else 'failed', time.time(), run_id),
			)
		finally:
			self.db.commit()
			event_file.unlink(missing_ok=True)
			self.process = None
			self.active_id = None
			self.manual = None
			self.stopping = False

	def _progress(self, event_file: Path) -> dict:
		try:
			if event_file.stat().st_size > 1024 * 1024:
				return {}
			value = json.loads(event_file.read_text(encoding='utf-8'))
			return value if isinstance(value, dict) else {}
		except (OSError, ValueError):
			return {}

	def _read_progress(self, event_file: Path, run_id: int) -> None:
		progress = self._progress(event_file)
		state = 'stopping' if self.stopping else 'running'
		self.db.execute('UPDATE runs SET state=? WHERE id=?', (state, run_id))
		self.db.commit()

	def _record_interrupted_account(self, progress: dict, config: dict) -> None:
		account = next((item for item in config['accounts'] if item['id'] == progress.get('active_account')), None)
		if account is None:
			return
		state = ExecutionState(self.data_dir / 'webui.sqlite3')
		try:
			state.record(
				account['id'],
				account_binding(account, config),
				{'outcome': 'uncertain', 'reason': 'WORKER_INTERRUPTED_RESULT_UNKNOWN'},
			)
		finally:
			state.close()

	async def stop(self) -> bool:
		if self.active_id is None:
			return False
		self.stopping = True
		self.manual = None
		self.db.execute("UPDATE runs SET state='stopping' WHERE id=?", (self.active_id,))
		self.db.commit()
		await self._terminate()
		return True

	async def _terminate(self) -> None:
		process = self.process
		if process is None or process.returncode is not None:
			return
		try:
			if os.name == 'nt':
				await terminate_windows_tree(process)
				return
			process.terminate()
			await asyncio.wait_for(process.wait(), timeout=8)
		except ProcessLookupError:
			pass
		except TimeoutError:
			if os.name != 'nt':
				getattr(os, 'killpg')(process.pid, getattr(signal, 'SIGKILL'))
			else:
				killer = await asyncio.create_subprocess_exec(
					'taskkill',
					'/PID',
					str(process.pid),
					'/T',
					'/F',
					stdout=asyncio.subprocess.DEVNULL,
					stderr=asyncio.subprocess.DEVNULL,
				)
				await killer.wait()
			await process.wait()

	async def scheduler(self) -> None:
		while True:
			await asyncio.sleep(1)
			config, revision = self.config_store.load()
			next_at = self.db.execute('SELECT next_at FROM scheduler WHERE id=1').fetchone()[0]
			if not config['schedule']['enabled']:
				continue
			if next_at is None:
				self.schedule_changed()
			elif next_at <= time.time() and self.active_id is None:
				# Advance before starting: a restart or failure never creates a catch-up loop.
				self.schedule_changed()
				try:
					await self.start(revision, trigger='scheduled')
				except BusyError:
					pass

	async def open(self) -> None:
		config, _ = self.config_store.load()
		next_at = self.db.execute('SELECT next_at FROM scheduler WHERE id=1').fetchone()[0]
		if not config['schedule']['enabled'] or next_at is None or next_at <= time.time():
			self.schedule_changed()
		self._scheduler_task = asyncio.create_task(self.scheduler(), name='scheduler')

	async def close(self) -> None:
		if self._scheduler_task:
			self._scheduler_task.cancel()
			await asyncio.gather(self._scheduler_task, return_exceptions=True)
		if self.task and not self.task.done():
			self.task.cancel()
			await asyncio.gather(self.task, return_exceptions=True)
		self.db.close()
		if self._instance_lock:
			self._instance_lock.close()
