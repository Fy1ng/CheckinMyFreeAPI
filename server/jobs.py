"""One isolated worker at a time, with persistent run history and scheduling."""

from __future__ import annotations

import asyncio
import base64
import copy
import json
import math
import os
import secrets
import signal
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from utils.manual_login import child_environment
from utils.secure_state import remove_owned_tree


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
	"""Terminate the worker and its Chromium/driver descendants together."""
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
	def __init__(self, config_store, data_dir: Path, key: bytes):
		self.config_store = config_store
		self.data_dir = data_dir.resolve()
		self.key = key
		self._instance_lock: BinaryIO | None = None
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
		manual = self.manual if self.active_id is not None and not self.stopping else None
		remaining = None
		if manual and isinstance(manual.get('deadline'), (int, float)):
			remaining = max(0, math.ceil(manual['deadline'] - time.monotonic()))
			if remaining == 0:
				manual = None
		transport = manual.get('transport', 'remote') if manual else None
		if run is not None:
			run = dict(
				run,
				manual_url=f'/manual/{run["id"]}/'
				if manual and transport == 'remote' and self.active_id == run['id']
				else None,
				manual_transport=transport,
				manual_remaining_seconds=remaining,
			)
		return {
			'running': self.active_id is not None,
			'run': run,
			'next_run_at': iso_time(self.db.execute('SELECT next_at FROM scheduler WHERE id=1').fetchone()[0]),
			'platform': {
				'manual_supported': sys.platform == 'win32' or (sys.platform == 'linux' and bool(os.getenv('DISPLAY'))),
				'manual_mode': 'desktop'
				if sys.platform == 'win32'
				else ('remote' if sys.platform == 'linux' and os.getenv('DISPLAY') else None),
			},
		}

	def schedule_changed(self) -> None:
		config, _ = self.config_store.load()
		schedule = config['schedule']
		next_at = time.time() + schedule['interval_minutes'] * 60 if schedule['enabled'] else None
		self.db.execute('UPDATE scheduler SET next_at=? WHERE id=1', (next_at,))
		self.db.commit()

	async def start(self, revision: int) -> dict:
		return await self._start(revision, kind='checkin')

	async def start_identity(self, identity: str, revision: int) -> dict:
		return await self._start(revision, kind='identity_login', identity=identity)

	async def _start(self, revision: int, *, kind: str, identity: str | None = None) -> dict:
		async with self._lock:
			if self.active_id is not None:
				raise BusyError('已有任务运行, 请等待完成或先停止')
			config, current_revision = self.config_store.load()
			if current_revision != revision:
				raise BusyError('配置已更新, 请重新读取后运行')
			if kind == 'identity_login':
				if not isinstance(identity, str) or identity not in config['identities']:
					raise BusyError('请选择已保存的登录身份')
				config = copy.deepcopy(config)
				config['browser']['headless'] = False
			elif not config['accounts']:
				raise BusyError('请先保存至少一个账号')
			cursor = self.db.execute(
				"INSERT INTO runs(state,started_at,revision,kind,identity) VALUES ('running',?,?,?,?)",
				(time.time(), revision, kind, identity),
			)
			self.db.commit()
			assert cursor.lastrowid is not None
			self.active_id = cursor.lastrowid
			self.stopping = False
			self.task = asyncio.create_task(self._execute(self.active_id, config), name='checkin-worker')
			return self.history()[0]

	async def _execute(self, run_id: int, config: dict) -> None:
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
			for name in ('CLOAKBROWSER_BINARY_PATH', 'NOVNC_WEB_ROOT', 'CHECKIN_AUTH_ROOT'):
				if os.getenv(name):
					environment[name] = os.environ[name]
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
				'manual_session': secrets.token_urlsafe(32),
			}
			kind, identity = self.db.execute('SELECT kind,identity FROM runs WHERE id=?', (run_id,)).fetchone()
			payload.update(kind=kind, identity=identity)
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
			state = (
				'cancelled'
				if self.stopping
				else (
					'succeeded' if self.process.returncode == 0 and progress.get('state') == 'succeeded' else 'failed'
				)
			)
			summary = progress.get('summary') if isinstance(progress.get('summary'), dict) else None
			error = (
				None
				if state == 'succeeded'
				else (
					'任务已停止, 部分操作可能已完成, 请核对后再运行'
					if self.stopping
					else progress.get('error', '任务未正常完成, 请检查浏览器依赖和配置')
				)
			)
			self.db.execute(
				'UPDATE runs SET state=?,finished_at=?,error=?,summary=? WHERE id=?',
				(state, time.time(), error, json.dumps(summary) if summary else None, run_id),
			)
		except asyncio.CancelledError:
			await self._terminate()
			self.db.execute(
				"UPDATE runs SET state='interrupted',finished_at=?,error='服务关闭, 请核对站点结果' WHERE id=?",
				(time.time(), run_id),
			)
			raise
		except Exception:
			await self._terminate()
			self.db.execute(
				"UPDATE runs SET state=?,finished_at=?,error='执行器启动或运行失败, 请核对后再运行' WHERE id=?",
				('cancelled' if self.stopping else 'failed', time.time(), run_id),
			)
		finally:
			if (
				self.stopping
				and event_file.exists()
				and self.process is not None
				and self.process.returncode is not None
			):
				root = Path(os.getenv('CHECKIN_AUTH_ROOT', str(self.data_dir / 'auth-live')))
				try:
					for directory in (root / 'live', root / 'saved'):
						remove_owned_tree(directory, root)
				except (OSError, RuntimeError):
					self.db.execute(
						"UPDATE runs SET error='任务已停止, 临时认证文件清理失败, 请检查数据目录' WHERE id=?", (run_id,)
					)
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
		manual = progress.get('manual')
		self.manual = manual if isinstance(manual, dict) else None
		state = 'stopping' if self.stopping else ('awaiting_login' if self.manual else 'running')
		self.db.execute('UPDATE runs SET state=? WHERE id=?', (state, run_id))
		self.db.commit()

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
					await self.start(revision)
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
