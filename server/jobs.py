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

from server.automation_store import AutomationStore
from server.balance_store import BalanceStore, day_at
from server.execution_state import ExecutionState
from utils.cron_schedule import CronSchedule, next_daily_time
from utils.http_checkin import account_binding
from utils.process_env import child_environment


class BusyError(RuntimeError):
	pass


def iso_time(timestamp: float | None) -> str | None:
	return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp is not None else None


def acquire_file_lock(path: Path) -> BinaryIO:
	stream = path.open('a+b')
	try:
		if sys.platform == 'win32':
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
		CREATE TABLE IF NOT EXISTS balance_scheduler (id INTEGER PRIMARY KEY CHECK(id=1), next_at REAL);
		INSERT OR IGNORE INTO balance_scheduler VALUES (1, NULL);
		""")
		columns = {column[1] for column in self.db.execute('PRAGMA table_info(runs)')}
		if 'kind' not in columns:
			self.db.execute("ALTER TABLE runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'checkin'")
		if 'identity' not in columns:
			self.db.execute('ALTER TABLE runs ADD COLUMN identity TEXT')
		config, _ = self.config_store.load()
		self._checkin_signature = json.dumps(config['schedule'], sort_keys=True)
		self._balance_signature = self._monitoring_signature(config)
		automation = AutomationStore(self.data_dir / 'webui.sqlite3')
		automation.interrupt_pending()
		automation.close()
		for run_id, kind in self.db.execute(
			"SELECT id,kind FROM runs WHERE state IN ('running','awaiting_login','stopping')"
		).fetchall():
			if kind == 'checkin':
				self._record_interrupted_account(self._progress(self.data_dir / f'run-{run_id}.json'), config)
		self.db.execute(
			"UPDATE runs SET state='interrupted',finished_at=?,error=CASE WHEN kind='balance' THEN '服务重启, 余额刷新已中断' WHEN kind='summary' THEN '服务重启, 请核对日报通知记录' ELSE '服务重启, 请核对站点结果后再运行' END WHERE state IN ('running','awaiting_login','stopping')",
			(time.time(),),
		)
		self.db.commit()
		self.task: asyncio.Task | None = None
		self.process: asyncio.subprocess.Process | None = None
		self.active_id: int | None = None
		self.active_kind: str | None = None
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

	def balance_snapshot(self) -> dict:
		config, _ = self.config_store.load()
		store = BalanceStore(self.data_dir / 'webui.sqlite3')
		try:
			result = store.snapshot(config)
		finally:
			store.close()
		health = self.automation_snapshot()['health']
		for account in result['accounts']:
			account['health'] = {item['scope']: item for item in health if item['account_id'] == account['id']}
		return {
			**result,
			'refreshing': self.active_id is not None,
			'next_refresh_at': iso_time(
				self.db.execute('SELECT next_at FROM balance_scheduler WHERE id=1').fetchone()[0]
			),
		}

	def automation_snapshot(self) -> dict:
		config, _ = self.config_store.load()
		store = AutomationStore(self.data_dir / 'webui.sqlite3')
		try:
			return store.snapshot(config)
		finally:
			store.close()

	@staticmethod
	def _monitoring_signature(config: dict) -> str:
		return json.dumps(
			[config['monitoring'], any(account['enabled'] for account in config['accounts'])], sort_keys=True
		)

	def summary_schedule_changed(self) -> None:
		config, _ = self.config_store.load()
		settings = config['automation']['daily_summary']
		signature = json.dumps(settings, sort_keys=True)
		row = self.db.execute('SELECT signature,next_at FROM automation_scheduler WHERE id=1').fetchone()
		if row[0] != signature or (settings['enabled'] and row[1] is None):
			self.db.execute(
				'UPDATE automation_scheduler SET signature=?,next_at=? WHERE id=1',
				(signature, next_daily_time(settings['time'], time.time()) if settings['enabled'] else None),
			)
			self.db.commit()

	def balance_schedule_changed(self) -> None:
		config, _ = self.config_store.load()
		monitoring = config['monitoring']
		next_at = (
			time.time() + monitoring['interval_minutes'] * 60
			if monitoring['enabled'] and any(account['enabled'] for account in config['accounts'])
			else None
		)
		self.db.execute('UPDATE balance_scheduler SET next_at=? WHERE id=1', (next_at,))
		self.db.commit()
		self._balance_signature = self._monitoring_signature(config)

	def schedule_changed(self, *, include_balance: bool = True) -> None:
		config, _ = self.config_store.load()
		schedule = config['schedule']
		signature = json.dumps(schedule, sort_keys=True)
		if not include_balance or signature != self._checkin_signature:
			next_at = None
			if schedule['enabled']:
				next_at = (
					CronSchedule(schedule['cron']).next_after(time.time())
					if schedule['mode'] == 'cron'
					else time.time() + schedule['interval_minutes'] * 60
				)
			self.db.execute('UPDATE scheduler SET next_at=? WHERE id=1', (next_at,))
			self.db.commit()
			self._checkin_signature = signature
		if include_balance and self._monitoring_signature(config) != self._balance_signature:
			self.balance_schedule_changed()
		self.summary_schedule_changed()

	async def start_summary(self, revision: int) -> dict:
		return await self.start(revision, kind='summary')

	async def start(
		self,
		revision: int,
		*,
		trigger: str = 'manual',
		account_id: str | None = None,
		kind: str = 'checkin',
		summary_day: str | None = None,
	) -> dict:
		async with self._lock:
			if self.active_id is not None:
				raise BusyError('已有任务运行, 请等待完成或先停止')
			config, current_revision = self.config_store.load()
			if current_revision != revision:
				raise BusyError('配置已更新, 请重新读取后运行')
			if trigger not in {'manual', 'scheduled'}:
				raise BusyError('任务来源无效')
			if kind not in {'checkin', 'balance', 'summary'}:
				raise BusyError('任务类型无效')
			if account_id is not None:
				if not isinstance(account_id, str) or trigger != 'manual' or kind == 'summary':
					raise BusyError('单账号任务参数无效')
				selected = next((account for account in config['accounts'] if account['id'] == account_id), None)
				if selected is None or not selected.get('enabled', True):
					raise BusyError('请选择已保存且已启用的账号')
				config['accounts'] = [selected]
			if kind != 'summary' and not any(account.get('enabled', True) for account in config['accounts']):
				raise BusyError('请先保存至少一个已启用账号')
			summary: dict = {
				'account_id': account_id,
				'accounts': [],
				'progress': {
					'total': sum(account.get('enabled', True) for account in config['accounts']),
					'completed': 0,
					'active_account': None,
				},
			}
			cursor = self.db.execute(
				"INSERT INTO runs(state,started_at,revision,kind,identity,summary) VALUES ('running',?,?,?,?,?)",
				(time.time(), revision, kind, None, json.dumps(summary)),
			)
			self.db.commit()
			assert cursor.lastrowid is not None
			self.active_id = cursor.lastrowid
			self.active_kind = kind
			self.stopping = False
			self.task = asyncio.create_task(
				self._execute(
					self.active_id, config, trigger=trigger, account_id=account_id, kind=kind, summary_day=summary_day
				),
				name=kind + '-worker',
			)
			return self.history()[0]

	async def _execute(
		self,
		run_id: int,
		config: dict,
		*,
		trigger: str = 'manual',
		account_id: str | None = None,
		kind: str = 'checkin',
		summary_day: str | None = None,
	) -> None:
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
			# Backup recovery credentials are unrelated to account execution or notifications.
			worker_config = {**config, 'backups': {**config['backups'], 'enabled': False, 'password': str()}}
			payload = {
				'config': worker_config,
				'key': base64.b64encode(self.key).decode(),
				'data_dir': str(self.data_dir),
				'event_file': str(event_file),
				'run_id': run_id,
				'trigger': trigger,
				'account_id': account_id,
				'kind': kind,
				'summary_day': summary_day,
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
			if state != 'succeeded' and kind == 'checkin':
				self._record_interrupted_account(progress, config)
			summary = (
				progress.get('summary') if isinstance(progress.get('summary'), dict) else self.history()[0]['summary']
			)
			error = (
				None
				if state == 'succeeded'
				else (
					(
						'余额刷新已停止'
						if kind == 'balance'
						else '日报通知已停止, 请核对通知记录'
						if kind == 'summary'
						else '任务已停止, 部分操作可能已完成, 请核对后再运行'
					)
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
			if kind == 'checkin':
				self._record_interrupted_account(self._progress(event_file), config)
			self.db.execute(
				"UPDATE runs SET state='interrupted',finished_at=?,error=? WHERE id=?",
				(
					time.time(),
					'服务关闭, 余额刷新已中断'
					if kind == 'balance'
					else '服务关闭, 请核对日报通知记录'
					if kind == 'summary'
					else '服务关闭, 请核对站点结果',
					run_id,
				),
			)
			raise
		except Exception:
			await self._terminate()
			if kind == 'checkin':
				self._record_interrupted_account(self._progress(event_file), config)
			self.db.execute(
				'UPDATE runs SET state=?,finished_at=?,error=? WHERE id=?',
				(
					'cancelled' if self.stopping else 'failed',
					time.time(),
					'余额执行器启动或运行失败'
					if kind == 'balance'
					else '日报执行器启动或运行失败, 请核对通知记录'
					if kind == 'summary'
					else '执行器启动或运行失败, 请核对后再运行',
					run_id,
				),
			)
		finally:
			self.db.commit()
			automation = AutomationStore(self.data_dir / 'webui.sqlite3')
			automation.interrupt_pending(run_id)
			automation.close()
			event_file.unlink(missing_ok=True)
			self.process = None
			self.active_id = None
			self.active_kind = None
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
		if isinstance(progress.get('summary'), dict):
			self.db.execute(
				'UPDATE runs SET state=?,summary=? WHERE id=?', (state, json.dumps(progress['summary']), run_id)
			)
		else:
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
			if config['schedule']['enabled'] and next_at is None:
				self.schedule_changed(include_balance=False)
			elif (
				config['schedule']['enabled']
				and next_at is not None
				and next_at <= time.time()
				and self.active_id is None
			):
				# Advance before starting: a restart or failure never creates a catch-up loop.
				self.schedule_changed(include_balance=False)
				try:
					await self.start(revision, trigger='scheduled')
				except BusyError:
					pass
			balance_at = self.db.execute('SELECT next_at FROM balance_scheduler WHERE id=1').fetchone()[0]
			if config['monitoring']['enabled'] and any(account['enabled'] for account in config['accounts']):
				if balance_at is None:
					self.balance_schedule_changed()
				elif balance_at <= time.time() and self.active_id is None:
					self.balance_schedule_changed()
					try:
						await self.start(revision, trigger='scheduled', kind='balance')
					except BusyError:
						pass
			self.summary_schedule_changed()
			summary_at = self.db.execute('SELECT next_at FROM automation_scheduler WHERE id=1').fetchone()[0]
			if summary_at is not None and summary_at <= time.time() and self.active_id is None:
				self.db.execute(
					'UPDATE automation_scheduler SET next_at=? WHERE id=1',
					(next_daily_time(config['automation']['daily_summary']['time'], time.time()),),
				)
				self.db.commit()
				try:
					await self.start(revision, trigger='scheduled', kind='summary', summary_day=day_at(summary_at))
				except BusyError:
					pass

	async def open(self) -> None:
		config, _ = self.config_store.load()
		next_at = self.db.execute('SELECT next_at FROM scheduler WHERE id=1').fetchone()[0]
		if not config['schedule']['enabled'] or next_at is None or next_at <= time.time():
			self.schedule_changed(include_balance=False)
		balance_at = self.db.execute('SELECT next_at FROM balance_scheduler WHERE id=1').fetchone()[0]
		if not config['monitoring']['enabled'] or balance_at is None or balance_at <= time.time():
			self.balance_schedule_changed()
		self.summary_schedule_changed()
		summary_at = self.db.execute('SELECT next_at FROM automation_scheduler WHERE id=1').fetchone()[0]
		if summary_at is not None and summary_at <= time.time():
			self.db.execute(
				'UPDATE automation_scheduler SET next_at=? WHERE id=1',
				(next_daily_time(config['automation']['daily_summary']['time'], time.time()),),
			)
			self.db.commit()
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
