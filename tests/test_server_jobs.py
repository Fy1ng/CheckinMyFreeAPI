"""Local job orchestration tests; no browser, subprocess or notification is started."""

import asyncio
import base64
import json
import os
import sqlite3
import time
from unittest.mock import AsyncMock

import pytest

import server.jobs as jobs_module
from server.config_store import ConfigStore, default_config
from server.jobs import BusyError, JobManager, terminate_windows_tree


@pytest.fixture(autouse=True)
def fake_os_termination(monkeypatch):
	async def terminate(process):
		process.terminate()
		await process.wait()

	monkeypatch.setattr(jobs_module, 'terminate_windows_tree', terminate)


@pytest.mark.asyncio
async def test_windows_stop_targets_entire_worker_process_tree(monkeypatch):
	from types import SimpleNamespace

	process = SimpleNamespace(pid=987654, wait=AsyncMock(return_value=-1))
	killer = SimpleNamespace(wait=AsyncMock(return_value=0))
	launch = AsyncMock(return_value=killer)
	monkeypatch.setattr(jobs_module.asyncio, 'create_subprocess_exec', launch)
	await terminate_windows_tree(process)
	assert launch.await_args is not None
	assert launch.await_args.args == ('taskkill', '/PID', '987654', '/T', '/F')
	process.wait.assert_awaited_once()


class FakeInput:
	def __init__(self):
		self.data = bytearray()
		self.closed = False

	def write(self, data):
		self.data.extend(data)

	async def drain(self):
		return None

	def close(self):
		self.closed = True


async def test_balance_tasks_share_checkin_lock_and_snapshot_never_starts_network(
	configured_store, tmp_path, fake_worker
):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	process, launched, _ = fake_worker
	try:
		assert manager.balance_snapshot()['summary']['balance'] is None
		assert manager.history() == []
		run = await manager.start(1, kind='balance')
		assert run['kind'] == 'balance'
		await launched.wait()
		assert json.loads(bytes(process.stdin.data))['kind'] == 'balance'
		assert manager.balance_snapshot()['refreshing'] is True
		with pytest.raises(BusyError):
			await manager.start(1)
		with pytest.raises(BusyError):
			await manager.start(1, kind='balance')
	finally:
		await manager.close()
	assert store.load()[1] == 1


async def test_balance_restart_does_not_pause_account_as_an_unknown_write(configured_store, tmp_path):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	manager.db.execute(
		"INSERT INTO runs(state,started_at,revision,kind) VALUES ('running',?,1,'balance')", (time.time(),)
	)
	run_id = manager.db.execute('SELECT max(id) FROM runs').fetchone()[0]
	manager.db.commit()
	(tmp_path / f'run-{run_id}.json').write_text(json.dumps({'active_account': 'first'}))
	await manager.close()
	restarted = JobManager(store, tmp_path, key)
	try:
		assert restarted.status()['attention'] == {}
		assert restarted.history()[0]['state'] == 'interrupted'
	finally:
		await restarted.close()


@pytest.mark.asyncio
async def test_single_account_scope_filters_snapshot_without_changing_saved_config(
	configured_store, tmp_path, fake_worker
):
	store, key = configured_store
	config, revision = store.load()
	config['accounts'] += [
		{**config['accounts'][0], 'id': 'second', 'password': 'synthetic-second-password'},
		{**config['accounts'][0], 'id': 'disabled', 'enabled': False},
	]
	store.save(config, revision)
	manager = JobManager(store, tmp_path, key)
	process, launched, _ = fake_worker
	try:
		for account_id in ('missing', 'disabled'):
			with pytest.raises(BusyError):
				await manager.start(2, account_id=account_id)
		with pytest.raises(BusyError):
			await manager.start(1, account_id='second')
		assert manager.history() == []
		run = await manager.start(2, account_id='second')
		await launched.wait()
		payload = json.loads(bytes(process.stdin.data))
		assert payload['account_id'] == 'second'
		assert [account['id'] for account in payload['config']['accounts']] == ['second']
		assert 'synthetic-account-password' not in bytes(process.stdin.data).decode()
		assert len(store.load()[0]['accounts']) == 3 and store.load()[1] == 2
		assert run['summary']['account_id'] == 'second'
		assert run['summary']['progress'] == {'total': 1, 'completed': 0, 'active_account': None}
		with pytest.raises(BusyError):
			await manager.start(2)
		with pytest.raises(BusyError):
			await manager.start(2, account_id='first')
		assert len(manager.history()) == 1
	finally:
		await manager.close()


@pytest.mark.asyncio
async def test_running_progress_survives_refresh_and_invalid_event(configured_store, tmp_path, fake_worker):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	process, launched, _ = fake_worker
	try:
		run = await manager.start(1)
		await launched.wait()
		event_file = tmp_path / f'run-{run["id"]}.json'
		summary = {
			'accounts': [],
			'progress': {
				'total': 1,
				'completed': 0,
				'active_account': {'id': 'first', 'stage': 'checkin', 'method': 'POST', 'path': '/api/user/sign_in'},
			},
		}
		event_file.write_text(json.dumps({'state': 'running', 'active_account': 'first', 'summary': summary}))
		manager._read_progress(event_file, run['id'])
		assert manager.status()['run']['summary'] == summary
		assert manager.history()[0]['summary'] == summary
		event_file.write_text('{incomplete')
		manager._read_progress(event_file, run['id'])
		assert manager.history()[0]['summary'] == summary
		event_file.write_text(json.dumps({'state': 'failed', 'error': 'HTTP_WORKER_FAILED'}))
		process.finish(1)
		assert manager.task is not None
		await manager.task
		assert manager.history()[0]['summary'] == summary
		assert manager.history()[0]['state'] == 'failed'
	finally:
		await manager.close()


class FakeProcess:
	def __init__(self, returncode=None):
		self.stdin = FakeInput()
		self.returncode = returncode
		self.exited = asyncio.Event()
		self.terminated = 0
		self.killed = 0
		if returncode is not None:
			self.exited.set()

	async def wait(self):
		await self.exited.wait()
		return self.returncode

	def finish(self, returncode):
		self.returncode = returncode
		self.exited.set()

	def terminate(self):
		self.terminated += 1
		self.finish(-15)

	def kill(self):
		self.killed += 1
		self.finish(-9)


@pytest.fixture
def configured_store(tmp_path):
	key = os.urandom(32)
	store = ConfigStore(tmp_path / 'webui.sqlite3', key)
	config = default_config()
	config['accounts'] = [
		{
			'id': 'first',
			'provider': 'anyrouter',
			'auth_type': 'password',
			'username': 'synthetic-user',
			'password': 'synthetic-account-password',
		}
	]
	store.save(config, 0)
	yield store, key
	store.close()


@pytest.fixture
def fake_worker(monkeypatch):
	process = FakeProcess()
	launched = asyncio.Event()
	calls = []

	async def launch(*args, **kwargs):
		calls.append((args, kwargs))
		launched.set()
		return process

	monkeypatch.setattr(jobs_module.asyncio, 'create_subprocess_exec', launch)
	return process, launched, calls


@pytest.mark.asyncio
async def test_duplicate_job_is_rejected_until_worker_finishes(configured_store, tmp_path, fake_worker):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	process, launched, _ = fake_worker
	try:
		first = await manager.start(1)
		await launched.wait()
		with pytest.raises(BusyError):
			await manager.start(1)
		assert len(manager.history()) == 1
		assert manager.status()['running'] is True
		(tmp_path / f'run-{first["id"]}.json').write_text(
			json.dumps({'state': 'succeeded', 'summary': {'success_count': 1, 'total_count': 1}}), encoding='utf-8'
		)
		process.finish(0)
		assert manager.task is not None
		await manager.task
		assert manager.status()['running'] is False
		assert manager.history()[0]['state'] == 'succeeded'
		assert manager.history()[0]['finished_at'] is not None
	finally:
		await manager.close()


@pytest.mark.asyncio
async def test_stale_revision_rejected_and_snapshot_sent_privately(
	configured_store, tmp_path, fake_worker, monkeypatch
):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	process, launched, calls = fake_worker
	for name in ('CHECKIN_SERVER_PASSWORD', 'CHECKIN_PROXY_URL', 'EMAIL_PASS', 'HTTP_PROXY', 'HTTPS_PROXY'):
		monkeypatch.setenv(name, 'synthetic-parent-secret')
	parent_environment = dict(os.environ)
	try:
		with pytest.raises(BusyError):
			await manager.start(0)
		assert manager.history() == []
		run = await manager.start(1)
		await launched.wait()
		payload = json.loads(bytes(process.stdin.data))
		config, _ = store.load()
		config['accounts'][0]['password'] = 'synthetic-new-password'
		store.save(config, 1)
		assert run['revision'] == 1
		assert payload['config']['accounts'][0]['password'] == 'synthetic-account-password'
		assert store.load()[1] == 2
		assert base64.b64decode(payload['key']) == key
		assert payload['trigger'] == 'manual'
		assert 'manual_session' not in payload
		assert process.stdin.closed
		args, options = calls[0]
		assert args[1:] == ('-m', 'server.worker')
		assert options['stdin'] is asyncio.subprocess.PIPE
		assert options['stdout'] is asyncio.subprocess.DEVNULL
		assert options['stderr'] is asyncio.subprocess.DEVNULL
		assert 'synthetic-account-password' not in json.dumps(args)
		assert base64.b64encode(key).decode() not in json.dumps(args)
		for name in ('CHECKIN_SERVER_PASSWORD', 'CHECKIN_PROXY_URL', 'EMAIL_PASS', 'HTTP_PROXY', 'HTTPS_PROXY'):
			assert name not in options['env']
		assert dict(os.environ) == parent_environment
	finally:
		await manager.close()


@pytest.mark.asyncio
async def test_stop_revokes_manual_access_and_finalizes_cancelled(configured_store, tmp_path, fake_worker):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	process, launched, _ = fake_worker
	try:
		run = await manager.start(1)
		await launched.wait()
		event_file = tmp_path / f'run-{run["id"]}.json'
		event_file.write_text(
			json.dumps(
				{'state': 'running', 'manual': {'url': 'http://127.0.0.1:1234', 'session': 'synthetic-session'}}
			),
			encoding='utf-8',
		)
		manager._read_progress(event_file, run['id'])
		assert manager.history()[0]['state'] == 'running'
		assert 'manual_url' not in manager.status()['run']
		assert 'synthetic-session' not in json.dumps(manager.status())
		assert await manager.stop() is True
		assert manager.manual is None
		assert 'manual_url' not in manager.status()['run']
		assert manager.task is not None
		await manager.task
		assert manager.history()[0]['state'] == 'cancelled'
		assert manager.history()[0]['finished_at'] is not None
		assert manager.active_id is None
		assert not event_file.exists()
		assert process.terminated == 1
		assert await manager.stop() is False
	finally:
		await manager.close()


@pytest.mark.asyncio
async def test_interrupted_account_is_paused_until_explicit_resolution(configured_store, tmp_path, fake_worker):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	process, launched, _ = fake_worker
	try:
		run = await manager.start(1)
		await launched.wait()
		(tmp_path / f'run-{run["id"]}.json').write_text(json.dumps({'state': 'running', 'active_account': 'first'}))
		assert await manager.stop() is True
		assert manager.task is not None
		await manager.task
		assert manager.status()['attention']['first']['outcome'] == 'uncertain'
		manager.resolve_attention('first', 1)
		assert manager.status()['attention'] == {}
	finally:
		await manager.close()


@pytest.mark.asyncio
async def test_service_close_interrupts_running_worker_and_clears_manual(configured_store, tmp_path, fake_worker):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	process, launched, _ = fake_worker
	run = await manager.start(1)
	await launched.wait()
	manager.manual = {'url': 'http://127.0.0.1:1234', 'session': 'synthetic-session'}
	await manager.close()
	assert process.terminated == 1
	assert manager.manual is None
	assert manager.active_id is None
	with sqlite3.connect(tmp_path / 'webui.sqlite3') as db:
		state, finished = db.execute('SELECT state,finished_at FROM runs WHERE id=?', (run['id'],)).fetchone()
	assert state == 'interrupted'
	assert finished is not None


@pytest.mark.asyncio
async def test_stop_during_process_launch_terminates_late_worker(configured_store, tmp_path, monkeypatch):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	entered_launch = asyncio.Event()
	continue_launch = asyncio.Event()
	process = FakeProcess()

	async def launch(*args, **kwargs):
		entered_launch.set()
		await continue_launch.wait()
		return process

	monkeypatch.setattr(jobs_module.asyncio, 'create_subprocess_exec', launch)
	try:
		await manager.start(1)
		await entered_launch.wait()
		assert manager.process is None
		assert await manager.stop() is True
		assert manager.history()[0]['state'] == 'stopping'
		continue_launch.set()
		assert manager.task is not None
		await manager.task
		assert process.terminated == 1
		assert manager.history()[0]['state'] == 'cancelled'
		assert manager.active_id is None
		assert manager.manual is None
	finally:
		await manager.close()


@pytest.mark.asyncio
async def test_failed_launch_releases_slot_and_next_job_can_succeed(configured_store, tmp_path, monkeypatch):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	launch = AsyncMock(side_effect=OSError('synthetic launch failure with secret'))
	monkeypatch.setattr(jobs_module.asyncio, 'create_subprocess_exec', launch)
	try:
		await manager.start(1)
		assert manager.task is not None
		await manager.task
		assert manager.history()[0]['state'] == 'failed'
		assert manager.status()['running'] is False
		assert 'synthetic launch failure with secret' not in manager.history()[0]['error']

		async def succeed(*args, **kwargs):
			(tmp_path / f'run-{manager.active_id}.json').write_text(
				json.dumps({'state': 'succeeded'}), encoding='utf-8'
			)
			return FakeProcess(0)

		monkeypatch.setattr(jobs_module.asyncio, 'create_subprocess_exec', succeed)
		await manager.start(1)
		assert manager.task is not None
		await manager.task
		assert [run['state'] for run in manager.history()] == ['succeeded', 'failed']
	finally:
		await manager.close()


@pytest.mark.asyncio
async def test_competing_instance_cannot_rewrite_live_run_as_interrupted(configured_store, tmp_path):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	manager.db.execute("INSERT INTO runs(state,started_at,revision) VALUES ('running',?,1)", (time.time(),))
	manager.db.commit()
	try:
		with pytest.raises(BusyError):
			JobManager(store, tmp_path, key)
		assert manager.history()[0]['state'] == 'running'
		assert manager.history()[0]['finished_at'] is None
	finally:
		await manager.close()
	# An actual restart, after acquiring the released lock, marks the orphaned run.
	restarted = JobManager(store, tmp_path, key)
	try:
		assert restarted.history()[0]['state'] == 'interrupted'
		assert restarted.history()[0]['finished_at'] is not None
	finally:
		await restarted.close()


@pytest.mark.asyncio
async def test_restart_pauses_inflight_account_before_scheduler_can_repeat(configured_store, tmp_path):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	manager.db.execute(
		"INSERT INTO runs(state,started_at,revision,kind) VALUES ('running',?,1,'checkin')", (time.time(),)
	)
	run_id = manager.db.execute('SELECT max(id) FROM runs').fetchone()[0]
	manager.db.commit()
	(tmp_path / f'run-{run_id}.json').write_text(json.dumps({'active_account': 'first'}))
	await manager.close()
	restarted = JobManager(store, tmp_path, key)
	try:
		assert restarted.status()['attention']['first']['outcome'] == 'uncertain'
		assert restarted.history()[0]['state'] == 'interrupted'
	finally:
		await restarted.close()


def one_scheduler_tick(monkeypatch):
	calls = 0

	async def tick(_delay):
		nonlocal calls
		calls += 1
		if calls > 1:
			raise asyncio.CancelledError

	monkeypatch.setattr(jobs_module.asyncio, 'sleep', tick)


async def test_balance_schedule_runs_independently_with_checkin_disabled(configured_store, tmp_path, monkeypatch):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	manager.db.execute('UPDATE balance_scheduler SET next_at=? WHERE id=1', (time.time() - 10,))
	manager.db.commit()
	start = AsyncMock()
	monkeypatch.setattr(manager, 'start', start)
	one_scheduler_tick(monkeypatch)
	try:
		with pytest.raises(asyncio.CancelledError):
			await manager.scheduler()
		start.assert_awaited_once_with(1, trigger='scheduled', kind='balance')
		assert manager.balance_snapshot()['next_refresh_at'] is not None
		assert manager.status()['next_run_at'] is None
	finally:
		await manager.close()


async def test_checkin_advancement_cannot_postpone_due_balance_collection(configured_store, tmp_path, monkeypatch):
	store, key = configured_store
	config, revision = store.load()
	config['schedule'].update(enabled=True, interval_minutes=30)
	revision = store.save(config, revision)['revision']
	manager = JobManager(store, tmp_path, key)
	balance_due = time.time() - 5
	manager.db.execute('UPDATE scheduler SET next_at=? WHERE id=1', (time.time() - 10,))
	manager.db.execute('UPDATE balance_scheduler SET next_at=? WHERE id=1', (balance_due,))
	manager.db.commit()

	async def start_checkin(*args, **kwargs):
		manager.active_id = 123

	start = AsyncMock(side_effect=start_checkin)
	monkeypatch.setattr(manager, 'start', start)
	one_scheduler_tick(monkeypatch)
	try:
		with pytest.raises(asyncio.CancelledError):
			await manager.scheduler()
		start.assert_awaited_once_with(revision, trigger='scheduled')
		assert manager.db.execute('SELECT next_at FROM balance_scheduler WHERE id=1').fetchone()[0] == balance_due
	finally:
		manager.active_id = None
		await manager.close()


@pytest.mark.asyncio
async def test_scheduler_is_disabled_by_default(configured_store, tmp_path, monkeypatch):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	start = AsyncMock()
	monkeypatch.setattr(manager, 'start', start)
	one_scheduler_tick(monkeypatch)
	try:
		with pytest.raises(asyncio.CancelledError):
			await manager.scheduler()
		start.assert_not_awaited()
		assert manager.status()['next_run_at'] is None
	finally:
		await manager.close()


@pytest.mark.asyncio
async def test_restart_does_not_execute_overdue_schedule(configured_store, tmp_path, monkeypatch):
	store, key = configured_store
	config, revision = store.load()
	config['schedule']['enabled'] = True
	store.save(config, revision)
	previous = JobManager(store, tmp_path, key)
	previous.db.execute('UPDATE scheduler SET next_at=? WHERE id=1', (time.time() - 86400,))
	previous.db.commit()
	await previous.close()
	restarted = JobManager(store, tmp_path, key)
	start = AsyncMock()
	monkeypatch.setattr(restarted, 'start', start)
	one_scheduler_tick(monkeypatch)
	try:
		await restarted.open()
		assert restarted._scheduler_task is not None
		with pytest.raises(asyncio.CancelledError):
			await restarted._scheduler_task
		start.assert_not_awaited()
		assert restarted.db.execute('SELECT next_at FROM scheduler WHERE id=1').fetchone()[0] > time.time()
	finally:
		await restarted.close()


@pytest.mark.asyncio
async def test_due_schedule_advances_before_busy_failure(configured_store, tmp_path, monkeypatch):
	store, key = configured_store
	config, revision = store.load()
	config['schedule']['enabled'] = True
	current_revision = store.save(config, revision)['revision']
	manager = JobManager(store, tmp_path, key)
	manager.db.execute('UPDATE scheduler SET next_at=? WHERE id=1', (time.time() - 10,))
	manager.db.commit()
	start = AsyncMock(side_effect=BusyError('synthetic busy race'))
	monkeypatch.setattr(manager, 'start', start)
	one_scheduler_tick(monkeypatch)
	try:
		with pytest.raises(asyncio.CancelledError):
			await manager.scheduler()
		start.assert_awaited_once_with(current_revision, trigger='scheduled')
		assert manager.db.execute('SELECT next_at FROM scheduler WHERE id=1').fetchone()[0] > time.time()
	finally:
		await manager.close()


@pytest.mark.asyncio
async def test_untrusted_or_oversized_progress_does_not_crash_job_manager(configured_store, tmp_path):
	store, key = configured_store
	manager = JobManager(store, tmp_path, key)
	path = tmp_path / 'run-progress.json'
	try:
		assert manager._progress(path) == {}
		for value in ('{invalid', '[]', 'x' * (1024 * 1024 + 1)):
			path.write_text(value, encoding='utf-8')
			assert manager._progress(path) == {}
	finally:
		await manager.close()
