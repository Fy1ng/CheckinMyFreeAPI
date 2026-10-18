"""Private subprocess adapter for the existing authentication runtime."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import signal
import sys
from pathlib import Path

from utils.manual_login import ManualTakeover
from utils.secure_state import atomic_write, remove_owned_tree


async def execute(payload: dict) -> int:
	config = payload['config']
	data_dir = Path(payload['data_dir'])
	event_file = Path(payload['event_file'])
	key = base64.b64decode(payload['key'])
	state_key = hmac.digest(key, b'checkin-server-login-state-v1', 'sha256')
	environment = {
		'ANYROUTER_ACCOUNTS': json.dumps(config['accounts']),
		'CHECKIN_IDENTITIES': json.dumps(config['identities']),
		'PROVIDERS': json.dumps(config['providers']),
		'CHECKIN_PROXY_URL': config['proxy_url'],
		'CHECKIN_STATE_KEY': base64.urlsafe_b64encode(state_key).decode(),
		'CHECKIN_AUTH_CACHE_FILE': str(data_dir / 'auth-cache' / 'auth-state.enc'),
		'CHECKIN_AUTH_ROOT': os.getenv('CHECKIN_AUTH_ROOT', str(data_dir / 'auth-live')),
		'CHECKIN_STATE_SCOPE': 'checkin-server-v1',
		'CHECKIN_SECURE_MODE': 'true',
		'CHECKIN_MANUAL_LOGIN': 'true',
		'CHECKIN_MANUAL_TRANSPORT': 'local',
		'CHECKIN_MANUAL_SESSION': payload['manual_session'],
		'CHECKIN_MANUAL_HEADLESS': str(config['browser']['headless']).lower(),
		'CHECKIN_REMOTE_PASSWORD': payload['manual_session'],
		'CHECKIN_HEADLESS': str(config['browser']['headless']).lower(),
		'CHECKIN_HUMANIZE': str(config['browser']['humanize']).lower(),
		'CHECKIN_WAIT_TIMEOUT_MS': str(config['browser']['wait_timeout_ms']),
		'CHECKIN_MANUAL_TIMEOUT_SECONDS': str(config['browser']['manual_timeout_seconds']),
		'CHECKIN_MANUAL_TOTAL_TIMEOUT_SECONDS': str(config['browser']['manual_total_timeout_seconds']),
		'DEBUG_MODE': 'false',
		'CLOAKBROWSER_AUTO_UPDATE': 'false',
	}
	environment.update(config['notifications'])
	os.environ.update(environment)
	import utils.auth_runtime as auth_module
	from server.config_store import build_app_config
	from utils.auth_runtime import AuthenticationRuntime
	from utils.config import AccountConfig
	from utils.logging_safety import install_redaction
	from utils.notify import notify

	install_redaction()
	progress: dict = {'state': 'running', 'manual': None}

	def publish(**updates):
		progress.update(updates)
		atomic_write(event_file, json.dumps(progress).encode())

	class LocalTakeover(ManualTakeover):
		async def __aenter__(self):
			await super().__aenter__()
			manual = {
				'transport': self.transport,
				'deadline': asyncio.get_running_loop().time() + self.timeout,
			}
			if self.transport == 'remote':
				manual.update(url=self.url, session=payload['manual_session'])
			publish(manual=manual)
			return self

		async def __aexit__(self, *args):
			try:
				await super().__aexit__(*args)
			finally:
				publish(manual=None)

	setattr(auth_module, 'ManualTakeover', LocalTakeover)
	accounts = [AccountConfig.from_dict(account, index) for index, account in enumerate(config['accounts'])]
	root = Path(environment['CHECKIN_AUTH_ROOT'])
	for directory in (root / 'live', root / 'saved'):
		remove_owned_tree(directory, root)

	async def notify_ready(url: str, account_name: str, timeout: int):
		instructions = '请在本机已打开的 Chromium 中完成登录' if not url else '请通过已登录的 WebUI 打开当前任务'
		await asyncio.to_thread(
			notify.push_message,
			'签到需要人工登录',
			f'{account_name} 需要人工登录. {instructions}, 剩余约 {timeout} 秒.',
			msg_type='text',
		)

	runtime = AuthenticationRuntime.from_environment(accounts, build_app_config(config), notify_ready=notify_ready)
	results: list[dict | None] = [None] * len(accounts)
	from utils.oauth import AuthError, ManualLoginRequired

	async def run(index, allow_manual):
		account = accounts[index]
		try:
			success, before, after = await runtime.execute(account, index, allow_manual=allow_manual)
			results[index] = {
				'id': account.id,
				'name': account.name,
				'success': bool(success),
				'balance': after.get('quota') if after else None,
			}
		except ManualLoginRequired:
			results[index] = {
				'id': account.id,
				'name': account.name,
				'success': False,
				'error': 'MANUAL_LOGIN_REQUIRED' if allow_manual else 'MANUAL_LOGIN_REQUIRES_HEADED_BROWSER',
			}
		except Exception as error:
			results[index] = {
				'id': account.id,
				'name': account.name,
				'success': False,
				'error': error.reason if isinstance(error, AuthError) else type(error).__name__,
			}

	publish()
	try:
		for index in range(len(accounts)):
			await run(index, not config['browser']['headless'])
	finally:
		runtime.close()
	summary = {
		'accounts': results,
		'success_count': sum(bool(result and result['success']) for result in results),
		'total_count': len(accounts),
	}
	success = summary['success_count'] == len(accounts)
	fingerprint = hashlib.sha256(json.dumps(results, sort_keys=True).encode()).hexdigest()
	previous = data_dir / 'balance-fingerprint.txt'
	changed = not previous.exists() or previous.read_text().strip() != fingerprint
	if not success or changed:
		try:
			await asyncio.to_thread(
				notify.push_message,
				'签到执行结果',
				f'成功 {summary["success_count"]}/{len(accounts)}. 请在 WebUI 查看执行记录.',
				msg_type='text',
			)
		except Exception:
			summary['notification_error'] = True
	atomic_write(previous, fingerprint.encode())
	publish(
		state='succeeded' if success else 'failed',
		summary=summary,
		error=None if success else '部分账号未完成, 请查看执行记录',
		manual=None,
	)
	return 0 if success else 1


async def main(payload: dict) -> int:
	task = asyncio.current_task()
	if os.name != 'nt' and task:
		asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
	try:
		return await execute(payload)
	except asyncio.CancelledError:
		return 130
	except Exception as error:
		atomic_write(
			Path(payload['event_file']),
			json.dumps({'state': 'failed', 'manual': None, 'error': '执行失败: ' + type(error).__name__}).encode(),
		)
		return 1


if __name__ == '__main__':
	request = json.loads(sys.stdin.buffer.read(1024 * 1024 + 1))
	# A worker can outlive an abruptly killed parent. This lock prevents a new
	# service instance from executing the same accounts concurrently with it.
	from server.jobs import acquire_file_lock

	try:
		execution_lock = acquire_file_lock(Path(request['data_dir']) / 'execution.lock')
	except RuntimeError:
		raise SystemExit(2) from None
	try:
		raise SystemExit(asyncio.run(main(request)))
	finally:
		execution_lock.close()
