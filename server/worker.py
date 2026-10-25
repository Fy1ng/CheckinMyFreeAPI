"""Isolated, serial HTTP-only check-in worker with durable attention states."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import os
import signal
import sys
import time
from pathlib import Path
from urllib.parse import quote

from server.balance_store import BalanceStore
from server.config_store import validate_config
from server.execution_state import ExecutionState
from server.http_session_store import HttpSessionStore
from utils.http_checkin import HttpCheckinRuntime, account_binding
from utils.secure_state import atomic_write


async def execute(payload: dict) -> int:
	config = validate_config(payload['config'])
	kind = payload.get('kind', 'checkin')
	if kind not in {'checkin', 'balance'}:
		raise ValueError('Unsupported task kind')
	trigger = payload.get('trigger', 'manual')
	if trigger not in {'manual', 'scheduled'}:
		raise ValueError('Unsupported trigger')
	account_id = payload.get('account_id')
	accounts = config['accounts']
	if account_id is not None:
		if not isinstance(account_id, str) or trigger != 'manual':
			raise ValueError('Invalid single-account task')
		accounts = [account for account in accounts if account['id'] == account_id and account.get('enabled', True)]
		if not accounts:
			raise ValueError('Single-account task requires an enabled saved account')
	data_dir = Path(payload['data_dir'])
	event_file = Path(payload['event_file'])
	key = base64.b64decode(payload['key'], validate=True)
	session_key = hmac.digest(key, b'newapi-http-sessions-v1', 'sha256')
	os.environ.update(config['notifications'])
	from utils.logging_safety import install_redaction
	from utils.notify import notify

	install_redaction()
	sessions = HttpSessionStore(data_dir / 'webui.sqlite3', session_key)
	attention = ExecutionState(data_dir / 'webui.sqlite3')
	balances = BalanceStore(data_dir / 'webui.sqlite3')
	runtime = HttpCheckinRuntime(config, sessions)
	results: list[dict] = []
	total = sum(account.get('enabled', True) for account in accounts)

	def publish(**updates):
		atomic_write(event_file, json.dumps(updates, ensure_ascii=False).encode())

	def snapshot(active=None):
		return {
			'accounts': results,
			'account_id': account_id,
			'success_count': sum(bool(result['success']) for result in results),
			'total_count': total,
			'progress': {
				'total': total,
				'completed': sum(result['reason'] != 'ACCOUNT_DISABLED' for result in results),
				'active_account': active,
			},
		}

	publish(state='running', active_account=None, summary=snapshot())
	try:
		for account in accounts:
			base = {name: account.get(name, '') for name in ('id', 'name', 'provider')}
			binding = account_binding(account, config)
			previous = attention.get(account['id'], binding)
			if not account.get('enabled', True):
				results.append({**base, 'success': False, 'outcome': 'skipped', 'reason': 'ACCOUNT_DISABLED'})
				publish(state='running', active_account=None, summary=snapshot())
				continue
			retry_at = previous.get('retry_at') if previous else None
			balance_retry = balances.retry_at(account, config)
			if balance_retry and balance_retry > time.time():
				retry_at = max(retry_at or 0, balance_retry)
				limited_balance = True
			else:
				limited_balance = False
			limited = previous and previous['outcome'] == 'rate_limited' and retry_at and retry_at > time.time()
			paused = previous and (
				(kind == 'checkin' and previous['outcome'] == 'uncertain')
				or (trigger == 'scheduled' and previous['outcome'] not in {'rate_limited', 'uncertain'})
			)
			if limited_balance or (previous is not None and (limited or paused)):
				pending = {'outcome': 'rate_limited', 'reason': 'rate_limited'} if limited_balance else previous
				assert pending is not None
				results.append(
					{
						**base,
						'success': False,
						'outcome': 'skipped',
						'reason': 'ACCOUNT_PAUSED',
						'pending_outcome': pending['outcome'],
						'pending_reason': pending['reason'],
						**({'retry_after_seconds': max(1, int((retry_at or 0) - time.time()) + 1)} if limited else {}),
					}
				)
				if kind == 'balance':
					balances.failure(account, config, pending['outcome'], pending['reason'])
				publish(state='running', active_account=None, summary=snapshot())
				continue

			latest_event: dict = {}

			def report(event):
				latest_event.clear()
				latest_event.update(event)
				publish(state='running', active_account=account['id'], summary=snapshot({**base, **event}))

			report({'stage': 'prepare'})
			try:
				result = await (
					runtime.balance(account, on_progress=report)
					if kind == 'balance'
					else runtime.execute(account, on_progress=report)
				)
			except asyncio.CancelledError:
				if kind == 'checkin':
					attention.record(
						account['id'], binding, {'outcome': 'uncertain', 'reason': 'REQUEST_CANCELLED_RESULT_UNKNOWN'}
					)
				else:
					balances.failure(account, config, 'failed', 'balance_refresh_interrupted')
				raise
			except Exception:
				result = {
					**base,
					'success': False,
					'outcome': 'uncertain' if kind == 'checkin' else 'failed',
					'reason': 'HTTP_EXECUTION_FAILED_RESULT_UNKNOWN'
					if kind == 'checkin'
					else 'balance_collection_failed',
					'diagnostic': {**latest_event, 'error_type': 'ExecutionError'},
					'steps': [{**latest_event, 'state': 'failed', 'error_type': 'ExecutionError'}],
				}
			if kind == 'checkin':
				attention.record(account['id'], binding, result)
			if kind == 'balance' or config['monitoring']['enabled']:
				try:
					observations = getattr(runtime, 'balance_observations', [])
					for observation in observations:
						valid = balances.record(account, config, observation)
						if kind == 'balance' and not valid:
							result.update(success=False, outcome='failed', reason='invalid_balance_data')
					error = getattr(runtime, 'balance_error', None)
					if error is None and not result['success']:
						error = result
					if error:
						balances.failure(account, config, error['outcome'], error['reason'])
						if error['outcome'] == 'rate_limited':
							balances.rate_limit(account, config, error.get('retry_after_seconds', 3600))
				except Exception:
					# An auxiliary metrics write must never undo a confirmed check-in.
					if kind == 'balance':
						result.update(success=False, outcome='failed', reason='balance_storage_failed')
					else:
						result['balance_warning'] = 'balance_storage_failed'
			results.append(result)
			publish(state='running', active_account=None, summary=snapshot())
	finally:
		sessions.close()
		attention.close()
		balances.close()
	outcomes = {
		result.get('pending_outcome', result['outcome']) for result in results if result['reason'] != 'ACCOUNT_DISABLED'
	}
	success = bool(outcomes) and outcomes <= {'success', 'already_checked_in'}
	state = (
		'succeeded'
		if success
		else 'uncertain'
		if 'uncertain' in outcomes
		else 'needs_attention'
		if outcomes & {'needs_credentials', 'blocked', 'rate_limited'}
		else 'failed'
	)
	summary = {**snapshot(), 'trigger': trigger}
	if kind == 'balance':
		publish(
			state=state,
			active_account=None,
			summary=summary,
			error=None if success else '余额读取未全部完成, 请查看 Status',
		)
		return 0 if success else 1
	normalized = [
		{
			**result,
			'outcome': result.get('pending_outcome', result['outcome']),
			'reason': result.get('pending_reason', result['reason']),
		}
		for result in results
	]
	for result in normalized:
		result.pop('pending_outcome', None)
		result.pop('pending_reason', None)
		# Timestamps and changing countdowns must not resend identical outcomes.
		for field in ('steps', 'diagnostic', 'retry_after_seconds'):
			result.pop(field, None)
	fingerprint = hashlib.sha256(json.dumps(normalized, sort_keys=True).encode()).hexdigest()
	scope = '-' + hashlib.sha256(account_id.encode()).hexdigest()[:16] if account_id is not None else ''
	previous_file = data_dir / f'http-result-fingerprint{scope}.txt'
	changed = not previous_file.exists() or previous_file.read_text().strip() != fingerprint
	if changed:
		lines = [f'成功 {summary["success_count"]}/{summary["total_count"]}. 请在 WebUI 查看执行记录.']
		for result in results:
			if not result['success'] and result['reason'] != 'ACCOUNT_DISABLED':
				lines.append(f'{result["name"] or result["id"]}: {result.get("pending_reason", result["reason"])}')
				if config.get('webui_url'):
					lines.append(config['webui_url'].rstrip('/') + '/?account=' + quote(result['id'], safe=''))
		try:
			await asyncio.to_thread(notify.push_message, '签到执行结果', '\n'.join(lines), msg_type='text')
			atomic_write(previous_file, fingerprint.encode())
		except Exception:
			summary['notification_error'] = True
	publish(
		state=state,
		active_account=None,
		summary=summary,
		error=None if success else '请查看账号结果并更新凭据或人工处理',
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
	except Exception:
		active_account = None
		previous = {}
		try:
			event_file = Path(payload['event_file'])
			if event_file.stat().st_size <= 1024 * 1024:
				previous = json.loads(event_file.read_text(encoding='utf-8'))
				if isinstance(previous, dict) and isinstance(previous.get('active_account'), str):
					active_account = previous['active_account']
		except (OSError, ValueError, TypeError):
			pass
		atomic_write(
			Path(payload['event_file']),
			json.dumps(
				{
					'state': 'failed',
					'error': 'HTTP_WORKER_FAILED',
					'active_account': active_account,
					'summary': previous.get('summary') if isinstance(previous, dict) else None,
				}
			).encode(),
		)
		return 1


if __name__ == '__main__':
	request = json.loads(sys.stdin.buffer.read(1024 * 1024 + 1))
	from server.jobs import acquire_file_lock

	try:
		execution_lock = acquire_file_lock(Path(request['data_dir']) / 'execution.lock')
	except RuntimeError:
		raise SystemExit(2) from None
	try:
		raise SystemExit(asyncio.run(main(request)))
	finally:
		execution_lock.close()
