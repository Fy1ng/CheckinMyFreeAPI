"""Durable health transitions and single-attempt notification claims."""

from __future__ import annotations

import json
import math
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

from server.balance_store import STAT_TIMEZONE, BalanceStore, day_at, stamp
from utils.http_checkin import account_binding

FAILURES = {'failed', 'needs_credentials', 'blocked', 'rate_limited', 'uncertain'}
DELIVERY_STATES = {'accepted', 'partial', 'failed', 'unknown', 'not_configured'}


def _safe_code(value: object) -> str:
	if (
		isinstance(value, str)
		and 0 < len(value) <= 128
		and all(c.isascii() and (c.isalnum() or c == '_') for c in value)
	):
		return value
	return 'operation_failed'


class AutomationStore:
	def __init__(self, path: Path, *, run_id: int | None = None):
		self.path = path
		self.run_id = run_id
		self.db = sqlite3.connect(path, timeout=10)
		self.db.row_factory = sqlite3.Row
		self.db.executescript("""
		CREATE TABLE IF NOT EXISTS automation_health (
		 account_id TEXT NOT NULL, binding TEXT NOT NULL, scope TEXT NOT NULL,
		 state TEXT NOT NULL, reason TEXT, failure_since REAL, last_failure_at REAL,
		 last_success_at REAL, recovered_at REAL, consecutive_failures INTEGER NOT NULL,
		 recovery_notified_at REAL, PRIMARY KEY(account_id,binding,scope)
		);
		CREATE TABLE IF NOT EXISTS automation_low_balance (
		 account_id TEXT NOT NULL, binding TEXT NOT NULL, threshold REAL NOT NULL,
		 below INTEGER NOT NULL, episode REAL, notified_at REAL,
		 PRIMARY KEY(account_id,binding)
		);
		CREATE TABLE IF NOT EXISTS automation_notifications (
		 id INTEGER PRIMARY KEY, event_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL,
		 account_id TEXT, state TEXT NOT NULL, created_at REAL NOT NULL,
		 finished_at REAL, title TEXT NOT NULL, message TEXT NOT NULL,
		 delivery TEXT, run_id INTEGER
		);
		CREATE TABLE IF NOT EXISTS automation_scheduler (
		 id INTEGER PRIMARY KEY CHECK(id=1), signature TEXT NOT NULL, next_at REAL
		);
		INSERT OR IGNORE INTO automation_scheduler VALUES (1,'',NULL);
		""")
		self.db.commit()

	def claim(
		self, event_key: str, kind: str, title: str, message: str, account_id: str | None = None, *, commit: bool = True
	) -> int | None:
		cursor = self.db.execute(
			'INSERT OR IGNORE INTO automation_notifications '
			"(event_key,kind,account_id,state,created_at,title,message,run_id) VALUES (?,?,?,'pending',?,?,?,?)",
			(event_key, kind, account_id, time.time(), title[:256], message[:32768], self.run_id),
		)
		if commit:
			self.db.commit()
		return cursor.lastrowid if cursor.rowcount else None

	def record_health(
		self, account: dict, config: dict, scope: str, result: dict, *, now: float | None = None
	) -> list[int]:
		if (
			scope not in {'checkin', 'balance'}
			or not account.get('enabled', True)
			or result.get('outcome') == 'skipped'
		):
			return []
		if not result.get('success') and result.get('outcome') not in FAILURES:
			return []
		now = time.time() if now is None else now
		binding = account_binding(account, config)
		old = self.db.execute(
			'SELECT * FROM automation_health WHERE account_id=? AND binding=? AND scope=?',
			(account['id'], binding, scope),
		).fetchone()
		failure_since = old['failure_since'] if old else None
		last_failure = old['last_failure_at'] if old else None
		last_success = old['last_success_at'] if old else None
		recovered = old['recovered_at'] if old else None
		notified = old['recovery_notified_at'] if old else None
		consecutive = old['consecutive_failures'] if old else 0
		claimed = []
		if result.get('success'):
			settings = config['automation']['recovery']
			if failure_since is not None:
				recovered = now
				if settings['enabled'] and (notified is None or now - notified >= settings['cooldown_minutes'] * 60):
					name = account.get('name', account['id'])
					label = '签到' if scope == 'checkin' else '余额查询'
					message = (
						f'{name}: {label}已恢复. 异常持续 {max(0, int(now - failure_since))} 秒. 请在管理面板查看详情.'
					)
					notification = self.claim(
						f'recovery:{account["id"]}:{binding}:{scope}:{failure_since}',
						'recovery',
						'账户故障恢复',
						message,
						account['id'],
						commit=False,
					)
					if notification:
						claimed.append(notification)
						notified = now
			failure_since, consecutive, last_success = None, 0, now
			state, reason = 'healthy', None
		else:
			failure_since = failure_since if failure_since is not None else now
			last_failure, consecutive = now, consecutive + 1
			state, reason = result['outcome'], _safe_code(result.get('reason'))
		with self.db:
			self.db.execute(
				'INSERT OR REPLACE INTO automation_health VALUES (?,?,?,?,?,?,?,?,?,?,?)',
				(
					account['id'],
					binding,
					scope,
					state,
					reason,
					failure_since,
					last_failure,
					last_success,
					recovered,
					consecutive,
					notified,
				),
			)
		return claimed

	def check_low_balance(
		self, account: dict, config: dict, observation: dict, *, now: float | None = None
	) -> list[int]:
		settings = config['automation']['low_balance']
		if (
			not settings['enabled']
			or not account.get('enabled', True)
			or observation.get('stale')
			or observation.get('state') != 'ok'
		):
			return []
		balance = observation.get('balance')
		if isinstance(balance, bool) or not isinstance(balance, (int, float)) or not math.isfinite(balance):
			return []
		now = time.time() if now is None else now
		binding = account_binding(account, config)
		threshold = account.get('low_balance_threshold')
		if threshold is None:
			threshold = settings['threshold']
		old = self.db.execute(
			'SELECT * FROM automation_low_balance WHERE account_id=? AND binding=?', (account['id'], binding)
		).fetchone()
		below = balance < threshold
		new_episode = old is None or not old['below'] or old['threshold'] != threshold
		episode = float(now) if new_episode else old['episode']
		notified = None if new_episode else old['notified_at']
		claimed = []
		unconfirmed = False
		if notified is not None:
			prefix = f'low:{account["id"]}:{binding}:{episode}:'
			previous = self.db.execute(
				"SELECT state FROM automation_notifications WHERE kind='low_balance' AND substr(event_key,1,?)=? ORDER BY id DESC LIMIT 1",
				(len(prefix), prefix),
			).fetchone()
			unconfirmed = previous is not None and previous['state'] in {'pending', 'unknown', 'partial'}
		if below and not unconfirmed and (notified is None or now - notified >= settings['cooldown_minutes'] * 60):
			name = account.get('name', account['id'])
			message = f'{name}: 当前站内额度 ${balance:.4f}, 低于阈值 ${threshold:.4f}. 请在 Status 查看余额.'
			notification = self.claim(
				f'low:{account["id"]}:{binding}:{episode}:{now}',
				'low_balance',
				'账户低余额提醒',
				message,
				account['id'],
				commit=False,
			)
			if notification:
				claimed.append(notification)
				notified = now
		with self.db:
			self.db.execute(
				'INSERT OR REPLACE INTO automation_low_balance VALUES (?,?,?,?,?,?)',
				(
					account['id'],
					binding,
					threshold,
					int(below),
					episode if below else None,
					notified if below else None,
				),
			)
		return claimed

	def finish(self, notification_id: int, delivery: dict) -> None:
		state = delivery.get('state') if isinstance(delivery, dict) else 'unknown'
		if state not in DELIVERY_STATES:
			state = 'unknown'
		channels = []
		for channel in delivery.get('channels', []) if isinstance(delivery, dict) else []:
			if isinstance(channel, dict):
				name = channel.get('channel')
				if name in {
					'Email',
					'PushPlus',
					'Server Push',
					'DingTalk',
					'Feishu',
					'WeChat Work',
					'Gotify',
					'Telegram',
					'Bark',
					'Fy1Push',
				}:
					channels.append(
						{
							'channel': name,
							'state': channel.get('state') if channel.get('state') in DELIVERY_STATES else 'unknown',
							'error_code': _safe_code(channel.get('error_code')) if channel.get('error_code') else None,
						}
					)
		with self.db:
			self.db.execute(
				"UPDATE automation_notifications SET state=?,finished_at=?,delivery=? WHERE id=? AND state='pending'",
				(
					state,
					time.time(),
					json.dumps({'channels': channels, 'device_delivery': 'unconfirmed'}),
					notification_id,
				),
			)

	def interrupt_pending(self, run_id: int | None = None) -> None:
		with self.db:
			query = "UPDATE automation_notifications SET state='unknown',finished_at=? WHERE state='pending'"
			params: tuple = (time.time(),)
			if run_id is not None:
				query += ' AND run_id=?'
				params += (run_id,)
			self.db.execute(query, params)

	def pending(self, notification_id: int) -> dict | None:
		row = self.db.execute(
			"SELECT id,title,message FROM automation_notifications WHERE id=? AND state='pending'", (notification_id,)
		).fetchone()
		return dict(row) if row else None

	def snapshot(self, config: dict, *, now: float | None = None) -> dict:
		now = time.time() if now is None else now
		health = []
		for account in config['accounts']:
			binding = account_binding(account, config)
			for row in self.db.execute(
				'SELECT * FROM automation_health WHERE account_id=? AND binding=?', (account['id'], binding)
			):
				item = {key: row[key] for key in ['account_id', 'scope', 'state', 'reason', 'consecutive_failures']}
				item.update(
					{
						key: stamp(row[key])
						for key in ['failure_since', 'last_failure_at', 'last_success_at', 'recovered_at']
					}
				)
				health.append(item)
		notifications = []
		for row in self.db.execute('SELECT * FROM automation_notifications ORDER BY id DESC LIMIT 30'):
			item = {key: row[key] for key in ['id', 'kind', 'account_id', 'state', 'title']}
			item.update(
				created_at=stamp(row['created_at']),
				finished_at=stamp(row['finished_at']),
				delivery=json.loads(row['delivery']) if row['delivery'] else None,
			)
			notifications.append(item)
		daily = self.db.execute(
			"SELECT event_key,state FROM automation_notifications WHERE kind='daily_summary' ORDER BY id DESC LIMIT 1"
		).fetchone()
		schedule = self.db.execute('SELECT next_at FROM automation_scheduler WHERE id=1').fetchone()
		return {
			'timezone': 'Asia/Singapore',
			'day': day_at(now),
			'health': health,
			'notifications': notifications,
			'daily_summary': {
				'last_day': daily['event_key'].removeprefix('summary:') if daily else None,
				'last_state': daily['state'] if daily else None,
				'next_at': stamp(schedule[0]) if schedule else None,
			},
		}

	def close(self) -> None:
		self.db.close()


def build_daily_summary(
	path: Path, config: dict, *, now: float | None = None, day: str | None = None
) -> tuple[str, str]:
	now = time.time() if now is None else now
	local = datetime.fromtimestamp(now, STAT_TIMEZONE)
	current_day = local.date().isoformat()
	if day is not None and day != current_day:
		selected = datetime.strptime(day, '%Y-%m-%d').replace(tzinfo=STAT_TIMEZONE)
		if selected.date().isoformat() != day or day > current_day:
			raise ValueError('Invalid summary day')
		local = selected.replace(hour=23, minute=59, second=59)
		now = local.timestamp()
	start = local.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
	end = (local.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)).timestamp()
	store = BalanceStore(path)
	try:
		snapshot = store.snapshot(config, now=now)
	finally:
		store.close()
	active = {account['id'] for account in config['accounts'] if account.get('enabled', True)}
	counts = {'success': 0, 'failed': 0, 'skipped': 0}
	with sqlite3.connect(path) as db:
		for (document,) in db.execute(
			"SELECT summary FROM runs WHERE kind='checkin' AND COALESCE(finished_at,started_at)>=? AND COALESCE(finished_at,started_at)<? AND state NOT IN ('running','stopping')",
			(start, end),
		):
			try:
				results = json.loads(document or '{}').get('accounts', [])
			except (ValueError, TypeError, AttributeError):
				continue
			for result in results:
				if not isinstance(result, dict) or result.get('id') not in active:
					continue
				key = (
					'skipped'
					if result.get('outcome') == 'skipped'
					else 'success'
					if result.get('success') is True
					else 'failed'
				)
				counts[key] += 1

	def money(value):
		return '未知' if value is None else f'${value:.4f}'

	summary = snapshot['summary']
	if day is not None and day != current_day:
		history = next((item for item in snapshot['history'] if item['day'] == day), None)
		summary = {
			**summary,
			'balance': history['balance'] if history else None,
			'balance_count': history['balance_count'] if history else 0,
			'fresh_count': 0,
		}
	partial = any(a.get('income_partial') for a in snapshot['accounts'] if a['enabled'])
	lines = [
		f'日期: {snapshot["day"]}, UTC+8',
		f'总余额: {money(summary["balance"])}. 已知 {summary["balance_count"]}/{len(active)}, 新鲜 {summary["fresh_count"]}/{len(active)}.',
		f'今日新增: {money(summary["today_income"])}. 覆盖 {summary["income_count"]}/{len(active)}{", 含部分采集时段" if partial else ""}.',
		f'采集期净变化: {money(summary["today_net_change"])}. 覆盖 {summary["net_change_count"]}/{len(active)}.',
		f'签到记录: 成功 {counts["success"]}, 失败或待处理 {counts["failed"]}, 跳过 {counts["skipped"]}.',
		'站内额度统计, 未知或过期数据不代表余额为 0. 接收确认不代表设备送达.',
	]
	if config.get('webui_url'):
		lines.append(config['webui_url'].rstrip('/') + '/status')
	return f'每日摘要 {snapshot["day"]}', '\n'.join(lines)
