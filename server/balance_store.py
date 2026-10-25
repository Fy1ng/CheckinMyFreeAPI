"""Credential-bound balance observations and explicitly partial UTC+8 daily metrics.

Only numeric user fields are retained. Credentials and upstream response bodies
never enter this store. Daily samples describe the observed period, not an
invented midnight balance or a reconstructed pre-installation history.
"""

from __future__ import annotations

import hashlib
import math
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path

from utils.http_checkin import account_binding

STAT_TIMEZONE = timezone(timedelta(hours=8), 'Asia/Singapore')


def day_at(timestamp: float) -> str:
	return datetime.fromtimestamp(timestamp, STAT_TIMEZONE).date().isoformat()


def stamp(timestamp: float | None) -> str | None:
	return datetime.fromtimestamp(timestamp, timezone.utc).isoformat() if timestamp is not None else None


def amount(value: object) -> Decimal | None:
	if isinstance(value, bool) or not isinstance(value, (int, float)):
		return None
	try:
		number = Decimal(str(value))
		return number / Decimal(500000) if number.is_finite() and 0 <= number <= Decimal('1e24') else None
	except (InvalidOperation, ValueError):
		return None


def number(value: str | Decimal | None) -> float | None:
	if value is None:
		return None
	with localcontext() as context:
		context.prec = 40
		return float(Decimal(value).quantize(Decimal('0.0000000001')))


def combined(items: list[dict], key: str) -> float | None:
	values = [Decimal(str(item[key])) for item in items if item.get(key) is not None]
	return number(sum(values, Decimal(0))) if values else None


class BalanceStore:
	def __init__(self, path: Path):
		self.db = sqlite3.connect(path, timeout=10)
		self.db.row_factory = sqlite3.Row
		self.db.executescript("""
		CREATE TABLE IF NOT EXISTS balance_accounts (
		 account_id TEXT PRIMARY KEY, binding TEXT NOT NULL, identity TEXT,
		 balance TEXT, used TEXT, total TEXT, observed_at REAL,
		 state TEXT NOT NULL, reason TEXT, attempted_at REAL NOT NULL
		);
		CREATE TABLE IF NOT EXISTS balance_days (
		 account_id TEXT NOT NULL, binding TEXT NOT NULL, day TEXT NOT NULL,
		 opening TEXT NOT NULL, closing TEXT NOT NULL, total TEXT,
		 credits TEXT NOT NULL, site_income TEXT, samples INTEGER NOT NULL,
		 first_at REAL NOT NULL, last_at REAL NOT NULL, reset INTEGER NOT NULL DEFAULT 0,
		 PRIMARY KEY (account_id, binding, day)
		);
		CREATE TABLE IF NOT EXISTS balance_retry (
		 account_id TEXT PRIMARY KEY, binding TEXT NOT NULL, retry_at REAL NOT NULL
		);
		""")
		self.db.commit()

	def record(self, account: dict, config: dict, observation: dict) -> bool:
		quota, used, income = (amount(observation.get(key)) for key in ('quota', 'used_quota', 'today_income'))
		observed_at = observation.get('observed_at', time.time())
		if (
			quota is None
			or isinstance(observed_at, bool)
			or not isinstance(observed_at, (int, float))
			or not math.isfinite(observed_at)
			or not 0 < observed_at <= time.time() + 300
		):
			self.failure(account, config, 'failed', 'invalid_balance_data')
			return False
		identity_value = observation.get('id')
		if (
			isinstance(identity_value, bool)
			or not isinstance(identity_value, (int, str))
			or not str(identity_value).isdigit()
			or len(str(identity_value)) > 128
			or int(identity_value) <= 0
		):
			self.failure(account, config, 'failed', 'invalid_balance_identity')
			return False
		identity = hashlib.sha256(str(identity_value).encode()).hexdigest()
		binding = account_binding(account, config)
		current = self.db.execute('SELECT * FROM balance_accounts WHERE account_id=?', (account['id'],)).fetchone()
		if current and current['binding'] == binding and current['identity'] not in {None, identity}:
			self.failure(account, config, 'needs_credentials', 'account_identity_mismatch')
			return False
		if (
			current
			and current['binding'] == binding
			and current['observed_at']
			and current['observed_at'] > observed_at
		):
			return False
		total = quota + used if used is not None else None
		day = day_at(observed_at)
		row = self.db.execute(
			'SELECT * FROM balance_days WHERE account_id=? AND binding=? AND day=?', (account['id'], binding, day)
		).fetchone()
		with self.db:
			if row is None:
				self.db.execute(
					'INSERT INTO balance_days VALUES (?,?,?,?,?,?,?,?,?,?,?,0)',
					(
						account['id'],
						binding,
						day,
						str(quota),
						str(quota),
						str(total) if total is not None else None,
						'0',
						str(income) if income is not None else None,
						1,
						observed_at,
						observed_at,
					),
				)
			else:
				credits, reset = Decimal(row['credits']), row['reset']
				if total is not None and row['total'] is not None:
					delta = total - Decimal(row['total'])
					if delta >= 0:
						credits += delta
					else:
						reset = 1
				else:
					reset = 1
				self.db.execute(
					'UPDATE balance_days SET closing=?,total=?,credits=?,site_income=?,samples=samples+1,last_at=?,reset=? '
					'WHERE account_id=? AND binding=? AND day=?',
					(
						str(quota),
						str(total) if total is not None else None,
						str(credits),
						str(income) if income is not None else None,
						observed_at,
						reset,
						account['id'],
						binding,
						day,
					),
				)
			self.db.execute(
				'INSERT OR REPLACE INTO balance_accounts VALUES (?,?,?,?,?,?,?,?,?,?)',
				(
					account['id'],
					binding,
					identity,
					str(quota),
					str(used) if used is not None else None,
					str(total) if total is not None else None,
					observed_at,
					'ok',
					None,
					observed_at,
				),
			)
			cutoff = (datetime.fromtimestamp(observed_at, STAT_TIMEZONE).date() - timedelta(days=30)).isoformat()
			self.db.execute('DELETE FROM balance_days WHERE day < ?', (cutoff,))
		return True

	def rate_limit(self, account: dict, config: dict, delay: object = 3600) -> None:
		if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not math.isfinite(delay):
			delay = 3600
		with self.db:
			self.db.execute(
				'INSERT OR REPLACE INTO balance_retry VALUES (?,?,?)',
				(account['id'], account_binding(account, config), time.time() + max(1, min(delay, 86400))),
			)

	def retry_at(self, account: dict, config: dict) -> float | None:
		row = self.db.execute(
			'SELECT retry_at FROM balance_retry WHERE account_id=? AND binding=?',
			(account['id'], account_binding(account, config)),
		).fetchone()
		return row[0] if row else None

	def failure(self, account: dict, config: dict, state: str, reason: str, *, at: float | None = None) -> None:
		binding = account_binding(account, config)
		allowed = {'unknown', 'needs_credentials', 'blocked', 'rate_limited', 'failed'}
		state = state if state in allowed else 'failed'
		# Reasons are fixed local codes, never an upstream message.
		if (
			not isinstance(reason, str)
			or not reason
			or len(reason) > 128
			or not all(c.isascii() and (c.isalnum() or c == '_') for c in reason)
		):
			reason = 'balance_collection_failed'
		with self.db:
			self.db.execute(
				'INSERT INTO balance_accounts(account_id,binding,state,reason,attempted_at) VALUES (?,?,?,?,?) '
				'ON CONFLICT(account_id) DO UPDATE SET '
				'identity=CASE WHEN binding=excluded.binding THEN identity ELSE NULL END,'
				'balance=CASE WHEN binding=excluded.binding THEN balance ELSE NULL END,'
				'used=CASE WHEN binding=excluded.binding THEN used ELSE NULL END,'
				'total=CASE WHEN binding=excluded.binding THEN total ELSE NULL END,'
				'observed_at=CASE WHEN binding=excluded.binding THEN observed_at ELSE NULL END,'
				'binding=excluded.binding,state=excluded.state,reason=excluded.reason,attempted_at=excluded.attempted_at',
				(account['id'], binding, state, reason, at if at is not None else time.time()),
			)

	@staticmethod
	def _daily(row) -> dict:
		if row is None:
			return {
				'today_income': None,
				'today_net_change': None,
				'income_source': None,
				'partial': True,
				'income_partial': True,
				'net_change_partial': True,
				'observed_since': None,
			}
		income = row['site_income']
		source: str | None = 'site'
		if income is None:
			income = row['credits'] if row['samples'] > 1 and not row['reset'] and row['total'] is not None else None
			source = 'observed' if income is not None else None
		net = Decimal(row['closing']) - Decimal(row['opening']) if row['samples'] > 1 else None
		return {
			'today_income': number(income),
			'today_net_change': number(net),
			'income_source': source,
			'partial': True,
			'income_partial': source != 'site',
			'net_change_partial': True,
			'observed_since': stamp(row['first_at']),
		}

	def snapshot(self, config: dict, *, now: float | None = None) -> dict:
		now = time.time() if now is None else now
		day = day_at(now)
		accounts = []
		fresh_for = config.get('monitoring', {}).get('interval_minutes', 60) * 60 + 300
		for account in config['accounts']:
			binding = account_binding(account, config)
			row = self.db.execute(
				'SELECT * FROM balance_accounts WHERE account_id=? AND binding=?', (account['id'], binding)
			).fetchone()
			daily = self.db.execute(
				'SELECT * FROM balance_days WHERE account_id=? AND binding=? AND day=?', (account['id'], binding, day)
			).fetchone()
			enabled = account.get('enabled', True)
			stale = (
				row is None
				or row['state'] != 'ok'
				or row['observed_at'] is None
				or now - row['observed_at'] > fresh_for
			)
			accounts.append(
				{
					'id': account['id'],
					'name': account.get('name', account['id']),
					'provider': account['provider'],
					'enabled': enabled,
					'balance': number(row['balance']) if row else None,
					'used': number(row['used']) if row else None,
					'updated_at': stamp(row['observed_at']) if row else None,
					'stale': stale,
					'state': ('disabled' if not enabled else row['state'] if row else 'unknown'),
					'reason': row['reason'] if row else 'balance_not_collected',
					**self._daily(daily),
				}
			)
		active = [item for item in accounts if item['enabled']]
		summary = {
			'balance': combined(active, 'balance'),
			'today_income': combined(active, 'today_income'),
			'today_net_change': combined(active, 'today_net_change'),
			'account_count': len(active),
			'balance_count': sum(item['balance'] is not None for item in active),
			'fresh_count': sum(not item['stale'] for item in active),
			'income_count': sum(item['today_income'] is not None for item in active),
			'net_change_count': sum(item['today_net_change'] is not None for item in active),
		}
		by_day: dict[str, list[dict]] = {}
		cutoff = (datetime.fromtimestamp(now, STAT_TIMEZONE).date() - timedelta(days=29)).isoformat()
		for account in config['accounts']:
			if not account.get('enabled', True):
				continue
			for daily in self.db.execute(
				'SELECT * FROM balance_days WHERE account_id=? AND binding=? AND day>=? AND day<=?',
				(account['id'], account_binding(account, config), cutoff, day),
			):
				by_day.setdefault(daily['day'], []).append({'balance': number(daily['closing']), **self._daily(daily)})
		history = [
			{
				'day': key,
				'balance': combined(items, 'balance'),
				'today_income': combined(items, 'today_income'),
				'today_net_change': combined(items, 'today_net_change'),
				'balance_count': len(items),
				'income_count': sum(item['today_income'] is not None for item in items),
				'net_change_count': sum(item['today_net_change'] is not None for item in items),
			}
			for key, items in sorted(by_day.items())
		]
		return {'timezone': 'Asia/Singapore', 'day': day, 'summary': summary, 'accounts': accounts, 'history': history}

	def close(self) -> None:
		self.db.close()
