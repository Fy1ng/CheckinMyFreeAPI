"""Credential failures and uncertain writes stay paused between scheduled runs."""

import sqlite3
import time
from pathlib import Path


class ExecutionState:
	def __init__(self, path: Path):
		self.db = sqlite3.connect(path, timeout=30)
		self.db.execute("""CREATE TABLE IF NOT EXISTS account_attention (
		 account_id TEXT PRIMARY KEY, binding TEXT NOT NULL, outcome TEXT NOT NULL,
		 reason TEXT NOT NULL, retry_at REAL, updated_at REAL NOT NULL)""")
		self.db.commit()

	def get(self, account_id: str, binding: str) -> dict | None:
		row = self.db.execute(
			'SELECT outcome,reason,retry_at,updated_at,binding FROM account_attention WHERE account_id=?',
			(account_id,),
		).fetchone()
		if row is None or (row[4] != binding and row[0] != 'uncertain'):
			return None
		return dict(outcome=row[0], reason=row[1], retry_at=row[2], updated_at=row[3])

	def record(self, account_id: str, binding: str, result: dict) -> None:
		outcome = result.get('outcome')
		if outcome not in {'needs_credentials', 'blocked', 'rate_limited', 'uncertain'}:
			if result.get('success'):
				self.clear(account_id)
			return
		delay = result.get('retry_after_seconds', 3600)
		if not isinstance(delay, (int, float)) or isinstance(delay, bool):
			delay = 3600
		retry_at = time.time() + max(1, min(delay, 86400)) if outcome == 'rate_limited' else None
		with self.db:
			self.db.execute(
				'INSERT OR REPLACE INTO account_attention VALUES (?,?,?,?,?,?)',
				(account_id, binding, outcome, result.get('reason', 'REQUEST_FAILED'), retry_at, time.time()),
			)

	def clear(self, account_id: str) -> None:
		with self.db:
			self.db.execute('DELETE FROM account_attention WHERE account_id=?', (account_id,))

	def close(self) -> None:
		self.db.close()
