"""Bounded five-field Cron scheduling in the product's fixed UTC+8 timezone."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

LOCAL_TIMEZONE = timezone(timedelta(hours=8), 'Asia/Singapore')


def _field(text: str, lower: int, upper: int) -> set[int]:
	if not text or not re.fullmatch(r'[0-9*/,-]+', text):
		raise ValueError('Cron supports only numeric five-field expressions with *, lists, ranges and steps')
	values: set[int] = set()
	for item in text.split(','):
		parts = item.split('/')
		if len(parts) > 2 or (len(parts) == 2 and (not parts[1].isdigit() or int(parts[1]) < 1)):
			raise ValueError('Cron step must be a positive integer')
		step = int(parts[1]) if len(parts) == 2 else 1
		base = parts[0]
		if base == '*':
			start, end = lower, upper
		elif '-' in base:
			bounds = base.split('-')
			if len(bounds) != 2 or any(not value.isdigit() for value in bounds):
				raise ValueError('Invalid Cron range')
			start, end = map(int, bounds)
		elif base.isdigit():
			start = int(base)
			end = upper if len(parts) == 2 else start
		else:
			raise ValueError('Invalid Cron field')
		if not lower <= start <= end <= upper:
			raise ValueError('Cron field is out of range')
		values.update(range(start, end + 1, step))
	return values


class CronSchedule:
	def __init__(self, expression: str):
		if not isinstance(expression, str) or len(expression) > 128:
			raise ValueError('Cron expression must contain five numeric fields')
		fields = expression.split()
		if len(fields) != 5:
			raise ValueError('Cron expression must contain five numeric fields')
		self.minutes = _field(fields[0], 0, 59)
		self.hours = _field(fields[1], 0, 23)
		self.days = _field(fields[2], 1, 31)
		self.months = _field(fields[3], 1, 12)
		self.weekdays = {value % 7 for value in _field(fields[4], 0, 7)}
		self.day_wildcard = fields[2].startswith('*')
		self.weekday_wildcard = fields[4].startswith('*')
		self.times = sorted(hour * 60 + minute for hour in self.hours for minute in self.minutes)
		gaps = [end - start for start, end in zip(self.times, self.times[1:] + [self.times[0] + 1440])]
		if min(gaps) < 30:
			raise ValueError('Cron check-in times must be at least 30 minutes apart')
		# Bound impossible calendar expressions at validation time without scanning minutes.
		self.next_after(datetime(2024, 1, 1, tzinfo=LOCAL_TIMEZONE).timestamp())

	def _matches_day(self, day: datetime) -> bool:
		if day.month not in self.months:
			return False
		dom = day.day in self.days
		dow = (day.weekday() + 1) % 7 in self.weekdays
		if self.day_wildcard or self.weekday_wildcard:
			return dom and dow
		return dom or dow

	def next_after(self, timestamp: float) -> float:
		local = datetime.fromtimestamp(timestamp, LOCAL_TIMEZONE)
		midnight = local.replace(hour=0, minute=0, second=0, microsecond=0)
		for offset in range(366 * 8 + 1):
			day = midnight + timedelta(days=offset)
			if self._matches_day(day):
				for minute in self.times:
					candidate = day + timedelta(minutes=minute)
					if candidate > local:
						return candidate.timestamp()
		raise ValueError('Cron expression has no occurrence within eight years')


def next_daily_time(clock: str, timestamp: float) -> float:
	if not isinstance(clock, str) or not re.fullmatch(r'(?:[01][0-9]|2[0-3]):[0-5][0-9]', clock):
		raise ValueError('Daily time must use HH:MM in UTC+8')
	local = datetime.fromtimestamp(timestamp, LOCAL_TIMEZONE)
	hour, minute = map(int, clock.split(':'))
	candidate = local.replace(hour=hour, minute=minute, second=0, microsecond=0)
	return (candidate if candidate > local else candidate + timedelta(days=1)).timestamp()
