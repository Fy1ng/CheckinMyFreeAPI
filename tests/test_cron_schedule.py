"""Cron has deterministic UTC+8 calendar semantics and a bounded search."""

from datetime import datetime

import pytest

from utils.cron_schedule import LOCAL_TIMEZONE, CronSchedule, next_daily_time


def timestamp(text):
	return datetime.fromisoformat(text).replace(tzinfo=LOCAL_TIMEZONE).timestamp()


def test_daily_cron_uses_utc8_and_is_exclusive_at_exact_boundary():
	cron = CronSchedule('0 8 * * *')
	assert cron.next_after(timestamp('2026-10-25T07:59:59')) == timestamp('2026-10-25T08:00:00')
	assert cron.next_after(timestamp('2026-10-25T08:00:00')) == timestamp('2026-10-26T08:00:00')
	assert next_daily_time('23:55', timestamp('2026-10-25T23:55:00')) == timestamp('2026-10-26T23:55:00')


def test_numeric_lists_ranges_steps_and_sunday_alias():
	cron = CronSchedule('0,30 8-10/2 * * 1-5')
	assert cron.next_after(timestamp('2026-10-23T10:30:00')) == timestamp('2026-10-26T08:00:00')
	assert CronSchedule('0 8 * * 7').next_after(timestamp('2026-10-24T12:00:00')) == timestamp('2026-10-25T08:00:00')
	assert CronSchedule('0 8 * * 0').next_after(timestamp('2026-10-24T12:00:00')) == timestamp('2026-10-25T08:00:00')


def test_restricted_day_and_weekday_use_or_and_leap_day_is_found():
	cron = CronSchedule('0 8 1 * 1')
	assert cron.next_after(timestamp('2026-10-25T12:00:00')) == timestamp('2026-10-26T08:00:00')
	assert cron.next_after(timestamp('2026-10-31T12:00:00')) == timestamp('2026-11-01T08:00:00')
	assert CronSchedule('0 8 29 2 *').next_after(timestamp('2026-10-25T12:00:00')) == timestamp('2028-02-29T08:00:00')


def test_day_wildcard_steps_keep_calendar_and_weekday_intersection():
	cron = CronSchedule('0 8 */2 * 1')
	assert cron.next_after(timestamp('2026-10-25T12:00:00')) == timestamp('2026-11-09T08:00:00')
	assert CronSchedule('0 8 * * */2').next_after(timestamp('2026-10-25T12:00:00')) == timestamp('2026-10-27T08:00:00')


@pytest.mark.parametrize(
	'expression',
	[
		'* * * * *',
		'*/15 * * * *',
		'0,45 * * * *',
		'0 0 31 2 *',
		'0 0 * * MON',
		'@daily',
		'* * * * * *',
		'60 0 * * *',
		'0 24 * * *',
		'0 0 * * 8',
		'0 0 */0 * *',
		'0 0 3-1 * *',
		'0 0 1,,2 * *',
		'0 0 * * */-1',
		'0 0 * * 1/',
	],
)
def test_invalid_unsupported_impossible_or_too_frequent_cron_is_rejected(expression):
	with pytest.raises(ValueError):
		CronSchedule(expression)


@pytest.mark.parametrize('clock', ['8:00', '24:00', '08:60', [], None])
def test_invalid_daily_clock_is_rejected(clock):
	with pytest.raises(ValueError):
		next_daily_time(clock, timestamp('2026-10-25T08:00:00'))
