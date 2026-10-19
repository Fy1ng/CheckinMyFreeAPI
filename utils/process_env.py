"""Minimal non-secret environment for an isolated HTTP worker."""

import os


def child_environment() -> dict[str, str]:
	allowed = {
		'PATH',
		'HOME',
		'SYSTEMROOT',
		'TEMP',
		'TMP',
		'TMPDIR',
		'LANG',
		'LC_ALL',
		'USERPROFILE',
		'LOCALAPPDATA',
		'PROCESSOR_ARCHITECTURE',
		'PROCESSOR_ARCHITEW6432',
	}
	return {name: value for name, value in os.environ.items() if name.upper() in allowed}
