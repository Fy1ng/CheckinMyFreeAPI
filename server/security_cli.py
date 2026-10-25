"""SSH/operator recovery requires exclusive access to the stopped service data."""

import argparse
import json
import sqlite3
from pathlib import Path

from server.jobs import BusyError, acquire_file_lock
from server.passkeys import SecurityError, SecurityStore


def main() -> None:
	parser = argparse.ArgumentParser(description='通过 SSH 在停止服务后恢复密码登录模式')
	parser.add_argument('action', choices=('status', 'reset'))
	parser.add_argument('--data-dir', type=Path, required=True)
	parser.add_argument('--confirm', action='store_true')
	parser.add_argument('--clear-passkeys', action='store_true')
	args = parser.parse_args()
	if args.action == 'reset' and not args.confirm:
		parser.error('reset 需要 --confirm; 此操作会恢复密码登录并使旧管理会话失效')
	if (
		any(path.is_symlink() for path in (args.data_dir, *args.data_dir.parents))
		or (args.data_dir / 'webui.sqlite3').is_symlink()
		or not (args.data_dir / 'webui.sqlite3').is_file()
	):
		parser.exit(1, '数据目录无效.\n')
	try:
		lease = acquire_file_lock(args.data_dir / 'service.lock')
		try:
			store = SecurityStore(args.data_dir / 'webui.sqlite3')
			try:
				if args.action == 'reset':
					store.reset(clear=args.clear_passkeys)
				policy = store.policy()
				print(
					json.dumps(
						{
							'mode': policy['mode'],
							'revision': policy['revision'],
							'passkey_count': store.db.execute('SELECT count(*) FROM web_passkeys').fetchone()[0],
						}
					)
				)
			finally:
				store.close()
		finally:
			lease.close()
	except (BusyError, SecurityError, OSError, sqlite3.Error):
		parser.exit(1, '请停止服务后重试, 并核对数据目录权限.\n')


if __name__ == '__main__':
	main()
