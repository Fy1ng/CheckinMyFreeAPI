"""Inspect or restore an encrypted package into fresh offline paths."""

import argparse
import getpass
import json
from pathlib import Path

from server.backup import MAX_BACKUP_BYTES, BackupError, inspect_backup, restore_offline


def main() -> None:
	parser = argparse.ArgumentParser(description='离线检查或恢复加密备份, 密码通过交互输入')
	parser.add_argument('action', choices=('inspect', 'restore'))
	parser.add_argument('backup', type=Path)
	parser.add_argument('--data-dir', type=Path)
	parser.add_argument('--key-file', type=Path)
	args = parser.parse_args()
	if args.action == 'restore' and (args.data_dir is None or args.key_file is None):
		parser.error('restore 需要 --data-dir 和 --key-file, 且不能覆盖已有数据库或主密钥')
	try:
		if args.backup.is_symlink() or args.backup.stat().st_size > MAX_BACKUP_BYTES:
			raise BackupError('备份文件不可用或过大')
		data = args.backup.read_bytes()
		password = getpass.getpass('备份恢复密码: ')
		result = (
			inspect_backup(data, password)
			if args.action == 'inspect'
			else restore_offline(data, password, args.data_dir, args.key_file)
		)
		print(json.dumps(result, ensure_ascii=False))
	except (BackupError, OSError):
		parser.exit(1, '备份检查或恢复失败, 请核对密码、文件和新的目标路径.\n')


if __name__ == '__main__':
	main()
