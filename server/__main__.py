"""Start a private WebUI without changing the invoking shell's configuration."""

import argparse
import getpass
import os
import secrets
import sqlite3
from pathlib import Path

from aiohttp import web


def main() -> None:
	parser = argparse.ArgumentParser(description='启动本机配置和调度 WebUI')
	parser.parse_args()
	data = Path(os.getenv('CHECKIN_WEB_DATA_DIR', 'server-data'))
	key_path = Path(os.getenv('CHECKIN_WEB_KEY_FILE', 'server-keys/master.key'))
	if data.is_symlink() or key_path.is_symlink():
		raise SystemExit('数据或密钥路径不能是符号链接')
	data, key_path = data.resolve(), key_path.resolve()
	data.mkdir(parents=True, exist_ok=True, mode=0o700)
	if not key_path.exists():
		if (data / 'webui.sqlite3').exists():
			raise SystemExit('已有数据库但密钥缺失, 请恢复对应密钥备份')
		key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
		with key_path.open('xb') as stream:
			os.chmod(key_path, 0o600)
			stream.write(secrets.token_bytes(32))
	key = key_path.read_bytes()
	if len(key) != 32:
		raise SystemExit('主密钥文件必须是 32 原始字节')
	password_file = os.getenv('CHECKIN_WEB_PASSWORD_FILE')
	password = Path(password_file).read_text().strip() if password_file else os.getenv('CHECKIN_WEB_PASSWORD')
	db_path = data / 'webui.sqlite3'
	has_password = False
	if db_path.exists():
		with sqlite3.connect(db_path) as db:
			if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='web_auth'").fetchone():
				has_password = db.execute('SELECT 1 FROM web_auth WHERE id=1').fetchone() is not None
	if not has_password and not password:
		password = getpass.getpass('首次设置 WebUI 密码 (至少 16 字符): ')
		if password != getpass.getpass('再次输入 WebUI 密码: '):
			raise SystemExit('两次密码不一致')
	host = os.getenv('CHECKIN_WEB_HOST', '127.0.0.1')
	# Compose exposes the explicit container-wide bind only on the host's loopback.
	if host not in {'127.0.0.1', '::1', '0.0.0.0'}:  # nosec B104
		raise SystemExit('监听地址必须为 loopback, 或容器内部的 0.0.0.0')
	port = int(os.getenv('CHECKIN_WEB_PORT', '8765'))
	from server.app import create_app

	app = create_app(data, key, password)
	print(f'WebUI 已启动, 请通过本机或 SSH 转发访问 http://127.0.0.1:{port}')
	web.run_app(app, host=host, port=port, access_log=None, print=None)


if __name__ == '__main__':
	main()
