import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx


def test_cli_starts_locally_and_restores_configuration_after_restart(tmp_path):
	with socket.socket() as listener:
		listener.bind(('127.0.0.1', 0))
		port = listener.getsockname()[1]
	environment = dict(os.environ)
	environment.update(
		CHECKIN_WEB_DATA_DIR=str(tmp_path / 'data'),
		CHECKIN_WEB_KEY_FILE=str(tmp_path / 'keys' / 'master.key'),
		CHECKIN_WEB_PORT=str(port),
		CHECKIN_WEB_HOST='127.0.0.1',
		CHECKIN_WEB_PASSWORD='synthetic-webui-password',
	)
	environment.pop('CHECKIN_WEB_PASSWORD_FILE', None)
	for attempt in range(2):
		process = subprocess.Popen(
			[sys.executable, '-m', 'server'],
			cwd=Path(__file__).resolve().parent.parent,
			env=environment,
			stdin=subprocess.DEVNULL,
			stdout=subprocess.DEVNULL,
			stderr=subprocess.DEVNULL,
		)
		try:
			origin = f'http://127.0.0.1:{port}'
			with httpx.Client(base_url=origin, trust_env=False, timeout=2) as client:
				for _ in range(40):
					try:
						if client.get('/healthz').status_code == 200:
							break
					except httpx.TransportError:
						pass
					time.sleep(0.1)
				else:
					raise AssertionError('Local server did not start')
				response = client.post(
					'/api/login', json={'password': 'synthetic-webui-password'}, headers={'Origin': origin}
				)
				assert response.status_code == 200
				configuration = client.get('/api/config').json()
				assert configuration['revision'] == attempt
				if attempt == 0:
					response = client.put(
						'/api/config',
						json=configuration,
						headers={'Origin': origin, 'X-CSRF-Token': response.json()['csrf']},
					)
					assert response.status_code == 200
		finally:
			process.terminate()
			process.wait(timeout=10)
		environment.pop('CHECKIN_WEB_PASSWORD', None)
	assert (tmp_path / 'keys' / 'master.key').stat().st_size == 32
