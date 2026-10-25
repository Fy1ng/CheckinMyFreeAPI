"""Balance routes only expose cached data and require authenticated, scoped writes."""

import os
from unittest.mock import AsyncMock, Mock

import pytest
import pytest_asyncio
from aiohttp import CookieJar
from aiohttp.test_utils import TestClient, TestServer

from server.app import SERVICE, create_app

PASSWORD = 'synthetic-balance-api-password'


@pytest_asyncio.fixture
async def balance_client(tmp_path):
	app = create_app(tmp_path, os.urandom(32), PASSWORD, scheduler=False)
	client = TestClient(TestServer(app), cookie_jar=CookieJar(unsafe=True))
	await client.start_server()
	try:
		yield app[SERVICE], client
	finally:
		await client.close()


async def authenticate(client):
	origin = str(client.make_url('')).rstrip('/')
	response = await client.post('/api/login', json={'password': PASSWORD}, headers={'Origin': origin})
	assert response.status == 200
	return {'Origin': origin, 'X-CSRF-Token': (await response.json())['csrf']}


@pytest.mark.asyncio
async def test_balance_cache_is_private_and_get_does_not_start_collection(balance_client, monkeypatch):
	service, client = balance_client
	assert (await client.get('/api/balances')).status == 401
	await authenticate(client)
	start = AsyncMock()
	monkeypatch.setattr(service.jobs, 'start', start)
	snapshot = Mock(return_value={'accounts': [], 'history': [], 'summary': {'balance': None}})
	monkeypatch.setattr(service.jobs, 'balance_snapshot', snapshot)
	response = await client.get('/api/balances')
	assert response.status == 200
	assert response.headers['Cache-Control'] == 'no-store'
	assert (await response.json())['summary']['balance'] is None
	snapshot.assert_called_once_with()
	start.assert_not_called()


@pytest.mark.asyncio
async def test_balance_refresh_requires_csrf_and_valid_single_account_scope(balance_client, monkeypatch):
	service, client = balance_client
	headers = await authenticate(client)
	start = AsyncMock(return_value={'id': 8, 'kind': 'balance', 'state': 'running'})
	monkeypatch.setattr(service.jobs, 'start', start)
	assert (await client.post('/api/balances/refresh', json={'revision': 1})).status == 403
	invalid: list[object] = [None, [], {}, {'revision': True}, {'revision': -1}, {'revision': 1, 'kind': 'checkin'}]
	invalid_scopes: tuple[object, ...] = (None, '', True, 5, [], {}, 'x' * 129)
	invalid += [{'revision': 1, 'account_id': value} for value in invalid_scopes]
	for payload in invalid:
		assert (await client.post('/api/balances/refresh', json=payload, headers=headers)).status == 400
	start.assert_not_called()
	response = await client.post('/api/balances/refresh', json={'revision': 1}, headers=headers)
	assert response.status == 202
	start.assert_awaited_once_with(1, kind='balance', account_id=None)
	response = await client.post('/api/balances/refresh', json={'revision': 1, 'account_id': 'first'}, headers=headers)
	assert response.status == 202
	start.assert_awaited_with(1, kind='balance', account_id='first')


@pytest.mark.asyncio
async def test_status_deep_link_serves_login_shell_without_account_data(balance_client):
	_, client = balance_client
	response = await client.get('/status')
	assert response.status == 200
	text = await response.text()
	assert 'login-form' in text and 'app.js' in text
	assert 'synthetic-balance-api-password' not in text
	assert (await client.get('/api/balances')).status == 401
