"""Exercise real SOCKS5 handshakes and verified TLS without leaving loopback."""

from __future__ import annotations

import asyncio
import copy
import ipaddress
import json
import socket
import ssl
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

import anyio
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from utils.http_checkin import HttpCheckinRuntime

PROXY_USERNAME = 'proxy:name@/用户'
PROXY_PASSWORD = 'synthetic-p@ss: /%密码'
SITE_COOKIE = 'synthetic-site-session'
SITE_PASSWORD = 'synthetic-site-password'


def _tls_contexts(
	tmp_path: Path, certificate_hosts=('anyrouter.top', 'agentrouter.org')
) -> tuple[ssl.SSLContext, ssl.SSLContext]:
	"""Trust only an ephemeral self-signed test certificate, with hostname checks."""
	key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Synthetic SOCKS test')])
	now = datetime.now(timezone.utc)
	certificate = (
		x509.CertificateBuilder()
		.subject_name(name)
		.issuer_name(name)
		.public_key(key.public_key())
		.serial_number(x509.random_serial_number())
		.not_valid_before(now - timedelta(minutes=1))
		.not_valid_after(now + timedelta(days=1))
		.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
		.add_extension(
			x509.SubjectAlternativeName([x509.DNSName(host) for host in certificate_hosts]),
			critical=False,
		)
		.sign(key, hashes.SHA256())
	)
	cert_path, key_path = tmp_path / 'loopback-cert.pem', tmp_path / 'loopback-key.pem'
	cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
	key_path.write_bytes(
		key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
	)
	server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
	server_context.load_cert_chain(cert_path, key_path)
	client_context = ssl.create_default_context(cafile=str(cert_path))
	assert client_context.verify_mode == ssl.CERT_REQUIRED and client_context.check_hostname
	return server_context, client_context


class _LoopbackNetwork:
	def __init__(self, server_context: ssl.SSLContext, *, authenticate: bool, reject: bool):
		self.server_context = server_context
		self.authenticate = authenticate
		self.reject = reject
		self.site_requests: list[dict] = []
		self.server_names: list[str | None] = []
		self.methods: list[bytes] = []
		self.selected_methods: list[int] = []
		self.authentications: list[tuple[bytes, bytes]] = []
		self.destinations: list[tuple[int, str, int]] = []
		self.errors: list[str] = []
		self.connections: set[asyncio.StreamWriter] = set()
		self.tasks: set[asyncio.Task] = set()
		self.server_context.set_servername_callback(lambda _socket, name, _context: self.server_names.append(name))

	async def start(self):
		self.site = await asyncio.start_server(self._site, '127.0.0.1', 0, ssl=self.server_context)
		self.site_port = self.site.sockets[0].getsockname()[1]
		self.proxy = await asyncio.start_server(self._proxy, '127.0.0.1', 0)
		self.proxy_port = self.proxy.sockets[0].getsockname()[1]

	async def close(self):
		self.proxy.close()
		self.site.close()
		await self.proxy.wait_closed()
		await self.site.wait_closed()
		for writer in tuple(self.connections):
			writer.close()
		for task in tuple(self.tasks):
			task.cancel()
		await asyncio.gather(*tuple(self.tasks), return_exceptions=True)

	def proxy_url(self) -> str:
		credentials = f'{quote(PROXY_USERNAME, safe="")}:{quote(PROXY_PASSWORD, safe="")}@' if self.authenticate else ''
		return f'socks5://{credentials}127.0.0.1:{self.proxy_port}'

	async def _site(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
		self.connections.add(writer)
		task = asyncio.current_task()
		assert task is not None
		self.tasks.add(task)
		try:
			head = await reader.readuntil(b'\r\n\r\n')
			lines = head.decode('ascii').split('\r\n')
			method, path, _version = lines[0].split(' ')
			headers = {key.lower(): value for key, value in (line.split(': ', 1) for line in lines[1:] if line)}
			body = await reader.readexactly(int(headers.get('content-length', '0')))
			self.site_requests.append({'method': method, 'path': path, 'headers': headers, 'body': body})
			if path == '/api/user/self' and method == 'GET':
				quota = 500000 if len(self.site_requests) == 1 else 1000000
				payload = {
					'success': True,
					'data': {'id': 42, 'username': 'alice', 'quota': quota, 'used_quota': 100000},
				}
			elif path == '/api/user/sign_in' and method == 'POST':
				payload = {'success': True}
			elif path == '/api/user/login?turnstile=' and method == 'POST':
				assert json.loads(body) == {'username': 'alice', 'password': SITE_PASSWORD}
				payload = {'success': True, 'data': {'id': 42, 'username': 'alice', 'checked_in': True}}
			else:
				self.errors.append('Unexpected synthetic site request')
				payload = {'success': False}
			data = json.dumps(payload).encode()
			writer.write(
				b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: '
				+ str(len(data)).encode()
				+ b'\r\n\r\n'
				+ data
			)
			await writer.drain()
		except (asyncio.IncompleteReadError, ConnectionError):
			self.errors.append('Synthetic HTTPS connection closed unexpectedly')
		finally:
			writer.close()
			self.connections.discard(writer)
			self.tasks.discard(task)

	async def _proxy(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
		self.connections.add(writer)
		task = asyncio.current_task()
		assert task is not None
		self.tasks.add(task)
		upstream: asyncio.StreamWriter | None = None
		relays: list[asyncio.Task] = []
		try:
			version, count = await reader.readexactly(2)
			methods = await reader.readexactly(count)
			self.methods.append(methods)
			selected = 2 if self.authenticate else 0
			if version != 5 or selected not in methods:
				self.errors.append('Unexpected SOCKS5 authentication negotiation')
				writer.write(b'\x05\xff')
				await writer.drain()
				return
			self.selected_methods.append(selected)
			writer.write(bytes([5, selected]))
			await writer.drain()
			if selected == 2:
				auth_version, username_length = await reader.readexactly(2)
				username = await reader.readexactly(username_length)
				password_length = (await reader.readexactly(1))[0]
				password = await reader.readexactly(password_length)
				self.authentications.append((username, password))
				valid = (
					auth_version == 1
					and username == PROXY_USERNAME.encode()
					and password == PROXY_PASSWORD.encode()
					and not self.reject
				)
				writer.write(bytes([1, 0 if valid else 1]))
				await writer.drain()
				if not valid:
					return
			version, command, reserved, address_type = await reader.readexactly(4)
			if address_type != 3:
				self.errors.append('SOCKS5 must receive the original target domain for proxy DNS')
				return
			host_length = (await reader.readexactly(1))[0]
			host = (await reader.readexactly(host_length)).decode('ascii')
			port = int.from_bytes(await reader.readexactly(2), 'big')
			self.destinations.append((address_type, host, port))
			if (
				(version, command, reserved) != (5, 1, 0)
				or host not in {'anyrouter.top', 'agentrouter.org'}
				or port != 443
			):
				self.errors.append('Unexpected SOCKS5 destination; connection denied')
				writer.write(b'\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x00')
				await writer.drain()
				return
			# The requested public hostname is never resolved or contacted. Only this
			# loopback TLS listener is reachable through the synthetic proxy.
			upstream_reader, upstream = await asyncio.open_connection('127.0.0.1', self.site_port)
			writer.write(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
			await writer.drain()

			async def relay(source: asyncio.StreamReader, destination: asyncio.StreamWriter):
				while data := await source.read(65536):
					destination.write(data)
					await destination.drain()

			relays = [asyncio.create_task(relay(reader, upstream)), asyncio.create_task(relay(upstream_reader, writer))]
			await asyncio.wait(relays, return_when=asyncio.FIRST_COMPLETED)
		except (asyncio.IncompleteReadError, ConnectionError):
			self.errors.append('Synthetic SOCKS5 connection closed unexpectedly')
		finally:
			for relay_task in relays:
				relay_task.cancel()
			await asyncio.gather(*relays, return_exceptions=True)
			if upstream is not None:
				upstream.close()
			writer.close()
			self.connections.discard(writer)
			self.tasks.discard(task)


@asynccontextmanager
async def _local_network(
	tmp_path, monkeypatch, *, authenticate=True, reject=False, certificate_hosts=('anyrouter.top', 'agentrouter.org')
):
	server_context, client_context = _tls_contexts(tmp_path, certificate_hosts)
	network = _LoopbackNetwork(server_context, authenticate=authenticate, reject=reject)
	await network.start()
	connections = []
	connect_tcp = anyio.connect_tcp
	getaddrinfo = socket.getaddrinfo

	async def local_connect_tcp(*args, **kwargs):
		host = kwargs.get('remote_host', args[0] if args else None)
		port = kwargs.get('remote_port', args[1] if len(args) > 1 else None)
		connections.append((host, port))
		assert host == '127.0.0.1' and port == network.proxy_port, 'No direct or external connection is allowed'
		return await connect_tcp(*args, **kwargs)

	def local_getaddrinfo(host, *args, **kwargs):
		assert ipaddress.ip_address(host).is_loopback, 'Public hostnames must be resolved by the SOCKS5 proxy'
		return getaddrinfo(host, *args, **kwargs)

	monkeypatch.setattr(anyio, 'connect_tcp', local_connect_tcp)
	monkeypatch.setattr(socket, 'getaddrinfo', local_getaddrinfo)
	# Even an explicitly set environment proxy must not affect account routing.
	monkeypatch.setenv('HTTPS_PROXY', 'http://unexpected-environment-proxy.invalid:8080')
	monkeypatch.setenv('ALL_PROXY', 'socks5://unexpected-environment-proxy.invalid:1080')

	def client_factory(**kwargs):
		assert kwargs['verify'] is True
		assert kwargs['trust_env'] is False
		assert kwargs['follow_redirects'] is False
		assert kwargs['proxy'] == network.proxy_url()
		return httpx.AsyncClient(**{**kwargs, 'verify': client_context})

	try:
		yield network, client_factory, connections
	finally:
		await network.close()


class _Sessions:
	def __init__(self):
		self.loads: list[tuple[str, str]] = []
		self.saved: list[tuple[str, str, dict]] = []

	def load(self, account_id, binding):
		self.loads.append((account_id, binding))
		return None

	def save(self, account_id, binding, state):
		self.saved.append((account_id, binding, copy.deepcopy(state)))


def _account(provider, route):
	return {
		'id': 'synthetic-account',
		'name': 'Synthetic account',
		'provider': provider,
		'auth_type': 'password' if provider == 'agentrouter' else 'cookie',
		'api_user': '42',
		'expected_username': 'alice',
		'cookies': f'session={SITE_COOKIE}' if provider == 'anyrouter' else '',
		'username': 'alice' if provider == 'agentrouter' else '',
		'password': SITE_PASSWORD if provider == 'agentrouter' else '',
		'proxy': route,
	}


def _routing(route, proxy_url):
	if route == 'default':
		return {'http': {'timeout_seconds': 3}, 'proxy_url': proxy_url}, 'default'
	return {'http': {'timeout_seconds': 3}, 'proxy_url': 'socks5://ignored:unused@127.0.0.1:9'}, proxy_url


def _assert_no_secrets(result, events, output):
	text = json.dumps([result, events], ensure_ascii=False) + output
	for secret in (
		PROXY_USERNAME,
		PROXY_PASSWORD,
		quote(PROXY_USERNAME, safe=''),
		quote(PROXY_PASSWORD, safe=''),
		SITE_COOKIE,
		SITE_PASSWORD,
	):
		assert secret not in text


@pytest.mark.parametrize('route', ['default', 'account'])
@pytest.mark.parametrize('provider', ['anyrouter', 'agentrouter'])
async def test_authenticated_socks5_routes_runtime_requests_with_proxy_dns_and_verified_tls(
	tmp_path, monkeypatch, capsys, route, provider
):
	async with _local_network(tmp_path, monkeypatch) as (network, factory, connections):
		config, account_route = _routing(route, network.proxy_url())
		store = _Sessions()
		events = []
		result = await HttpCheckinRuntime(config, store, client_factory=factory).execute(
			_account(provider, account_route), on_progress=lambda event: events.append(copy.deepcopy(event))
		)
		assert result['success'] is True
		count = 3 if provider == 'anyrouter' else 1
		host = 'anyrouter.top' if provider == 'anyrouter' else 'agentrouter.org'
		assert len(connections) == count
		assert network.selected_methods == [2] * count
		assert len(network.methods) == count and all(2 in methods for methods in network.methods)
		assert network.authentications == [(PROXY_USERNAME.encode(), PROXY_PASSWORD.encode())] * count
		assert network.destinations == [(3, host, 443)] * count
		assert network.server_names == [host] * count
		assert not network.errors
		if provider == 'anyrouter':
			assert all(request['headers']['new-api-user'] == '42' for request in network.site_requests)
			assert result['reason'] == 'checkin_verified' and result['reward'] == 1
			assert [(request['method'], request['path']) for request in network.site_requests] == [
				('GET', '/api/user/self'),
				('POST', '/api/user/sign_in'),
				('GET', '/api/user/self'),
			]
			assert all(request['headers']['cookie'] == f'session={SITE_COOKIE}' for request in network.site_requests)
			assert len(store.saved) == 1
		else:
			assert result['reason'] == 'agent_checkin_verified' and result['checked_in'] is True
			assert [(request['method'], request['path']) for request in network.site_requests] == [
				('POST', '/api/user/login?turnstile=')
			]
			assert json.loads(network.site_requests[0]['body']) == {'username': 'alice', 'password': SITE_PASSWORD}
			assert 'authorization' not in network.site_requests[0]['headers']
			assert 'cookie' not in network.site_requests[0]['headers']
			assert not store.loads and not store.saved
		_assert_no_secrets(result, events, capsys.readouterr().out)


@pytest.mark.parametrize('route', ['default', 'account'])
@pytest.mark.parametrize('provider', ['anyrouter', 'agentrouter'])
async def test_socks5_authentication_rejection_is_sanitized_without_retry_or_direct_fallback(
	tmp_path, monkeypatch, capsys, route, provider
):
	async with _local_network(tmp_path, monkeypatch, reject=True) as (network, factory, connections):
		config, account_route = _routing(route, network.proxy_url())
		store = _Sessions()
		events = []
		result = await HttpCheckinRuntime(config, store, client_factory=factory).execute(
			_account(provider, account_route), on_progress=lambda event: events.append(copy.deepcopy(event))
		)
		assert result['success'] is False
		assert result['outcome'] == 'failed' and result['reason'] == 'proxy_authentication_failed'
		assert len(connections) == 1
		assert network.selected_methods == [2]
		assert network.authentications == [(PROXY_USERNAME.encode(), PROXY_PASSWORD.encode())]
		assert not network.destinations and not network.site_requests and not network.server_names
		assert not network.errors and not store.saved
		_assert_no_secrets(result, events, capsys.readouterr().out)


async def test_unauthenticated_socks5_remains_compatible_with_real_transport(tmp_path, monkeypatch):
	async with _local_network(tmp_path, monkeypatch, authenticate=False) as (network, factory, connections):
		config, route = _routing('default', network.proxy_url())
		result = await HttpCheckinRuntime(config, _Sessions(), client_factory=factory).execute(
			_account('agentrouter', route)
		)
		assert result['success'] is True
		assert network.methods == [b'\x00'] and network.selected_methods == [0]
		assert not network.authentications
		assert network.destinations == [(3, 'agentrouter.org', 443)]
		assert network.server_names == ['agentrouter.org']
		assert len(network.site_requests) == len(connections) == 1
		assert not network.errors


async def test_agent_socks5_rejects_certificate_for_another_hostname_without_retry(tmp_path, monkeypatch):
	async with _local_network(tmp_path, monkeypatch, certificate_hosts=('unrelated.test',)) as (
		network,
		factory,
		connections,
	):
		config, route = _routing('default', network.proxy_url())
		store = _Sessions()
		result = await HttpCheckinRuntime(config, store, client_factory=factory).execute(_account('agentrouter', route))
		assert result['success'] is False
		assert result['outcome'] == 'uncertain' and result['reason'] == 'request_result_unknown'
		assert len(connections) == 1
		assert network.destinations == [(3, 'agentrouter.org', 443)]
		assert network.server_names == ['agentrouter.org']
		assert not network.site_requests and not store.loads and not store.saved
