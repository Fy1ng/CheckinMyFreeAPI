"""Fy1Push contracts with in-memory HTTP transport only."""

import json
from unittest.mock import Mock
from uuid import UUID

import httpx
import pytest

from utils.fy1push import fy1push_channel, fy1push_endpoint
from utils.logging_safety import redact, sensitive_values
from utils.notify import NotificationKit


@pytest.fixture
def fy1push_kit(monkeypatch):
	monkeypatch.setenv('FY1PUSH_SERVER', 'https://push.example.test')
	monkeypatch.setenv('FY1PUSH_TOKEN', 'synthetic-fy1push-sending-token')
	monkeypatch.delenv('FY1PUSH_CHANNEL', raising=False)
	return NotificationKit()


@pytest.fixture
def transport(monkeypatch):
	requests = []
	options = []
	result = {'response': httpx.Response(200, json={'ok': True, 'accepted': True, 'delivered': None})}
	client_class = httpx.Client

	def handler(request):
		requests.append(request)
		response = result['response']
		if isinstance(response, Exception):
			raise response
		return response

	def client(**kwargs):
		options.append(kwargs)
		return client_class(transport=httpx.MockTransport(handler), **kwargs)

	monkeypatch.setattr('utils.notify.httpx.Client', client)
	return requests, options, result


def test_send_uses_bearer_header_channel_and_single_idempotent_request(fy1push_kit, transport):
	requests, options, _ = transport
	fy1push_kit.send_fy1push('签到执行结果', '成功 1/1. 请在 WebUI 查看执行记录.')
	assert len(requests) == 1
	request = requests[0]
	assert str(request.url) == 'https://push.example.test/v1/push'
	assert request.headers['Authorization'] == 'Bearer synthetic-fy1push-sending-token'
	assert UUID(request.headers['Idempotency-Key']).version == 4
	assert json.loads(request.content) == {
		'title': '签到执行结果',
		'body': '成功 1/1. 请在 WebUI 查看执行记录.',
		'channel': '签到',
	}
	assert options == [{'timeout': 30.0, 'trust_env': False, 'follow_redirects': False}]
	assert b'synthetic-fy1push-sending-token' not in request.content


@pytest.mark.parametrize('channel', ['default', '签到', 'x' * 24, 'éΔ١_𐐀９².-'])
def test_message_summaries_fit_actual_fy1push_unicode_limits(fy1push_kit, transport, channel):
	requests, _, _ = transport
	fy1push_kit.fy1push_channel = channel
	fy1push_kit.send_fy1push('长标题' * 25, '长通知正文' * 60)
	payload = json.loads(requests[0].content)
	assert len(payload['body']) == 100 and payload['body'].endswith('...')
	rendered_title = payload['title'] if channel == 'default' else f'【来源：{channel}】' + payload['title']
	assert len(rendered_title) == 40 and payload['title'].endswith('...')
	assert payload['channel'] == channel


@pytest.mark.parametrize(
	'server',
	[
		'https://push.example.test',
		'https://push.example.test/',
		'https://push.example.test/v1/push',
		'https://push.example.test/v1/push/',
	],
)
def test_endpoint_never_duplicates_v1_push(server):
	assert fy1push_endpoint(server) == 'https://push.example.test/v1/push'


@pytest.mark.parametrize('server', ['http://localhost:8787', 'http://127.0.0.1:8787', 'http://[::1]:8787'])
def test_local_http_service_is_supported(server):
	assert fy1push_endpoint(server) == server + '/v1/push'


@pytest.mark.parametrize(
	'server',
	[
		'http://push.example.test',
		'https://name:synthetic-secret@push.example.test',
		'https://push.example.test?token=synthetic-secret',
		'https://push.example.test/#synthetic-secret',
		'https://push.example.test/other',
		'file:///tmp/test',
		'https://push.example.test:invalid',
		'https://push.example.test:0',
		'https://push.example.test:',
	],
)
def test_invalid_server_is_rejected_without_echoing_input(server):
	with pytest.raises(ValueError) as failure:
		fy1push_endpoint(server)
	assert server not in str(failure.value)
	assert 'synthetic-secret' not in str(failure.value)


@pytest.mark.parametrize('channel', ['two words', 'x' * 25, ' name', 'name ', '[name]', '😀'])
def test_invalid_channel_is_rejected(channel):
	with pytest.raises(ValueError):
		fy1push_channel(channel)
	assert fy1push_channel('') == '签到'


@pytest.mark.parametrize('status', [302, 400, 401, 429, 500, 503])
def test_http_failures_do_not_retry_or_reflect_response_body(fy1push_kit, transport, status):
	requests, _, result = transport
	result['response'] = httpx.Response(
		status, text='synthetic-secret must not be logged', headers={'Location': 'https://other.example.test'}
	)
	with pytest.raises(RuntimeError, match=f'HTTP {status}') as failure:
		fy1push_kit.send_fy1push('通知', '正文')
	assert len(requests) == 1
	assert 'synthetic-secret' not in str(failure.value)


@pytest.mark.parametrize(
	'payload',
	[
		None,
		[],
		{'ok': False, 'accepted': False},
		{'ok': True},
		{'ok': 1, 'accepted': 1},
		{'ok': True, 'accepted': False, 'error': 'synthetic-secret'},
	],
)
def test_200_without_explicit_acceptance_is_not_success(fy1push_kit, transport, payload):
	requests, _, result = transport
	result['response'] = httpx.Response(200, json=payload)
	with pytest.raises(RuntimeError) as failure:
		fy1push_kit.send_fy1push('通知', '正文')
	assert len(requests) == 1
	assert 'synthetic-secret' not in str(failure.value)


def test_network_timeout_is_uncertain_and_never_retried(fy1push_kit, transport):
	requests, _, result = transport
	result['response'] = httpx.ReadTimeout('synthetic-secret')
	with pytest.raises(RuntimeError, match='outcome unknown; no automatic retry') as failure:
		fy1push_kit.send_fy1push('通知', '正文')
	assert len(requests) == 1
	assert 'synthetic-secret' not in str(failure.value)


@pytest.mark.parametrize(
	'field,value',
	[
		('fy1push_token', ''),
		('fy1push_server', ''),
		('fy1push_token', 'synthetic\ninjection'),
		('fy1push_channel', 'invalid channel'),
	],
)
def test_invalid_configuration_never_sends(fy1push_kit, transport, field, value):
	requests, _, _ = transport
	setattr(fy1push_kit, field, value)
	with pytest.raises(ValueError):
		fy1push_kit.send_fy1push('通知', '正文')
	assert requests == []


def test_dispatch_acceptance_does_not_claim_device_delivery(fy1push_kit, transport, monkeypatch, capsys):
	for name in (
		'send_email',
		'send_pushplus',
		'send_serverPush',
		'send_dingtalk',
		'send_feishu',
		'send_wecom',
		'send_gotify',
		'send_telegram',
		'send_bark',
	):
		monkeypatch.setattr(fy1push_kit, name, Mock())
	fy1push_kit.push_message('通知', '正文')
	output = capsys.readouterr().out
	assert '[Fy1Push]: Request accepted; device delivery not confirmed' in output
	assert '[Fy1Push]: Message push successful' not in output
	assert 'synthetic-fy1push-sending-token' not in output
	fy1push_kit.fy1push_server = ''
	send = Mock()
	monkeypatch.setattr(fy1push_kit, 'send_fy1push', send)
	fy1push_kit.push_message('通知', '正文')
	send.assert_not_called()


def test_fy1push_token_is_included_in_log_redaction(monkeypatch):
	monkeypatch.setenv('FY1PUSH_TOKEN', 'synthetic-fy1push-token')
	values = sensitive_values()
	assert 'synthetic-fy1push-token' in values
	assert redact('Bearer synthetic-fy1push-token', values) == 'Bearer [REDACTED]'
