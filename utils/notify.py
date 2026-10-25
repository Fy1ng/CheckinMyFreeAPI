import os
import smtplib
from email.mime.text import MIMEText
from typing import Any, Literal
from uuid import uuid4

import httpx

from utils.fy1push import fy1push_channel, fy1push_endpoint, fy1push_summary, validate_fy1push_token


class NotificationRejected(RuntimeError):
	"""The provider explicitly rejected this notification."""


class NotificationKit:
	def __init__(self):
		self.email_user: str = os.getenv('EMAIL_USER', '')
		self.email_pass: str = os.getenv('EMAIL_PASS', '')
		self.email_to: str = os.getenv('EMAIL_TO', '')
		self.email_sender: str = os.getenv('EMAIL_SENDER', '')
		self.smtp_server: str = os.getenv('CUSTOM_SMTP_SERVER', '')
		self.pushplus_token = os.getenv('PUSHPLUS_TOKEN')
		self.server_push_key = os.getenv('SERVERPUSHKEY')
		self.dingding_webhook = os.getenv('DINGDING_WEBHOOK')
		self.feishu_webhook = os.getenv('FEISHU_WEBHOOK')
		self.weixin_webhook = os.getenv('WEIXIN_WEBHOOK')
		self.gotify_url = os.getenv('GOTIFY_URL')
		self.gotify_token = os.getenv('GOTIFY_TOKEN')
		gotify_priority_env = os.getenv('GOTIFY_PRIORITY', '9')
		self.gotify_priority = int(gotify_priority_env) if gotify_priority_env.strip() else 9
		self.telegram_bot_token = os.getenv('TELEGRAM_BOT_TOKEN')
		self.telegram_chat_id = os.getenv('TELEGRAM_CHAT_ID')
		self.bark_key = os.getenv('BARK_KEY')
		self.bark_server = os.getenv('BARK_SERVER', 'https://api.day.app')
		self.fy1push_server = os.getenv('FY1PUSH_SERVER', '')
		self.fy1push_token = os.getenv('FY1PUSH_TOKEN', '')
		self.fy1push_channel = os.getenv('FY1PUSH_CHANNEL', '')

	def _post_json(self, service: str, url: str, data: dict[str, Any]) -> httpx.Response:
		with httpx.Client(timeout=30.0) as client:
			response = client.post(url, json=data)

		if not 200 <= response.status_code < 300:
			raise NotificationRejected(f'{service} request failed: HTTP {response.status_code}')

		try:
			payload = response.json()
		except ValueError:
			return response

		if not isinstance(payload, dict):
			return response

		error_msg = payload.get('errmsg') or payload.get('message') or payload.get('msg') or payload.get('error')
		if payload.get('ok') is False:
			raise NotificationRejected(
				f'{service} request failed: {error_msg or payload.get("description") or "ok=false"}'
			)
		if payload.get('errcode') not in (None, 0):
			raise NotificationRejected(f'{service} request failed: {error_msg or payload.get("errcode")}')
		if payload.get('StatusCode') not in (None, 0):
			raise NotificationRejected(f'{service} request failed: {error_msg or payload.get("StatusCode")}')
		if payload.get('code') not in (None, 0, 200):
			raise NotificationRejected(f'{service} request failed: {error_msg or payload.get("code")}')
		if payload.get('ret') not in (None, 0, 1, 200):
			raise NotificationRejected(f'{service} request failed: {error_msg or payload.get("ret")}')

		return response

	def send_email(self, title: str, content: str, msg_type: Literal['text', 'html'] = 'text'):
		if not self.email_user or not self.email_pass or not self.email_to:
			raise ValueError('Email configuration not set')

		# 如果未设置 EMAIL_SENDER，使用 EMAIL_USER 作为默认值
		sender = self.email_sender if self.email_sender else self.email_user

		# MIMEText 需要 'plain' 或 'html'，而不是 'text'
		mime_subtype = 'plain' if msg_type == 'text' else 'html'
		msg = MIMEText(content, mime_subtype, 'utf-8')
		msg['From'] = f'AnyRouter Assistant <{sender}>'
		msg['To'] = self.email_to
		msg['Subject'] = title

		smtp_server = self.smtp_server if self.smtp_server else f'smtp.{self.email_user.split("@")[1]}'
		with smtplib.SMTP_SSL(smtp_server, 465, timeout=30) as server:
			server.login(self.email_user, self.email_pass)
			if server.send_message(msg):
				raise NotificationRejected('SMTP did not accept all recipients')

	def send_pushplus(self, title: str, content: str):
		if not self.pushplus_token:
			raise ValueError('PushPlus Token not configured')

		data = {'token': self.pushplus_token, 'title': title, 'content': content, 'template': 'html'}
		self._post_json('PushPlus', 'http://www.pushplus.plus/send', data)

	def send_serverPush(self, title: str, content: str):
		if not self.server_push_key:
			raise ValueError('Server Push key not configured')

		data = {'title': title, 'desp': content}
		self._post_json('Server Push', f'https://sctapi.ftqq.com/{self.server_push_key}.send', data)

	def send_dingtalk(self, title: str, content: str):
		if not self.dingding_webhook:
			raise ValueError('DingTalk Webhook not configured')

		data = {'msgtype': 'text', 'text': {'content': f'{title}\n{content}'}}
		self._post_json('DingTalk', self.dingding_webhook, data)

	def send_feishu(self, title: str, content: str):
		if not self.feishu_webhook:
			raise ValueError('Feishu Webhook not configured')

		data = {
			'msg_type': 'interactive',
			'card': {
				'elements': [{'tag': 'markdown', 'content': content, 'text_align': 'left'}],
				'header': {'template': 'blue', 'title': {'content': title, 'tag': 'plain_text'}},
			},
		}
		self._post_json('Feishu', self.feishu_webhook, data)

	def send_wecom(self, title: str, content: str):
		if not self.weixin_webhook:
			raise ValueError('WeChat Work Webhook not configured')

		data = {'msgtype': 'text', 'text': {'content': f'{title}\n{content}'}}
		self._post_json('WeChat Work', self.weixin_webhook, data)

	def send_gotify(self, title: str, content: str):
		if not self.gotify_url or not self.gotify_token:
			raise ValueError('Gotify URL or Token not configured')

		# 使用环境变量配置的优先级，默认为9
		priority = self.gotify_priority

		# 确保优先级在有效范围内 (1-10)
		priority = max(1, min(10, priority))

		data = {'title': title, 'message': content, 'priority': priority}

		url = f'{self.gotify_url}?token={self.gotify_token}'
		self._post_json('Gotify', url, data)

	def send_telegram(self, title: str, content: str):
		if not self.telegram_bot_token or not self.telegram_chat_id:
			raise ValueError('Telegram Bot Token or Chat ID not configured')

		message = f'<b>{title}</b>\n\n{content}'
		data = {'chat_id': self.telegram_chat_id, 'text': message, 'parse_mode': 'HTML'}
		url = f'https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage'
		self._post_json('Telegram', url, data)

	def send_bark(self, title: str, content: str):
		if not self.bark_key:
			raise ValueError('Bark Key not configured')

		# Bark API 支持 GET/POST，这里使用 POST JSON 方式支持更多参数
		# 文档: https://bark.day.app/#/tutorial
		url = f'{self.bark_server.rstrip("/")}/push'
		data = {
			'device_key': self.bark_key,
			'title': title,
			'body': content,
			'icon': 'https://anyrouter.top/favicon.ico',  # 可选：尝试使用 AnyRouter 图标
			'group': 'AnyRouter',
		}

		self._post_json('Bark', url, data)

	def send_fy1push(self, title: str, content: str):
		if not self.fy1push_server or not self.fy1push_token:
			raise ValueError('Fy1Push server or sending token not configured')
		endpoint = fy1push_endpoint(self.fy1push_server)
		channel = fy1push_channel(self.fy1push_channel)
		validate_fy1push_token(self.fy1push_token)
		title_limit = 40 if channel == 'default' else 40 - 5 - len(channel)
		payload = {
			'title': fy1push_summary(title, title_limit),
			'body': fy1push_summary(content, 100),
			'channel': channel,
		}
		headers = {'Authorization': 'Bearer ' + self.fy1push_token, 'Idempotency-Key': str(uuid4())}
		try:
			with httpx.Client(timeout=30.0, trust_env=False, follow_redirects=False) as client:
				response = client.post(endpoint, json=payload, headers=headers)
		except httpx.HTTPError:
			raise RuntimeError('Fy1Push request outcome unknown; no automatic retry') from None
		if response.status_code != 200:
			raise NotificationRejected(f'Fy1Push request failed: HTTP {response.status_code}')
		try:
			result = response.json()
		except ValueError:
			raise RuntimeError('Fy1Push returned an invalid response; delivery is unconfirmed') from None
		if not isinstance(result, dict) or result.get('ok') is not True or result.get('accepted') is not True:
			raise RuntimeError('Fy1Push did not confirm acceptance; no automatic retry')

	def deliver_message(self, title: str, content: str, msg_type: Literal['text', 'html'] = 'text') -> dict:
		"""Return acceptance evidence for configured channels without printing raw failures.

		One attempt per channel. An unknown result is deliberately not retried, and
		provider acceptance never means that a phone displayed the notification.
		"""
		channels = [
			(
				'Email',
				bool(self.email_user and self.email_pass and self.email_to),
				lambda: self.send_email(title, content, msg_type),
			),
			('PushPlus', bool(self.pushplus_token), lambda: self.send_pushplus(title, content)),
			('Server Push', bool(self.server_push_key), lambda: self.send_serverPush(title, content)),
			('DingTalk', bool(self.dingding_webhook), lambda: self.send_dingtalk(title, content)),
			('Feishu', bool(self.feishu_webhook), lambda: self.send_feishu(title, content)),
			('WeChat Work', bool(self.weixin_webhook), lambda: self.send_wecom(title, content)),
			('Gotify', bool(self.gotify_url and self.gotify_token), lambda: self.send_gotify(title, content)),
			(
				'Telegram',
				bool(self.telegram_bot_token and self.telegram_chat_id),
				lambda: self.send_telegram(title, content),
			),
			('Bark', bool(self.bark_key), lambda: self.send_bark(title, content)),
			('Fy1Push', bool(self.fy1push_server and self.fy1push_token), lambda: self.send_fy1push(title, content)),
		]
		results = []
		for name, configured, send in channels:
			if not configured:
				continue
			try:
				send()
				results.append({'channel': name, 'state': 'accepted', 'error_code': None})
			except NotificationRejected:
				results.append({'channel': name, 'state': 'failed', 'error_code': 'notification_rejected'})
			except RuntimeError:
				results.append({'channel': name, 'state': 'unknown', 'error_code': 'provider_acceptance_unconfirmed'})
			except Exception:
				results.append({'channel': name, 'state': 'unknown', 'error_code': 'notification_outcome_unknown'})
		states = {result['state'] for result in results}
		state = (
			'not_configured'
			if not results
			else 'accepted'
			if states == {'accepted'}
			else 'partial'
			if 'accepted' in states
			else 'failed'
			if states == {'failed'}
			else 'unknown'
		)
		return {'state': state, 'channels': results, 'device_delivery': 'unconfirmed'}

	def push_message(self, title: str, content: str, msg_type: Literal['text', 'html'] = 'text'):
		notifications = [
			('Email', lambda: self.send_email(title, content, msg_type)),
			('PushPlus', lambda: self.send_pushplus(title, content)),
			('Server Push', lambda: self.send_serverPush(title, content)),
			('DingTalk', lambda: self.send_dingtalk(title, content)),
			('Feishu', lambda: self.send_feishu(title, content)),
			('WeChat Work', lambda: self.send_wecom(title, content)),
			('Gotify', lambda: self.send_gotify(title, content)),
			('Telegram', lambda: self.send_telegram(title, content)),
			('Bark', lambda: self.send_bark(title, content)),
		]
		if self.fy1push_server:
			notifications.append(('Fy1Push', lambda: self.send_fy1push(title, content)))

		for name, func in notifications:
			try:
				func()
				if name == 'Fy1Push':
					print('[Fy1Push]: Request accepted; device delivery not confirmed')
				else:
					print(f'[{name}]: Message push successful!')
			except Exception as e:
				print(f'[{name}]: Message push failed! Reason: {str(e)}')


notify = NotificationKit()
