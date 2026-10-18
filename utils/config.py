#!/usr/bin/env python3
"""
配置管理模块
"""

import json
import os
from dataclasses import dataclass, field
from typing import Dict, List, Literal


@dataclass
class ProviderConfig:
	"""Provider 配置"""

	name: str
	domain: str
	login_path: str = '/login'
	sign_in_path: str | None = '/api/user/sign_in'
	user_info_path: str = '/api/user/self'
	api_user_key: str = 'new-api-user'
	bypass_method: Literal['waf_cookies'] | None = None
	waf_cookie_names: List[str] | None = None
	use_proxy: bool = False
	persist_profile: bool = False
	status_path: str = '/api/status'
	auth_state_path: str = '/api/oauth/state'
	oauth_client_ids: dict[str, str] = field(default_factory=dict)

	def __post_init__(self):
		required_waf_cookies = set()
		if self.waf_cookie_names and isinstance(self.waf_cookie_names, List):
			for item in self.waf_cookie_names:
				name = '' if not item or not isinstance(item, str) else item.strip()
				if not name:
					print(f'[WARNING] Found invalid WAF cookie name: {item}')
					continue

				required_waf_cookies.add(name)

		if not required_waf_cookies:
			self.bypass_method = None

		self.waf_cookie_names = list(required_waf_cookies)

	@classmethod
	def from_dict(cls, name: str, data: dict, *, defaults: 'ProviderConfig | None' = None) -> 'ProviderConfig':
		"""从字典创建 ProviderConfig

		配置格式:
		- 基础: {"domain": "https://example.com"}
		- 完整: {"domain": "https://example.com", "login_path": "/login", "use_proxy": true, ...}
		"""
		default_use_proxy = defaults.use_proxy if defaults else False
		default_persist_profile = defaults.persist_profile if defaults else False
		return cls(
			name=name,
			domain=data['domain'],
			login_path=data.get('login_path', defaults.login_path if defaults else '/login'),
			sign_in_path=data.get('sign_in_path', defaults.sign_in_path if defaults else '/api/user/sign_in'),
			user_info_path=data.get('user_info_path', defaults.user_info_path if defaults else '/api/user/self'),
			api_user_key=data.get('api_user_key', defaults.api_user_key if defaults else 'new-api-user'),
			bypass_method=data.get('bypass_method', defaults.bypass_method if defaults else None),
			waf_cookie_names=data.get('waf_cookie_names', defaults.waf_cookie_names if defaults else None),
			use_proxy=data.get('use_proxy', default_use_proxy),
			persist_profile=data.get('persist_profile', default_persist_profile),
			status_path=data.get('status_path', defaults.status_path if defaults else '/api/status'),
			auth_state_path=data.get('auth_state_path', defaults.auth_state_path if defaults else '/api/oauth/state'),
			oauth_client_ids=data.get('oauth_client_ids', defaults.oauth_client_ids if defaults else {}),
		)

	def needs_waf_cookies(self) -> bool:
		"""判断是否需要获取 WAF cookies"""
		return self.bypass_method == 'waf_cookies'

	def needs_manual_check_in(self) -> bool:
		"""判断是否需要手动调用签到接口"""
		return self.sign_in_path is not None


@dataclass
class AppConfig:
	"""应用配置"""

	providers: Dict[str, ProviderConfig]
	identities: dict[str, 'IdentityConfig'] = field(default_factory=dict)

	@classmethod
	def load_from_env(cls) -> 'AppConfig':
		"""从环境变量加载配置"""
		identities = load_identities_config()
		providers = {
			'anyrouter': ProviderConfig(
				name='anyrouter',
				domain='https://anyrouter.top',
				login_path='/login',
				sign_in_path='/api/user/sign_in',
				user_info_path='/api/user/self',
				api_user_key='new-api-user',
				bypass_method='waf_cookies',
				waf_cookie_names=['acw_tc', 'cdn_sec_tc', 'acw_sc__v2'],
				use_proxy=False,
				persist_profile=True,
			),
			'agentrouter': ProviderConfig(
				name='agentrouter',
				domain='https://agentrouter.org',
				login_path='/login',
				sign_in_path=None,  # 无需签到接口，查询用户信息时自动完成签到
				user_info_path='/api/user/self',
				api_user_key='new-api-user',
				bypass_method='waf_cookies',
				waf_cookie_names=['acw_tc'],
				use_proxy=True,
				persist_profile=False,
			),
		}

		# 尝试从环境变量加载自定义 providers
		providers_str = os.getenv('PROVIDERS')
		if providers_str:
			try:
				providers_data = json.loads(providers_str)

				if not isinstance(providers_data, dict):
					print('[WARNING] PROVIDERS must be a JSON object, ignoring custom providers')
					return cls(providers=providers, identities=identities)

				# 解析自定义 providers,会覆盖默认配置
				for name, provider_data in providers_data.items():
					try:
						providers[name] = ProviderConfig.from_dict(
							name,
							provider_data,
							defaults=providers.get(name),
						)
					except Exception as e:
						print(f'[WARNING] Failed to parse provider "{name}": {e}, skipping')
						continue

				print(f'[INFO] Loaded {len(providers_data)} custom provider(s) from PROVIDERS environment variable')
			except json.JSONDecodeError as e:
				print(
					f'[WARNING] Failed to parse PROVIDERS environment variable: {e}, using default configuration only'
				)
			except Exception as e:
				print(f'[WARNING] Error loading PROVIDERS: {e}, using default configuration only')

		return cls(providers=providers, identities=identities)

	def get_provider(self, name: str) -> ProviderConfig | None:
		"""获取指定 provider 配置"""
		return self.providers.get(name)


@dataclass
class AccountConfig:
	"""账号配置"""

	cookies: dict | str | None = field(repr=False)
	api_user: str | None = None
	provider: str = 'anyrouter'
	name: str | None = None
	email: str | None = None
	password: str | None = field(default=None, repr=False)
	id: str | None = None
	auth: dict[str, str] | None = None
	expected_username: str | None = None
	proxy: str | None = field(default=None, repr=False)

	@classmethod
	def from_dict(cls, data: dict, index: int) -> 'AccountConfig':
		"""从字典创建 AccountConfig"""
		provider = data.get('provider', 'anyrouter')
		name = data.get('name', f'Account {index + 1}')

		return cls(
			cookies=data.get('cookies'),
			api_user=data.get('api_user'),
			provider=provider,
			name=name if name else None,
			email=data.get('email'),
			password=data.get('password'),
			id=data.get('id'),
			auth=data.get('auth'),
			expected_username=data.get('expected_username'),
			proxy=data.get('proxy'),
		)

	def has_login_credentials(self) -> bool:
		"""是否配置了邮箱密码登录"""
		return bool(self.email and self.password)

	def has_oauth(self) -> bool:
		return bool(self.auth and self.auth.get('type') in {'linuxdo', 'github'})

	def get_display_name(self, index: int) -> str:
		"""获取显示名称"""
		return self.name if self.name else f'Account {index + 1}'


def load_accounts_config() -> list[AccountConfig] | None:
	"""从环境变量加载账号配置"""
	accounts_str = os.getenv('ANYROUTER_ACCOUNTS')
	if not accounts_str:
		print('ERROR: ANYROUTER_ACCOUNTS environment variable not found')
		return None

	try:
		accounts_data = json.loads(accounts_str)
	except json.JSONDecodeError as e:
		print(f'ERROR: ANYROUTER_ACCOUNTS JSON 解析失败: {e}')
		print('HINT: 常见原因 - 末尾多余逗号、使用了单引号、包含注释、或换行格式问题')
		return None

	try:
		if not isinstance(accounts_data, list):
			print('ERROR: Account configuration must use array format [{}]')
			return None

		accounts = []
		for i, account_dict in enumerate(accounts_data):
			if not isinstance(account_dict, dict):
				print(f'ERROR: Account {i + 1} configuration format is incorrect')
				return None

			auth = account_dict.get('auth')
			if auth is not None:
				if (
					not isinstance(auth, dict)
					or auth.get('type') not in {'linuxdo', 'github'}
					or not isinstance(auth.get('identity'), str)
					or not auth['identity'].strip()
				):
					print(f'ERROR: Account {i + 1} has invalid OAuth configuration')
					return None
				if not account_dict.get('api_user') and not account_dict.get('expected_username'):
					print(f'ERROR: Account {i + 1} OAuth requires api_user or expected_username for identity binding')
					return None
				if account_dict.get('email') or account_dict.get('password') or account_dict.get('cookies'):
					print(f'ERROR: Account {i + 1} cannot mix OAuth with cookies or password credentials')
					return None

			if 'api_user' not in account_dict and not auth:
				has_login = account_dict.get('email') and account_dict.get('password')
				if not has_login:
					print(
						f'ERROR: Account {i + 1} missing required field (api_user) - only email+password login can omit it'
					)
					return None

			has_cookies = 'cookies' in account_dict and account_dict['cookies']
			has_login = account_dict.get('email') and account_dict.get('password')

			if not has_cookies and not has_login and not auth:
				print(f'ERROR: Account {i + 1} must have either cookies or email+password')
				return None

			if 'name' in account_dict and not account_dict['name']:
				print(f'ERROR: Account {i + 1} name field cannot be empty')
				return None

			accounts.append(AccountConfig.from_dict(account_dict, i))

		return accounts
	except Exception as e:
		print(f'ERROR: Account configuration format is incorrect: {e}')
		return None


@dataclass(frozen=True)
class IdentityConfig:
	type: Literal['linuxdo', 'github']
	proxy: str | None = field(default=None, repr=False)


def load_identities_config() -> dict[str, IdentityConfig]:
	try:
		payload = json.loads(os.getenv('CHECKIN_IDENTITIES', '').strip() or '{}')
	except json.JSONDecodeError:
		raise ValueError('CHECKIN_IDENTITIES must be valid JSON') from None
	if not isinstance(payload, dict):
		raise ValueError('CHECKIN_IDENTITIES must be an object')
	identities = {}
	for alias, settings in payload.items():
		if not isinstance(alias, str) or not alias.strip() or len(alias) > 128:
			raise ValueError('Identity alias must be a nonempty string of at most 128 characters')
		if not isinstance(settings, dict) or settings.get('type') not in {'linuxdo', 'github'}:
			raise ValueError('Identity type must be linuxdo or github')
		proxy = settings.get('proxy')
		if proxy is not None and not isinstance(proxy, str):
			raise ValueError('Identity proxy must be a string')
		identities[alias] = IdentityConfig(type=settings['type'], proxy=proxy)
	return identities
