import json

import pytest

from utils.auth_runtime import build_plans, check_expected_user
from utils.config import AccountConfig, AppConfig, IdentityConfig, load_accounts_config
from utils.oauth import AuthError
from utils.proxy import playwright_proxy, resolve_proxy


@pytest.mark.parametrize('value', ['', '   '])
def test_empty_optional_identity_secret_allows_site_accounts(monkeypatch, value):
	monkeypatch.setenv('CHECKIN_IDENTITIES', value)
	assert AppConfig.load_from_env().identities == {}


def oauth_account(provider='anyrouter', **kwargs):
	return AccountConfig(
		cookies=None,
		provider=provider,
		name=provider + '-linuxdo',
		auth={'type': 'linuxdo', 'identity': 'main'},
		expected_username='expected-user',
		**kwargs,
	)


def test_shared_identity_uses_one_profile_and_explicit_stable_proxy(monkeypatch):
	monkeypatch.setenv('CHECKIN_PROXY_URL', 'http://user:example-pass@proxy.test:8080')
	config = AppConfig.load_from_env()
	config.identities = {'main': IdentityConfig('linuxdo', proxy='default')}
	accounts = [
		oauth_account(),
		oauth_account('agentrouter'),
		AccountConfig(None, email='site-user', password='example-pass', name='direct-site'),
	]
	plans = build_plans(accounts, config)
	assert plans[0].profile_key == plans[1].profile_key
	assert plans[0].account_key != plans[1].account_key
	assert plans[0].proxy == plans[1].proxy
	assert plans[2].proxy is None
	assert 'example-pass' not in repr(plans)


def test_implicit_shared_identity_proxy_conflict_is_rejected(monkeypatch):
	monkeypatch.setenv('CHECKIN_PROXY_URL', 'http://proxy.test:8080')
	config = AppConfig.load_from_env()
	config.identities = {'main': IdentityConfig('linuxdo')}
	with pytest.raises(AuthError, match='SHARED_IDENTITY_PROXY_CONFLICT'):
		build_plans([oauth_account(), oauth_account('agentrouter')], config)


def test_unknown_identity_rejected():
	with pytest.raises(AuthError, match='OAUTH_IDENTITY_NOT_CONFIGURED'):
		build_plans([oauth_account()], AppConfig.load_from_env())


def test_proxy_is_required_and_never_silently_direct(monkeypatch):
	monkeypatch.delenv('CHECKIN_PROXY_URL', raising=False)
	with pytest.raises(ValueError, match='required'):
		resolve_proxy(None, use_proxy=True)
	assert resolve_proxy('direct', use_proxy=True) is None
	assert resolve_proxy(None, use_proxy=False) is None


def test_proxy_credentials_are_separated_and_decoded():
	assert playwright_proxy('http://name%40example:p%3Ass%40word@proxy.test:8080') == {
		'server': 'http://proxy.test:8080',
		'username': 'name@example',
		'password': 'p:ss@word',
	}


@pytest.mark.parametrize(
	'proxy',
	[
		'http://proxy.test',
		'file:///tmp/test',
		'http://proxy.test:abc',
		'http://proxy.test:8080/?secret=x',
		'socks5://name:pass@proxy.test:8080',
	],
)
def test_invalid_proxy_fails_without_exposing_input(proxy):
	with pytest.raises(ValueError) as error:
		resolve_proxy(proxy)
	assert proxy not in str(error.value)


def test_oauth_schema_accepts_bound_account_without_exported_cookies(monkeypatch):
	monkeypatch.setenv(
		'ANYROUTER_ACCOUNTS',
		json.dumps(
			[
				{
					'id': 'stable-id',
					'name': 'LinuxDo',
					'expected_username': 'expected-user',
					'auth': {'type': 'linuxdo', 'identity': 'main'},
				}
			]
		),
	)
	accounts = load_accounts_config()
	assert accounts and accounts[0].has_oauth()
	assert accounts[0].id == 'stable-id'


@pytest.mark.parametrize(
	'extra',
	[{}, {'cookies': 'session=fake', 'expected_username': 'user'}, {'password': 'fake', 'expected_username': 'user'}],
)
def test_oauth_rejects_unbound_or_mixed_credentials(monkeypatch, extra):
	monkeypatch.setenv('ANYROUTER_ACCOUNTS', json.dumps([{'auth': {'type': 'linuxdo', 'identity': 'main'}, **extra}]))
	assert load_accounts_config() is None


def test_stable_account_ids_do_not_depend_on_array_order():
	config = AppConfig.load_from_env()
	accounts = [
		AccountConfig(None, id='one', email='first', password='fake'),
		AccountConfig(None, id='two', email='second', password='fake'),
	]
	first = build_plans(accounts, config)
	second = build_plans(list(reversed(accounts)), config)
	assert first[0].account_key == second[1].account_key
	assert first[0].profile_key == second[1].profile_key


@pytest.mark.parametrize(
	'user,saved',
	[
		({'id': 8, 'username': 'expected-user'}, '7'),
		({'id': 7, 'username': 'wrong-user'}, None),
		({'id': True, 'username': 'expected-user'}, None),
	],
)
def test_wrong_account_is_rejected_before_checkin(user, saved):
	with pytest.raises(AuthError):
		check_expected_user(oauth_account(), user, saved_id=saved)
