"""Real P-256 WebAuthn signatures, with no physical authenticator or network."""

import copy
import hashlib
import json
import os
import time

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from fido2.cose import ES256
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData, CollectedClientData

from server.config_store import ConflictError
from server.passkeys import PasskeyCeremonies, SecurityError, SecurityStore

ORIGIN = 'https://checkin.example.test'


class Authenticator:
	def __init__(self):
		self.key = ec.generate_private_key(ec.SECP256R1())
		self.id = os.urandom(32)
		self.counter = 0

	def response(
		self,
		options,
		*,
		registration=False,
		origin=ORIGIN,
		uv=True,
		cross_origin=False,
		top_origin=None,
		handle=None,
		backup=False,
		backed_up=False,
	):
		public = options['publicKey']
		flags = AuthenticatorData.FLAG.UP | (AuthenticatorData.FLAG.UV if uv else 0)
		flags |= AuthenticatorData.FLAG.BE if backup else 0
		flags |= AuthenticatorData.FLAG.BS if backed_up else 0
		rp = public['rp']['id'] if registration else public['rpId']
		client = CollectedClientData.create(
			'webauthn.create' if registration else 'webauthn.get',
			websafe_decode(public['challenge']),
			origin,
			cross_origin,
			**({'topOrigin': top_origin} if top_origin else {}),
		)
		response: dict
		if registration:
			credential = AttestedCredentialData.create(
				b'\0' * 16, self.id, ES256.from_cryptography_key(self.key.public_key())
			)
			auth = AuthenticatorData.create(
				hashlib.sha256(rp.encode()).digest(), flags | AuthenticatorData.FLAG.AT, self.counter, bytes(credential)
			)
			response = {
				'attestationObject': websafe_encode(bytes(AttestationObject.create('none', auth, {}))),
				'clientDataJSON': websafe_encode(bytes(client)),
				'transports': ['internal'],
			}
		else:
			auth = AuthenticatorData.create(hashlib.sha256(rp.encode()).digest(), flags, self.counter)
			response = {
				'authenticatorData': websafe_encode(bytes(auth)),
				'clientDataJSON': websafe_encode(bytes(client)),
				'signature': websafe_encode(self.key.sign(bytes(auth) + client.hash, ec.ECDSA(hashes.SHA256()))),
				'userHandle': websafe_encode(handle) if handle else None,
			}
		return {
			'id': websafe_encode(self.id),
			'rawId': websafe_encode(self.id),
			'type': 'public-key',
			'response': response,
			'clientExtensionResults': {},
		}


def registered(tmp_path, *, backup=False):
	store = SecurityStore(tmp_path / 'security.sqlite3')
	ceremonies = PasskeyCeremonies(store)
	device = Authenticator()
	options = ceremonies.begin('register', ORIGIN, 'session', label='Synthetic key')
	identifier = ceremonies.complete(
		'register', options['ticket'], device.response(options, registration=True, backup=backup), ORIGIN, 'session'
	)
	return store, ceremonies, device, identifier


def test_registration_assertion_and_mode_require_verified_possession(tmp_path):
	store, ceremonies, device, identifier = registered(tmp_path)
	try:
		assert not store.public(ORIGIN)['passkey_available']
		with pytest.raises(SecurityError):
			store.set_mode('passkey', store.policy()['revision'], ORIGIN, 'password')
		options = ceremonies.begin('reauth', ORIGIN, 'session')
		device.counter = 1
		assert (
			ceremonies.complete(
				'reauth',
				options['ticket'],
				device.response(options, handle=store.policy()['user_handle']),
				ORIGIN,
				'session',
			)
			== identifier
		)
		assert store.public(ORIGIN)['passkey_available']
		store.set_mode('passkey', store.policy()['revision'], ORIGIN, 'passkey')
		assert store.policy()['mode'] == 'passkey'
		with pytest.raises(SecurityError, match='最后'):
			store.remove(identifier, store.policy()['revision'], ORIGIN)
		with pytest.raises(ConflictError):
			store.set_mode('password', 1, ORIGIN, 'passkey')
	finally:
		store.close()


@pytest.mark.parametrize(
	'changes',
	[
		{'origin': 'https://attacker.example'},
		{'uv': False},
		{'cross_origin': True},
		{'top_origin': ORIGIN},
		{'handle': b'wrong-user'},
	],
)
def test_signed_but_wrong_origin_uv_cross_origin_or_user_handle_is_rejected(tmp_path, changes):
	store, ceremonies, device, _ = registered(tmp_path)
	try:
		options = ceremonies.begin('login', ORIGIN, 'browser')
		device.counter = 1
		with pytest.raises(SecurityError):
			ceremonies.complete('login', options['ticket'], device.response(options, **changes), ORIGIN, 'browser')
		assert not store.public(ORIGIN)['passkey_available']
	finally:
		store.close()


def test_signature_challenge_and_rp_hash_are_checked(tmp_path):
	store, ceremonies, device, _ = registered(tmp_path)
	try:
		for change in ['signature', 'challenge', 'rp']:
			options = ceremonies.begin('login', ORIGIN, 'browser')
			signed = copy.deepcopy(options)
			if change == 'challenge':
				signed['publicKey']['challenge'] = websafe_encode(os.urandom(32))
			if change == 'rp':
				signed['publicKey']['rpId'] = 'wrong.example'
			response = device.response(signed)
			if change == 'signature':
				response['response']['signature'] = websafe_encode(b'invalid-signature')
			with pytest.raises(SecurityError):
				ceremonies.complete('login', options['ticket'], response, ORIGIN, 'browser')
	finally:
		store.close()


def test_login_ticket_is_single_use_expiring_and_browser_bound(tmp_path):
	store, ceremonies, device, _ = registered(tmp_path)
	try:
		options = ceremonies.begin('login', ORIGIN, 'browser')
		response = device.response(options)
		with pytest.raises(SecurityError):
			ceremonies.complete('login', options['ticket'], response, ORIGIN, 'other-browser')
		with pytest.raises(SecurityError):
			ceremonies.complete('login', options['ticket'], response, ORIGIN, 'browser')
		options = ceremonies.begin('login', ORIGIN, 'browser')
		ceremonies.pending[options['ticket']]['expires'] = time.monotonic() - 1
		with pytest.raises(SecurityError):
			ceremonies.complete('login', options['ticket'], device.response(options), ORIGIN, 'browser')
		options = ceremonies.begin('login', ORIGIN, 'browser')
		response = device.response(options)
		ceremonies.complete('login', options['ticket'], response, ORIGIN, 'browser')
		with pytest.raises(SecurityError):
			ceremonies.complete('login', options['ticket'], response, ORIGIN, 'browser')
	finally:
		store.close()


def test_clone_counter_is_rejected_but_synced_zero_counters_work(tmp_path):
	store, ceremonies, device, _ = registered(tmp_path, backup=True)
	try:
		for _ in range(2):
			options = ceremonies.begin('login', ORIGIN, 'browser')
			ceremonies.complete(
				'login', options['ticket'], device.response(options, backup=True, backed_up=True), ORIGIN, 'browser'
			)
		device.counter = 5
		options = ceremonies.begin('login', ORIGIN, 'browser')
		ceremonies.complete('login', options['ticket'], device.response(options, backup=True), ORIGIN, 'browser')
		options = ceremonies.begin('login', ORIGIN, 'browser')
		with pytest.raises(SecurityError, match='计数器'):
			ceremonies.complete('login', options['ticket'], device.response(options, backup=True), ORIGIN, 'browser')
	finally:
		store.close()


def test_backup_eligibility_cannot_change_and_bs_requires_be(tmp_path):
	store, ceremonies, device, _ = registered(tmp_path)
	try:
		for kwargs in [{'backup': True}, {'backed_up': True}]:
			options = ceremonies.begin('login', ORIGIN, 'browser')
			with pytest.raises(SecurityError):
				ceremonies.complete('login', options['ticket'], device.response(options, **kwargs), ORIGIN, 'browser')
	finally:
		store.close()


def test_reauth_proofs_are_single_use_session_revision_and_method_bound(tmp_path):
	store, ceremonies, _, _ = registered(tmp_path)
	try:
		proof = ceremonies.proof(ORIGIN, 'session', 'password')
		with pytest.raises(SecurityError):
			ceremonies.consume(proof, ORIGIN, 'session', require_passkey=True)
		proof = ceremonies.proof(ORIGIN, 'session', 'passkey')
		assert ceremonies.consume(proof, ORIGIN, 'session', require_passkey=True)['method'] == 'passkey'
		with pytest.raises(SecurityError):
			ceremonies.consume(proof, ORIGIN, 'session', require_passkey=True)
		proof = ceremonies.proof(ORIGIN, 'session', 'passkey')
		store.reset()
		with pytest.raises(SecurityError):
			ceremonies.consume(proof, ORIGIN, 'session', require_passkey=True)
	finally:
		store.close()


@pytest.mark.parametrize('corruption', ['rawId', 'clientDataArray', 'expiredProof'])
def test_malformed_or_expired_authentication_never_updates_credential(tmp_path, corruption):
	store, ceremonies, device, _ = registered(tmp_path)
	try:
		options = ceremonies.begin('login', ORIGIN, 'browser')
		response = device.response(options)
		if corruption == 'rawId':
			response['rawId'] = websafe_encode(os.urandom(32))
		elif corruption == 'clientDataArray':
			response['response']['clientDataJSON'] = websafe_encode(json.dumps([]).encode())
		else:
			ceremonies.pending[options['ticket']]['expires'] = time.monotonic() - 1
		with pytest.raises(SecurityError):
			ceremonies.complete('login', options['ticket'], response, ORIGIN, 'browser')
		assert not store.public(ORIGIN)['passkey_available']
	finally:
		store.close()


def test_challenge_pool_is_bounded_but_full_pool_can_still_complete_existing_request(tmp_path):
	store, ceremonies, device, _ = registered(tmp_path)
	try:
		options = ceremonies.begin('login', ORIGIN, 'browser')
		for _ in range(127):
			ceremonies.begin('login', ORIGIN, 'other-browser')
		assert len(ceremonies.pending) == 128
		with pytest.raises(SecurityError):
			ceremonies.begin('login', ORIGIN, 'extra-browser')
		ceremonies.complete('login', options['ticket'], device.response(options), ORIGIN, 'browser')
		assert len(ceremonies.pending) == 127
	finally:
		store.close()


def test_passkey_rate_limits_are_bounded_and_do_not_trust_client_headers(tmp_path):
	store = SecurityStore(tmp_path / 'db')
	ceremonies = PasskeyCeremonies(store)
	try:
		for _ in range(30):
			assert ceremonies.check_limit('203.0.113.1')
		assert not ceremonies.check_limit('203.0.113.1')
		assert ceremonies.check_limit('203.0.113.2')
	finally:
		store.close()
