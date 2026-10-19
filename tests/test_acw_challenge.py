"""Offline vectors for the strictly bounded, non-executing acw decoder."""

import base64
import re
from collections.abc import Sequence
from pathlib import Path

import pytest

from utils.acw_challenge import is_acw_challenge, solve_acw_sc_v2

CHALLENGE = (Path(__file__).parent / 'fixtures' / 'anyrouter_acw_challenge.html').read_text(encoding='utf-8')
ARG1 = 'B8B78DDA1D5CD2598AAEE9DD6975913AA490BAE3'
SEED = '3000176000856006061501533003690027800375'
PERMUTATION = [
	15,
	35,
	29,
	24,
	33,
	16,
	1,
	38,
	10,
	9,
	19,
	31,
	40,
	27,
	22,
	23,
	25,
	13,
	6,
	11,
	39,
	18,
	20,
	8,
	14,
	21,
	32,
	26,
	2,
	30,
	7,
	4,
	17,
	5,
	3,
	28,
	34,
	37,
	12,
	36,
]


def encoded(value: str) -> str:
	return (
		base64.b64encode(value.encode())
		.decode()
		.rstrip('=')
		.translate(
			str.maketrans(
				'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
				'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/',
			)
		)
	)


def with_mapping(values: Sequence[int | str]) -> str:
	return re.sub(r'for\(var m=\[[^\]]+\]', 'for(var m=[' + ','.join(map(str, values)) + ']', CHALLENGE)


def expected(arg1: str, seed: str = SEED, permutation: list[int] = PERMUTATION) -> str:
	return ''.join(
		f'{int(arg1[permutation[i] - 1] + arg1[permutation[i + 1] - 1], 16) ^ int(seed[i : i + 2], 16):02x}'
		for i in range(0, 40, 2)
	)


def test_known_metapi_vector():
	assert is_acw_challenge(CHALLENGE)
	assert solve_acw_sc_v2(CHALLENGE) == '699dbedad126579b6bc0ebb91eaae8d7af3548b5'


@pytest.mark.parametrize('arg1', ['0' * 40, 'F' * 40, '0123456789abcdef' * 2 + '01234567', ARG1.lower()])
def test_changes_arg1_without_executing_script(arg1):
	assert solve_acw_sc_v2(CHALLENGE.replace(ARG1, arg1)) == expected(arg1)


def test_changes_unique_seed_without_executing_decoder():
	seed = 'ab' * 20
	assert solve_acw_sc_v2(CHALLENGE.replace(encoded(SEED), encoded(seed))) == expected(ARG1, seed)


def test_decimal_mapping_and_changed_permutation():
	assert solve_acw_sc_v2(with_mapping(PERMUTATION)) == expected(ARG1)
	identity = list(range(1, 41))
	assert solve_acw_sc_v2(with_mapping(identity)) == expected(ARG1, permutation=identity)


@pytest.mark.parametrize(
	'values',
	[
		PERMUTATION[:-1],
		[*PERMUTATION, 41],
		[0, *PERMUTATION[1:]],
		[41, *PERMUTATION[1:]],
		[-1, *PERMUTATION[1:]],
		[PERMUTATION[1], *PERMUTATION[1:]],
		['0xf+0', *PERMUTATION[1:]],
		['0x000000f', *PERMUTATION[1:]],
		['x', *PERMUTATION[1:]],
	],
)
def test_rejects_invalid_or_ambiguous_mapping(values):
	assert solve_acw_sc_v2(with_mapping(values)) is None


@pytest.mark.parametrize('arg1', ['f' * 39, 'f' * 41, 'g' * 40, '', 'f' * 4000])
def test_rejects_invalid_argument(arg1):
	assert solve_acw_sc_v2(CHALLENGE.replace(ARG1, arg1)) is None


def test_rejects_duplicate_or_missing_seed():
	for extra in [encoded(SEED), encoded('f' * 40)]:
		assert solve_acw_sc_v2(CHALLENGE.replace('var N=[', f"var N=['{extra}',")) is None
	assert solve_acw_sc_v2(CHALLENGE.replace(encoded(SEED), encoded('not-a-seed'))) is None


@pytest.mark.parametrize('encoded_value', ['A', '//8', '====', 'a' * 257, 'abc\\x64'])
def test_rejects_malformed_table_entries(encoded_value):
	assert solve_acw_sc_v2(CHALLENGE.replace(encoded(SEED), encoded_value)) is None


def test_rejects_excessive_string_table():
	assert solve_acw_sc_v2(CHALLENGE.replace('var N=[', 'var N=[' + "'abc'," * 65)) is None


@pytest.mark.parametrize(
	'html',
	[
		'<html><body>Login successful</body></html>',
		'<html><script src="/cdn-cgi/challenge-platform/foo.js"></script>Cloudflare</html>',
		'<html><script>var arg1="0123";document.cookie="acw_sc__v2=foo";</script></html>',
		'var arg1="' + ARG1 + '"; acw_sc__v2',
		'{' + '"success":true,"data":"acw_sc__v2 var arg1="' + '}',
	],
)
def test_does_not_solve_general_html_cloudflare_or_marker_only_text(html):
	assert solve_acw_sc_v2(html) is None


@pytest.mark.parametrize(
	'html',
	[
		CHALLENGE.replace('</script>', ';fetch("/api/user/checkin",{method:"POST"});</script>'),
		CHALLENGE.replace('</html>', '<script>businessOperation()</script></html>'),
		CHALLENGE.replace('<script>', '<body>Check-in successful</body><script>', 1),
		'<div>Check-in successful</div>' + CHALLENGE,
		CHALLENGE + '<div>Check-in successful</div>',
		CHALLENGE.replace('decodeURIComponent(o)', 'eval(o)'),
		CHALLENGE.replace('return N;', 'return [];'),
		CHALLENGE.replace('mJKZmgTStNvVyq', encoded('unexpected-string')),
		CHALLENGE.replace('var arg1=', 'var unrelated=0;var arg1='),
	],
)
def test_rejects_extra_html_or_scripts_and_changed_known_template(html):
	assert solve_acw_sc_v2(html) is None


def test_input_and_string_budgets():
	oversized = CHALLENGE + ' ' * 16_384
	assert not is_acw_challenge(oversized)
	assert solve_acw_sc_v2(oversized) is None
	assert solve_acw_sc_v2(CHALLENGE.replace('var N=[', 'var N=[' + "'" + 'a' * 10_000 + "',")) is None


def test_only_outer_formatting_is_flexible():
	assert solve_acw_sc_v2(' \n' + CHALLENGE.strip() + '\n ') == expected(ARG1)
	assert solve_acw_sc_v2(CHALLENGE.replace('<script>', '<script>\n')) == expected(ARG1)


def test_detection_is_not_a_solvability_guarantee():
	assert not is_acw_challenge('<html>Cloudflare</html>')
	assert not is_acw_challenge('var arg1="test";')
	assert not is_acw_challenge('acw_sc__v2')
	assert is_acw_challenge('var arg1="test"; acw_sc__v2')
	assert solve_acw_sc_v2('var arg1="test"; acw_sc__v2') is None
