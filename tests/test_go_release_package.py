"""Verify published archive contents, integrity checks and release input boundaries."""

import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml

from scripts.package_go_release import DOCUMENTS, LINUX_DESKTOP, STANDALONE, is_prerelease, package_release

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'package_go_release.py'


@pytest.fixture
def builds(tmp_path):
	standalone, desktop = tmp_path / 'standalone', tmp_path / 'desktop'
	for root, targets in ((standalone, STANDALONE), (desktop, LINUX_DESKTOP)):
		root.mkdir()
		checksums = []
		for target, binaries in targets.items():
			(root / target).mkdir()
			for binary in binaries:
				relative = f'{target}/{binary}'
				content = f'Synthetic binary for {relative}'.encode()
				(root / relative).write_bytes(content)
				checksums.append(f'{hashlib.sha256(content).hexdigest()}  {relative}\n')
		(root / 'SHA256SUMS').write_text(''.join(checksums), encoding='utf-8')
		for document in DOCUMENTS:
			(root / document).write_text(f'Synthetic document: {document}', encoding='utf-8')
		# These must never be recursively copied from a build directory.
		(root / 'master.key').write_bytes(b'synthetic-private-data')
		(root / 'webui.sqlite3').write_bytes(b'synthetic-private-data')
		(root / '.env').write_bytes(b'synthetic-private-data')
	return standalone, desktop


def verify_manifest(files):
	manifest = files['SHA256SUMS'].decode()
	seen = set()
	for line in manifest.splitlines():
		digest, name = line.split('  ', 1)
		assert hashlib.sha256(files[name]).hexdigest() == digest
		seen.add(name)
	assert seen == set(files) - {'SHA256SUMS'}


def test_release_archives_include_only_target_binaries_documents_and_checksums(builds, tmp_path):
	output = tmp_path / 'release'
	result = package_release('v1.2.3', builds[0], builds[1], output)
	assert {path.name for path in result} == {
		'CheckinMyFreeAPI-v1.2.3-windows-amd64.zip',
		'CheckinMyFreeAPI-v1.2.3-linux-amd64.tar.gz',
		'CheckinMyFreeAPI-v1.2.3-linux-arm64.tar.gz',
		'CheckinMyFreeAPI-v1.2.3-linux-desktop-amd64-ubuntu24.04.tar.gz',
		'SHA256SUMS',
	}
	verify_manifest({path.name: path.read_bytes() for path in result})
	for target, binaries in (STANDALONE | LINUX_DESKTOP).items():
		label = f'{target}-ubuntu24.04' if target in LINUX_DESKTOP else target
		name = f'CheckinMyFreeAPI-v1.2.3-{label}'
		if target.startswith('windows-'):
			with zipfile.ZipFile(output / f'{name}.zip') as archive:
				files = {member: archive.read(member) for member in archive.namelist()}
		else:
			with tarfile.open(output / f'{name}.tar.gz') as archive:
				files = {}
				for member in archive.getmembers():
					if member.isfile():
						source = archive.extractfile(member)
						assert source is not None
						with source:
							files[member.name] = source.read()
						assert member.mode == (0o755 if member.name.endswith('/checkin') else 0o644)
					assert member.uid == member.gid == 0
		assert set(files) == {*DOCUMENTS, 'SHA256SUMS', *(f'{target}/{binary}' for binary in binaries)}
		verify_manifest(files)
		root = builds[1] if target in LINUX_DESKTOP else builds[0]
		for relative, content in files.items():
			if relative != 'SHA256SUMS':
				assert content == (root / relative).read_bytes()


@pytest.mark.parametrize('failure', ['changed', 'missing', 'empty', 'missing-document', 'extra-entry', 'duplicate'])
def test_invalid_build_stops_before_creating_release_assets(builds, tmp_path, failure):
	standalone, _ = builds
	binary = standalone / 'linux-amd64' / 'checkin'
	if failure == 'changed':
		binary.write_bytes(b'modified-after-build')
	elif failure == 'missing':
		binary.unlink()
	elif failure == 'empty':
		binary.write_bytes(b'')
	elif failure == 'missing-document':
		(standalone / 'LICENSE').unlink()
	else:
		manifest = standalone / 'SHA256SUMS'
		line = manifest.read_text().splitlines()[0]
		if failure == 'extra-entry':
			line = f'{"0" * 64}  ../master.key'
		with manifest.open('a', encoding='utf-8') as destination:
			destination.write(f'{line}\n')
	output = tmp_path / 'release'
	with pytest.raises(ValueError):
		package_release('v1.2.3', builds[0], builds[1], output)
	assert not output.exists()


def test_symlink_input_is_rejected(builds, tmp_path):
	standalone, desktop = builds
	link = standalone / 'README.md'
	link.unlink()
	try:
		os.symlink(desktop / 'README.md', link)
	except OSError:
		pytest.skip('Creating symlinks requires OS support and permission')
	with pytest.raises(ValueError, match='Symlinks|regular file'):
		package_release('v1.2.3', builds[0], builds[1], tmp_path / 'release')


def test_existing_output_is_not_overwritten_or_published_with_stale_assets(builds, tmp_path):
	output = tmp_path / 'release'
	output.mkdir()
	private = output / 'master.key'
	private.write_bytes(b'synthetic-private-data')
	with pytest.raises(ValueError, match='must not already exist'):
		package_release('v1.2.3', builds[0], builds[1], output)
	assert list(output.iterdir()) == [private]
	assert private.read_bytes() == b'synthetic-private-data'


@pytest.mark.parametrize(
	('version', 'prerelease'),
	[
		('v0.0.0', False),
		('v1.2.3', False),
		('v1.2.3+build-metadata', False),
		('v1.2.3-rc.1', True),
		('v1.2.3-0+build.01', True),
	],
)
def test_version_and_prerelease_classification(version, prerelease):
	assert is_prerelease(version) is prerelease
	result = subprocess.run(
		[sys.executable, str(SCRIPT), '--version', version, '--validate-version'],
		capture_output=True,
		text=True,
		check=True,
	)
	assert result.stdout == f'prerelease={str(prerelease).lower()}\n'


@pytest.mark.parametrize(
	'version', ['v1', 'v1.2', 'v01.2.3', 'v1.2.3-01', 'v1.2.3-', 'v1.2.3+', '1.2.3', 'v1.2.3/../data', 'v1.2.3\n']
)
def test_invalid_version_is_rejected(version, builds, tmp_path):
	with pytest.raises(ValueError):
		package_release(version, builds[0], builds[1], tmp_path / 'release')
	assert not (tmp_path / 'release').exists()


def test_packaging_cli_uses_only_standard_library(builds, tmp_path):
	output = tmp_path / 'cli-release'
	result = subprocess.run(
		[
			sys.executable,
			'-I',
			'-S',
			str(SCRIPT),
			'--version',
			'v1.2.3-rc.1',
			'--standalone',
			str(builds[0]),
			'--linux-desktop',
			str(builds[1]),
			'--output',
			str(output),
		],
		capture_output=True,
		text=True,
		check=True,
	)
	assert len(result.stdout.splitlines()) == 5
	verify_manifest({path.name: path.read_bytes() for path in output.iterdir()})


@pytest.mark.parametrize(
	('existing', 'prerelease', 'failure', 'expected_commands', 'success'),
	[
		('', 'false', '', ['list', 'create', 'upload', 'edit'], True),
		('', 'true', '', ['list', 'create', 'upload', 'edit'], True),
		('true', 'false', '', ['list', 'upload', 'edit'], True),
		('false', 'false', '', ['list'], False),
		('', 'false', 'list', ['list'], False),
		('', 'false', 'upload', ['list', 'create', 'upload'], False),
	],
)
def test_publish_uses_draft_and_never_publishes_failed_uploads(
	tmp_path, existing, prerelease, failure, expected_commands, success
):
	bash = shutil.which('bash')
	if os.name == 'nt':
		git_bash = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe'
		bash = str(git_bash) if git_bash.is_file() else None
	if not bash:
		pytest.skip('Bash is required to exercise the release publishing step')
	workflow = yaml.safe_load((SCRIPT.parents[1] / '.github/workflows/release.yml').read_text(encoding='utf-8'))
	step = next(step for step in workflow['jobs']['publish']['steps'] if step['name'].startswith('Publish GitHub'))
	# Replace the remote CLI with a local fake; no GitHub operation can leave this test.
	harness = """
gh() {
  printf '%s %s\\n' "$2" "$*" >> "$GH_TEST_LOG"
  if [[ "$2" == "$GH_TEST_FAILURE" ]]; then return 1; fi
  if [[ "$2" == list ]]; then printf '%s' "$GH_TEST_EXISTING"; fi
}
"""
	log = tmp_path / 'gh-commands.txt'
	result = subprocess.run(
		[bash, '--noprofile', '--norc', '-s'],
		input=harness + step['run'],
		cwd=tmp_path,
		env={
			**os.environ,
			'GH_TEST_LOG': log.as_posix(),
			'GH_TEST_FAILURE': failure,
			'GH_TEST_EXISTING': existing,
			'RELEASE_VERSION': 'v1.2.3-rc.1' if prerelease == 'true' else 'v1.2.3',
			'RELEASE_PRERELEASE': prerelease,
		},
		capture_output=True,
		text=True,
		check=False,
	)
	assert (result.returncode == 0) is success, result.stderr
	commands = log.read_text().splitlines()
	assert [line.split(' ', 1)[0] for line in commands] == expected_commands
	for line in commands:
		if line.startswith('create '):
			assert '--draft' in line and '--verify-tag' in line
		if line.startswith(('create ', 'edit ')):
			assert f'--prerelease={prerelease}' in line
			assert ('--latest=false' in line) is (prerelease == 'true')
		if line.startswith('edit '):
			assert '--draft=false' in line and '--verify-tag' in line
