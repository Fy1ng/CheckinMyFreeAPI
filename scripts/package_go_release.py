"""Package only verified Go build outputs into platform-specific release archives."""

import argparse
import hashlib
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
from pathlib import Path

DOCUMENTS = ('README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'GO_DEPENDENCY_LICENSES.txt')
STANDALONE: dict[str, tuple[str, ...]] = {
	'windows-amd64': ('checkin.exe', 'checkin-cli.exe'),
	'linux-amd64': ('checkin',),
	'linux-arm64': ('checkin',),
}
LINUX_DESKTOP: dict[str, tuple[str, ...]] = {'linux-desktop-amd64': ('checkin',)}
VERSION_PATTERN = re.compile(
	r'v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'
	r'(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
	r'(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
)


def is_prerelease(version: str) -> bool:
	match = VERSION_PATTERN.fullmatch(version)
	if not match or len(version) > 128:
		raise ValueError('Release version must be vMAJOR.MINOR.PATCH with optional SemVer prerelease/build metadata.')
	prerelease = match.group(4)
	if prerelease and any(part.isdigit() and len(part) > 1 and part.startswith('0') for part in prerelease.split('.')):
		raise ValueError('Numeric prerelease identifiers must not have leading zeros.')
	return prerelease is not None


def checked_file(root: Path, relative: str) -> Path:
	path = root / relative
	if root.is_symlink() or any(parent.is_symlink() for parent in path.parents if parent != root.parent):
		raise ValueError(f'Symlinks are not allowed in release inputs: {relative}')
	if path.is_symlink() or not path.is_file() or path.stat().st_size == 0:
		raise ValueError(f'Required release input is missing, empty or not a regular file: {relative}')
	return path


def sha256(path: Path) -> str:
	with path.open('rb') as source:
		return hashlib.file_digest(source, 'sha256').hexdigest()


def checksum_manifest(paths: dict[str, Path]) -> str:
	return ''.join(f'{sha256(paths[name])}  {name}\n' for name in sorted(paths))


def verify_inputs(root: Path, targets: dict[str, tuple[str, ...]]) -> None:
	expected = {f'{target}/{binary}' for target, binaries in targets.items() for binary in binaries}
	manifest = checked_file(root, 'SHA256SUMS').read_text(encoding='utf-8')
	seen = set()
	for line in manifest.splitlines():
		digest, separator, relative = line.partition('  ')
		if not separator or not re.fullmatch('[0-9a-f]{64}', digest) or relative not in expected or relative in seen:
			raise ValueError('Build checksum manifest contains an invalid, duplicate or unexpected entry.')
		if sha256(checked_file(root, relative)) != digest:
			raise ValueError(f'Build checksum verification failed: {relative}')
		seen.add(relative)
	if seen != expected:
		raise ValueError('Build checksum manifest does not contain all required binaries.')
	for document in DOCUMENTS:
		checked_file(root, document)


def archive_mode(info: tarfile.TarInfo) -> tarfile.TarInfo:
	info.uid = info.gid = info.mtime = 0
	info.uname = info.gname = ''
	info.mode = 0o755 if info.isdir() or info.name.endswith('/checkin') else 0o644
	return info


def package_release(version: str, standalone: Path, linux_desktop: Path, output: Path) -> list[Path]:
	is_prerelease(version)
	verify_inputs(standalone, STANDALONE)
	verify_inputs(linux_desktop, LINUX_DESKTOP)
	if output.exists():
		raise ValueError('Release output must not already exist; choose a new directory to avoid stale assets.')
	output.parent.mkdir(parents=True, exist_ok=True)
	with tempfile.TemporaryDirectory(prefix='.release-', dir=output.parent) as temporary:
		working = Path(temporary)
		assets = working / 'assets'
		assets.mkdir()
		for root, targets in ((standalone, STANDALONE), (linux_desktop, LINUX_DESKTOP)):
			for target, binaries in targets.items():
				stage = working / target
				(stage / target).mkdir(parents=True)
				members = (*DOCUMENTS, *(f'{target}/{binary}' for binary in binaries))
				for relative in members:
					shutil.copyfile(checked_file(root, relative), stage / relative)
				(stage / 'SHA256SUMS').write_text(
					checksum_manifest({relative: stage / relative for relative in members}),
					encoding='utf-8',
					newline='\n',
				)
				label = f'{target}-ubuntu24.04' if target in LINUX_DESKTOP else target
				name = f'CheckinMyFreeAPI-{version}-{label}'
				if target.startswith('windows-'):
					with zipfile.ZipFile(assets / f'{name}.zip', 'w', compression=zipfile.ZIP_DEFLATED) as archive:
						for path in sorted(stage.rglob('*')):
							if path.is_file():
								info = zipfile.ZipInfo(path.relative_to(stage).as_posix())
								info.create_system = 3
								info.external_attr = (stat.S_IFREG | 0o644) << 16
								archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
				else:
					with tarfile.open(assets / f'{name}.tar.gz', 'w:gz') as archive:
						for path in sorted(stage.iterdir()):
							archive.add(path, arcname=path.name, filter=archive_mode)
		(assets / 'SHA256SUMS').write_text(
			checksum_manifest({path.name: path for path in assets.iterdir()}), encoding='utf-8', newline='\n'
		)
		assets.rename(output)
	return sorted(output.iterdir())


def main() -> None:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument('--version', required=True)
	parser.add_argument('--validate-version', action='store_true')
	parser.add_argument('--standalone', type=Path)
	parser.add_argument('--linux-desktop', type=Path)
	parser.add_argument('--output', type=Path)
	args = parser.parse_args()
	try:
		prerelease = is_prerelease(args.version)
		if args.validate_version:
			print(f'prerelease={str(prerelease).lower()}')
			return
		if not all((args.standalone, args.linux_desktop, args.output)):
			parser.error('Packaging requires --standalone, --linux-desktop and --output.')
		for path in package_release(args.version, args.standalone, args.linux_desktop, args.output):
			print(path.name)
	except (OSError, ValueError) as error:
		parser.exit(1, f'Release packaging failed: {error}\n')


if __name__ == '__main__':
	main()
