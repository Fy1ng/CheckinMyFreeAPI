"""Remove only this checkout's plaintext runtime directories after the job."""

import shutil
from pathlib import Path


def cleanup(root: Path) -> None:
	workspace = root.resolve()
	for name in ('.auth-state', '.browser_profiles', 'checkin_screenshots'):
		path = workspace / name
		if path.is_symlink() or not path.resolve().is_relative_to(workspace) or path.resolve() == workspace:
			raise RuntimeError('Refusing unsafe cleanup path')
		if path.exists():
			shutil.rmtree(path)


if __name__ == '__main__':
	cleanup(Path(__file__).resolve().parent.parent)
