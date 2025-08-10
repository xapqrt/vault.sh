"""Simple backup utility script.

Usage (from repo root):
  python -m scripts.backup --dest backups/
"""
from __future__ import annotations
import shutil
from datetime import datetime
from pathlib import Path
import click
from config import settings

@click.command()
@click.option('--dest', type=click.Path(file_okay=False, path_type=Path), default=Path('backups'), help='Destination directory for backups.')
def main(dest: Path):
	dest.mkdir(parents=True, exist_ok=True)
	vault_path = settings.DEFAULT_VAULT_PATH
	if not vault_path.exists():
		click.echo(f"No vault at {vault_path}; nothing to backup.")
		raise SystemExit(1)
	stamp = datetime.now().strftime('%Y%m%d_%H%M%S')
	target = dest / f"vault_{stamp}.dat"
	shutil.copy2(vault_path, target)
	click.echo(f"Backup written: {target}")

if __name__ == '__main__':  # pragma: no cover
	main()

