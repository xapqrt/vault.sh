"""Prune repository to only keep a whitelisted set of files.

Usage:
  python scripts/prune_repo.py            # Dry run (default)
  python scripts/prune_repo.py --execute  # Perform deletions
  python scripts/prune_repo.py --execute --include-caches  # Also remove __pycache__, .pytest_cache

Safety:
  - Dry run by default (no deletions unless --execute specified)
  - Preserves .git directory and (by default) .venv
  - Removes empty directories after pruning

Customize the WHITELIST set below if needed.
"""
from __future__ import annotations
import os
import argparse
from pathlib import Path
from typing import Set

# Root directory (repository root assumed as script's parent parent)
ROOT = Path(__file__).resolve().parent.parent

# Whitelisted relative file paths (POSIX style). Directories are retained iff containing any whitelisted file.
WHITELIST: Set[str] = {
    'src/main.py',
    'src/lib/utils.py',
    'src/lib/auth.py',
    'src/lib/crypto.py',
    'src/cli/commands.py',
    'docs/README.md',
    'docs/api.md',
    'docs/setup.md',
    'tests/test_main.py',
    'tests/test_utils.py',
    'config/requirements.txt',
    'config/.env.example',
    'config/settings.py',
    'scripts/deploy.sh',
    'scripts/backup.py',
    'scripts/prune_repo.py',  # keep self
}

# Always-keep directories (in addition to paths above) unless explicitly overridden
ALWAYS_KEEP_DIRS = {'.git'}  # .venv handled by flag
CACHE_DIRS = {'.pytest_cache', '__pycache__'}


def normalize(rel: Path) -> str:
    return rel.as_posix()


def collect_targets(include_caches: bool, include_venv: bool) -> tuple[list[Path], list[Path]]:
    files_to_delete: list[Path] = []
    dirs_to_consider: list[Path] = []

    for path in ROOT.rglob('*'):
        rel = path.relative_to(ROOT)
        rel_str = normalize(rel)

        # Skip pruning script's own directory evaluation of .git internals
        if any(part in ALWAYS_KEEP_DIRS for part in rel.parts):
            continue
        if not include_venv and rel.parts and rel.parts[0] == '.venv':
            continue

        if path.is_dir():
            # Directory decisions deferred; mark for potential cleanup
            dirs_to_consider.append(path)
            continue

        # Skip caches unless user requested to include them
        if not include_caches and any(part in CACHE_DIRS for part in rel.parts):
            continue

        if rel_str not in WHITELIST:
            files_to_delete.append(path)

    # Sort files longest path first for safer deletion info grouping
    files_to_delete.sort(key=lambda p: len(p.as_posix()), reverse=True)
    # Directories pruned later (post file deletion) if empty
    return files_to_delete, dirs_to_consider


def prune(dry_run: bool, include_caches: bool, include_venv: bool) -> None:
    files_to_delete, dirs = collect_targets(include_caches, include_venv)

    if files_to_delete:
        print(f"Found {len(files_to_delete)} non-whitelisted file(s).")
    else:
        print("No non-whitelisted files found.")

    for f in files_to_delete:
        action = 'DELETE' if not dry_run else 'WOULD DELETE'
        print(f"{action}: {f.relative_to(ROOT)}")
        if not dry_run:
            try:
                f.unlink()
            except Exception as e:
                print(f"  ! Failed to delete {f}: {e}")

    # Remove empty directories (excluding whitelist parents & always keep)
    if not dry_run:
        # Walk deepest first
        for d in sorted(dirs, key=lambda p: len(p.as_posix()), reverse=True):
            if not d.exists():
                continue
            if d.is_dir():
                if any(part in ALWAYS_KEEP_DIRS for part in d.relative_to(ROOT).parts):
                    continue
                if not include_venv and d.relative_to(ROOT).parts and d.relative_to(ROOT).parts[0] == '.venv':
                    continue
                try:
                    # If directory contains any whitelisted file path prefix, keep
                    rel = d.relative_to(ROOT).as_posix()
                    if any(w.startswith(rel + '/') for w in WHITELIST):
                        continue
                    if not any(d.iterdir()):  # empty
                        d.rmdir()
                        print(f"REMOVED EMPTY DIR: {rel}")
                except OSError:
                    pass

    print("Dry run complete." if dry_run else "Prune complete.")


def main():
    parser = argparse.ArgumentParser(description='Prune repository to whitelist.')
    parser.add_argument('--execute', action='store_true', help='Perform actual deletions (default is dry run).')
    parser.add_argument('--include-caches', action='store_true', help='Also delete cache directories (e.g., __pycache__, .pytest_cache).')
    parser.add_argument('--include-venv', action='store_true', help='Allow deletion of .venv if not whitelisted.')
    args = parser.parse_args()

    prune(dry_run=not args.execute, include_caches=args.include_caches, include_venv=args.include_venv)

if __name__ == '__main__':
    main()
