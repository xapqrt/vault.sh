"""CLI commands implemented with click."""
from __future__ import annotations
import json, click
from pathlib import Path
from src.lib.crypto import check_password_strength
from src.lib.utils import VaultStorage, EntryManager, EntryError, StorageError

@click.group()
def cli():
	"""vault.sh minimal CLI"""

@cli.command()
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--force', is_flag=True, help='Recreate if vault already exists.')
def init(password, force):
	"""Initialise a new encrypted vault (use --force to recreate)."""
	vs = VaultStorage()
	if force and vs.exists():
		# Remove existing file before init
		try:
			vs.path.unlink(missing_ok=True)  # type: ignore[arg-type]
		except Exception:
			pass
	try:
		vs.init(password)
		click.echo('Vault created.')
	except StorageError as e:
		click.echo(f'Error: {e}')

@cli.command('pw-strength')
@click.argument('password')
def pw_strength_cmd(password):
	score, fb = check_password_strength(password)
	click.echo(f"Score: {score} -> {fb}")

@cli.command()
@click.option('--password', prompt=True, hide_input=True)
def info(password):
	"""Show vault metadata."""
	vs = VaultStorage()
	try:
		data = vs.load(password)
		click.echo(json.dumps(data['metadata'], indent=2))
	except Exception as e:
		click.echo(f'Error: {e}')

@cli.command('add-note')
@click.option('--password', prompt=True, hide_input=True)
@click.option('--title', prompt=True)
@click.option('--content', prompt=True)
def add_note(password, title, content):
	vs = VaultStorage()
	em = EntryManager()
	try:
		data = vs.load(password)
		entries = data.setdefault('data', {}).setdefault('entries', {})
		logical = {'entries': entries, 'metadata': data.setdefault('data', {}).setdefault('metadata', {})}
		entry_id = em.create_entry(logical, title, 'note', content)
		entries.update(logical['entries'])
		vs.save(password, data)
		click.echo(f'Added note {entry_id}.')
	except (EntryError, StorageError) as e:
		click.echo(f'Error: {e}')

@cli.command('list')
@click.option('--password', prompt=True, hide_input=True)
def list_entries(password):
	vs = VaultStorage(); em = EntryManager()
	try:
		data = vs.load(password)
		logical = {'entries': data.get('data', {}).get('entries', {})}
		items = em.list_entries(logical)
		for e in items:
			click.echo(f"{e.id}: {e.title} [{e.type}]")
	except Exception as e:
		click.echo(f'Error: {e}')

@cli.command('show')
@click.argument('entry_id')
@click.option('--password', prompt=True, hide_input=True)
def show_entry(entry_id, password):
	"""Show full content of a note by ID."""
	vs = VaultStorage()
	try:
		data = vs.load(password)
		entries = data.get('data', {}).get('entries', {})
		entry = entries.get(entry_id)
		if not entry:
			click.echo('Not found')
			return
		click.echo(f"ID: {entry_id}\nTitle: {entry['title']}\nType: {entry['type']}\nCreated: {entry['created']}\nModified: {entry['modified']}\nTags: {', '.join(entry.get('tags') or []) or '-'}\n---\n{entry['content']}")
	except StorageError as e:
		click.echo(f'Error: {e}')
	except Exception as e:  # pragma: no cover (unexpected)
		click.echo(f'Error: {e}')

