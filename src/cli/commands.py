"""CLI commands implemented with click.

New:
- Stealth/Decoy routing via StealthVaultRouter
- Read-once notes: `vault note create` and `vault note read`
"""
from __future__ import annotations
import json, click
from pathlib import Path
from src.lib.crypto import check_password_strength
from src.lib.utils import VaultStorage, EntryManager, EntryError, StorageError, StealthVaultRouter

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

@cli.command('init-decoy')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
@click.option('--no-dummy', is_flag=True, help='Do not add dummy entries to decoy vault')
def init_decoy(password, no_dummy):
	"""Initialise a decoy vault protected by a different password."""
	r = StealthVaultRouter()
	try:
		r.init_decoy(password, seed_dummy=not no_dummy)
		click.echo('Decoy vault created.')
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
	r = StealthVaultRouter()
	try:
		_vs, data, kind = r.load_route(password)
		click.echo(json.dumps(data['metadata'], indent=2))
		if kind == 'decoy':
			click.echo('(decoy)')
	except Exception as e:
		click.echo(f'Error: {e}')

@cli.command('add-note')
@click.option('--password', prompt=True, hide_input=True)
@click.option('--title', prompt=True)
@click.option('--content', prompt=True)
def add_note(password, title, content):
	r = StealthVaultRouter(); em = EntryManager()
	try:
		vs, data, _ = r.load_route(password)
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
	r = StealthVaultRouter(); em = EntryManager()
	try:
		_vs, data, kind = r.load_route(password)
		logical = {'entries': data.get('data', {}).get('entries', {})}
		items = em.list_entries(logical)
		for e in items:
			flag = ' (read-once)' if getattr(e, 'read_once', False) else ''
			click.echo(f"{e.id}: {e.title} [{e.type}]{flag}")
	except Exception as e:
		click.echo(f'Error: {e}')

@cli.command('show')
@click.argument('entry_id')
@click.option('--password', prompt=True, hide_input=True)
def show_entry(entry_id, password):
	"""Show full content of a note by ID."""
	r = StealthVaultRouter(); em = EntryManager()
	try:
		vs, data, _ = r.load_route(password)
		entries = data.get('data', {}).get('entries', {})
		entry = entries.get(entry_id)
		if not entry:
			click.echo('Not found')
			return
		if entry.get('read_once'):
			content, burned = em.consume_if_read_once({'entries': entries}, entry_id)
			# Persist deletion if burned
			if burned:
				data['data']['entries'] = entries
				vs.save(password, data)
				click.echo(f"---\n{content}\n\n🔥 File Burned")
				return
			else:
				click.echo(f"---\n{content}")
				return
		click.echo(f"ID: {entry_id}\nTitle: {entry['title']}\nType: {entry['type']}\nCreated: {entry['created']}\nModified: {entry['modified']}\nTags: {', '.join(entry.get('tags') or []) or '-'}\n---\n{entry['content']}")
	except StorageError as e:
		click.echo(f'Error: {e}')
	except Exception as e:  # pragma: no cover (unexpected)
		click.echo(f'Error: {e}')


# --- Note subcommands (read-once support) ---

@cli.group()
def note():
	"""Manage notes (including read-once)."""

@note.command('create')
@click.option('--password', prompt=True, hide_input=True)
@click.option('--title', prompt=True)
@click.option('--content', prompt=True)
@click.option('--read-once', is_flag=True, help='Delete after first read')
def note_create(password, title, content, read_once):
	"""Create a note, optionally read-once."""
	r = StealthVaultRouter(); em = EntryManager()
	try:
		vs, data, _ = r.load_route(password)
		entries = data.setdefault('data', {}).setdefault('entries', {})
		logical = {'entries': entries, 'metadata': data.setdefault('data', {}).setdefault('metadata', {})}
		eid = em.create_entry(logical, title, 'note', content, read_once=read_once)
		entries.update(logical['entries'])
		vs.save(password, data)
		msg = f'Note {eid} created.' + (' (read-once)' if read_once else '')
		click.echo(msg)
	except (EntryError, StorageError) as e:
		click.echo(f'Error: {e}')

@note.command('read')
@click.argument('entry_id')
@click.option('--password', prompt=True, hide_input=True)
def note_read(entry_id, password):
	"""Read a note; if read-once, it will be deleted after reading."""
	r = StealthVaultRouter(); em = EntryManager()
	try:
		vs, data, _ = r.load_route(password)
		entries = data.get('data', {}).get('entries', {})
		if entry_id not in entries:
			click.echo('Not found')
			return
		content, burned = em.consume_if_read_once({'entries': entries}, entry_id)
		if burned:
			data['data']['entries'] = entries
			vs.save(password, data)
			click.echo(f"{content}\n\n🔥 File Burned")
		else:
			click.echo(content)
	except (EntryError, StorageError) as e:
		click.echo(f'Error: {e}')

