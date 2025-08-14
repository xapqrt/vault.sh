"""Utility layer: entry + storage management.

Additions:
- Stealth decoy vault routing (real vs. decoy) with password-based routing attempts.
- Read-once note helpers for ephemeral, self-destructing notes.
"""
from __future__ import annotations
import json, os, hashlib, base64, logging
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from config.settings import (
	DEFAULT_VAULT_PATH, MAX_ENTRY_SIZE, MAX_FILE_SIZE, ENTRY_TYPES, MAX_SEARCH_RESULTS, SALT_LENGTH
)
from .crypto import VaultCrypto, CryptoError

log = logging.getLogger(__name__)

class EntryError(Exception): ...
class StorageError(Exception): ...

@dataclass
class FileAttachment:
	filename: str
	content_b64: str
	mime_type: str
	size: int
	sha256: str
	created: str

	@classmethod
	def from_file(cls, path: Path) -> 'FileAttachment':
		if not path.exists(): raise EntryError(f"File not found: {path}")
		size = path.stat().st_size
		if size > MAX_FILE_SIZE: raise EntryError('File too large')
		raw = path.read_bytes()
		return cls(
			filename=path.name,
			content_b64=base64.b64encode(raw).decode('ascii'),
			mime_type='application/octet-stream',
			size=size,
			sha256=hashlib.sha256(raw).hexdigest(),
			created=datetime.now().isoformat()
		)


@dataclass
class VaultEntry:
	id: str
	title: str
	type: str
	content: str
	tags: List[str]
	created: str
	modified: str
	accessed: str
	attachments: List[FileAttachment]
	read_once: bool = False

	def touch(self):
		self.accessed = datetime.now().isoformat()

	def edit(self):
		now = datetime.now().isoformat()
		self.modified = now; self.accessed = now

class EntryManager:
	def create_entry(self, data: Dict, title: str, entry_type: str, content: str = '', tags: List[str] | None = None, read_once: bool = False) -> str:
		if entry_type not in ENTRY_TYPES: raise EntryError('Invalid entry type')
		if len(content.encode()) > MAX_ENTRY_SIZE: raise EntryError('Content too large')
		meta = data.setdefault('metadata', {})
		store = data.setdefault('entries', {})
		last = meta.get('last_id', 0) + 1
		meta['last_id'] = last
		entry_id = str(last)
		now = datetime.now().isoformat()
		e = VaultEntry(entry_id, title, entry_type, content, tags or [], now, now, now, [], read_once)
		store[entry_id] = asdict(e)
		return entry_id

	def get_entry(self, data: Dict, entry_id: str) -> Optional[VaultEntry]:
		raw = data.get('entries', {}).get(entry_id)
		if not raw: return None
		# Backward/forward compatibility defaults
		raw.setdefault('attachments', [])
		raw.setdefault('tags', [])
		raw.setdefault('read_once', False)
		raw['accessed'] = datetime.now().isoformat()
		return VaultEntry(**raw)

	def list_entries(self, data: Dict) -> List[VaultEntry]:
		entries = []
		for v in data.get('entries', {}).values():
			v = dict(v)
			v.setdefault('attachments', [])
			v.setdefault('tags', [])
			v.setdefault('read_once', False)
			entries.append(VaultEntry(**v))
		return sorted(entries, key=lambda e: e.modified, reverse=True)

	def mark_read_once(self, data: Dict, entry_id: str) -> None:
		"""Mark an existing entry as read-once (self-destruct after first read).

		Raises EntryError if the entry does not exist.
		"""
		entry = data.get('entries', {}).get(entry_id)
		if not entry:
			raise EntryError('Entry not found')
		entry['read_once'] = True

	def consume_if_read_once(self, data: Dict, entry_id: str) -> tuple[str, bool]:
		"""Return content and delete if flagged read-once.

		Returns (content, burned) where burned indicates if deletion occurred.
		Raises EntryError if the entry does not exist.
		"""
		store = data.get('entries', {})
		entry = store.get(entry_id)
		if not entry:
			raise EntryError('Entry not found')
		content = entry.get('content', '')
		if entry.get('read_once'):
			# Permanently delete
			store.pop(entry_id, None)
			return content, True
		return content, False

class VaultStorage:
	def __init__(self, path: Path | None = None):
		# Resolve path dynamically to honor environment overrides in tests
		if path is not None:
			self.path = Path(path)
		else:
			env_path = os.environ.get('VAULT_PATH')
			self.path = Path(env_path) if env_path else DEFAULT_VAULT_PATH
		self.crypto = VaultCrypto()

	def exists(self) -> bool:
		return self.path.exists() and self.path.stat().st_size > 0

	def init(self, password: str) -> bool:
		if self.exists(): raise StorageError('Vault exists')
		salt = self.crypto.generate_salt()
		key = self.crypto.derive_key(password, salt)
		payload = {"metadata":{"version":"1.0","created":datetime.now().isoformat(),"salt":salt.hex()},"data":{"entries":{},"metadata":{}}}
		self._write(salt, key, payload)
		return True

	def load(self, password: str) -> Dict[str, Any]:
		if not self.exists(): raise StorageError('Missing vault')
		raw = self.path.read_bytes()
		if len(raw) < SALT_LENGTH: raise StorageError('Corrupt vault')
		salt = raw[:SALT_LENGTH]
		key = self.crypto.derive_key(password, salt)
		try:
			data = json.loads(self.crypto.decrypt(raw[SALT_LENGTH:], key))
		except CryptoError:
			raise StorageError('Invalid password')
		return data

	def save(self, password: str, data: Dict[str, Any]) -> bool:
		"""Encrypt and persist the provided vault data using the given password.

		Keeps the existing salt embedded in metadata to preserve file format.
		"""
		salt_hex = data.get('metadata', {}).get('salt')
		if not salt_hex:
			raise StorageError('Missing metadata salt')
		salt = bytes.fromhex(salt_hex)
		key = self.crypto.derive_key(password, salt)
		self._write(salt, key, data)
		return True

	def backup(self, dest: Path) -> Path:
		dest.parent.mkdir(parents=True, exist_ok=True)
		import shutil
		shutil.copy2(self.path, dest)
		return dest

	def _write(self, salt: bytes, key: bytes, obj: Dict[str, Any]):
		enc = self.crypto.encrypt(json.dumps(obj).encode(), key)
		tmp = self.path.with_suffix('.tmp')
		tmp.write_bytes(salt + enc)
		os.replace(tmp, self.path)
 


class StealthVaultRouter:
	"""Route to real or decoy vault based on the entered password.

	Design:
	- Real vault path: DEFAULT_VAULT_PATH
	- Decoy vault path: <stem>.decoy<suffix> next to the real file
	- load_route() tries real first; if invalid, tries decoy. If both fail, raises StorageError.
	- init_decoy() creates a decoy vault (optionally seeding dummy entries) with its own password.
	"""

	def __init__(self, base_path: Path | None = None):
		if base_path is not None:
			self.real_path = Path(base_path)
		else:
			env_path = os.environ.get('VAULT_PATH')
			self.real_path = Path(env_path) if env_path else DEFAULT_VAULT_PATH
		stem = self.real_path.stem
		suffix = self.real_path.suffix or '.dat'
		self.decoy_path = self.real_path.with_name(f"{stem}.decoy{suffix}")

	def init_decoy(self, password: str, seed_dummy: bool = True) -> bool:
		vs = VaultStorage(self.decoy_path)
		if vs.exists():
			raise StorageError('Decoy vault exists')
		vs.init(password)
		if seed_dummy:
			try:
				data = vs.load(password)
				logical = {'entries': data.setdefault('data', {}).setdefault('entries', {}), 'metadata': data['data'].setdefault('metadata', {})}
				em = EntryManager()
				em.create_entry(logical, 'Shopping List', 'note', '- Eggs\n- Milk\n- Coffee')
				em.create_entry(logical, 'WiFi', 'note', 'SSID: Guest\nPass: welcome123')
				data['data']['entries'] = logical['entries']
				vs.save(password, data)
			except Exception:
				# Best-effort dummy seeding; ignore failures
				pass
		return True

	def load_route(self, password: str) -> tuple[VaultStorage, Dict[str, Any], str]:
		"""Attempt to load real first, then decoy.

		Returns (storage, data, kind) where kind is 'real' or 'decoy'.
		"""
		# Try real
		try:
			vs_real = VaultStorage(self.real_path)
			data = vs_real.load(password)
			return vs_real, data, 'real'
		except StorageError:
			pass
		# Try decoy
		try:
			vs_decoy = VaultStorage(self.decoy_path)
			data = vs_decoy.load(password)
			return vs_decoy, data, 'decoy'
		except StorageError as e:
			raise StorageError('Invalid password or vault not initialised') from e

