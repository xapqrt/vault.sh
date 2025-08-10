"""Utility layer: entry + storage management."""
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

	def touch(self):
		self.accessed = datetime.now().isoformat()

	def edit(self):
		now = datetime.now().isoformat()
		self.modified = now; self.accessed = now

class EntryManager:
	def create_entry(self, data: Dict, title: str, entry_type: str, content: str = '', tags: List[str] | None = None) -> str:
		if entry_type not in ENTRY_TYPES: raise EntryError('Invalid entry type')
		if len(content.encode()) > MAX_ENTRY_SIZE: raise EntryError('Content too large')
		meta = data.setdefault('metadata', {})
		store = data.setdefault('entries', {})
		last = meta.get('last_id', 0) + 1
		meta['last_id'] = last
		entry_id = str(last)
		now = datetime.now().isoformat()
		e = VaultEntry(entry_id, title, entry_type, content, tags or [], now, now, now, [])
		store[entry_id] = asdict(e)
		return entry_id

	def get_entry(self, data: Dict, entry_id: str) -> Optional[VaultEntry]:
		raw = data.get('entries', {}).get(entry_id)
		if not raw: return None
		raw['accessed'] = datetime.now().isoformat()
		return VaultEntry(**raw)

	def list_entries(self, data: Dict) -> List[VaultEntry]:
		entries = [VaultEntry(**v) for v in data.get('entries', {}).values()]
		return sorted(entries, key=lambda e: e.modified, reverse=True)

class VaultStorage:
	def __init__(self, path: Path | None = None):
		self.path = Path(path) if path else DEFAULT_VAULT_PATH
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
		salt = bytes.fromhex(data['metadata']['salt'])
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

