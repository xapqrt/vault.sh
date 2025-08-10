"""Project configuration settings.

Only constants required by the refactored code base are kept here.
The former scattered configuration files have been consolidated.
"""

from pathlib import Path
import os

# Security / crypto
DEFAULT_ITERATIONS = 100_000
SALT_LENGTH = 32
KEY_LENGTH = 32  # AES-256
IV_LENGTH = 16   # AES block size
AUTH_TAG_LENGTH = 16  # GCM tag length

# Vault
DEFAULT_VAULT_PATH = Path(os.environ.get("VAULT_PATH", "vault_data/vault.dat"))
DEFAULT_VAULT_PATH.parent.mkdir(parents=True, exist_ok=True)

# Entry types
ENTRY_TYPES = {"note": "Note", "credential": "Credential", "file": "File Attachment"}

# Limits
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_ENTRY_SIZE = 1024 * 1024      # 1MB text entries
MAX_SEARCH_RESULTS = 50

# Backup extensions
BACKUP_SUFFIX = ".backup"

__all__ = [
	'DEFAULT_ITERATIONS','SALT_LENGTH','KEY_LENGTH','IV_LENGTH','AUTH_TAG_LENGTH',
	'DEFAULT_VAULT_PATH','ENTRY_TYPES','MAX_FILE_SIZE','MAX_ENTRY_SIZE','MAX_SEARCH_RESULTS','BACKUP_SUFFIX'
]

