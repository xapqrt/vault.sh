"""Configuration settings and constants for vault.sh.

This package-level module exposes the same constants expected by the
application code (e.g. `from config import DEFAULT_ITERATIONS`). A
previous name collision existed between a top-level `config.py` file
and this `config` package which caused imports like `from config import
DEFAULT_ITERATIONS` to fail because this `__init__` was empty. The
constants are duplicated here to restore compatibility. Prefer keeping
them in one place (this file) going forward.
"""

# Security constants
DEFAULT_ITERATIONS = 100000  # PBKDF2 iterations
SALT_LENGTH = 32
KEY_LENGTH = 32  # AES-256 key length
IV_LENGTH = 16  # AES block size
MASTER_KEY_TAG_LENGTH = 16  # Authentication tag length

# Vault settings
DEFAULT_VAULT_PATH = "vault_data/vault.dat"
DEFAULT_CONFIG_PATH = "vault_data/config.json"
AUTO_LOCK_TIMEOUT = 900  # 15 minutes in seconds
CLIPBOARD_CLEAR_TIMEOUT = 10  # seconds

# Entry types
ENTRY_TYPES = {
	"note": "Note",
	"journal": "Journal Entry",
	"credential": "Credential",
	"file": "File Attachment"
}

# File size limits (in bytes)
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_ENTRY_SIZE = 1024 * 1024  # 1MB for text entries

# Search settings
MAX_SEARCH_RESULTS = 50

# Backup settings
BACKUP_EXTENSION = ".vault.backup"
EXPORT_EXTENSION = ".vault.export"

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "vault_data/vault.log"

# UI Settings
TERMINAL_WIDTH = 80
TERMINAL_HEIGHT = 24

__all__ = [
	'DEFAULT_ITERATIONS', 'SALT_LENGTH', 'KEY_LENGTH', 'IV_LENGTH', 'MASTER_KEY_TAG_LENGTH',
	'DEFAULT_VAULT_PATH', 'DEFAULT_CONFIG_PATH', 'AUTO_LOCK_TIMEOUT', 'CLIPBOARD_CLEAR_TIMEOUT',
	'ENTRY_TYPES', 'MAX_FILE_SIZE', 'MAX_ENTRY_SIZE', 'MAX_SEARCH_RESULTS',
	'BACKUP_EXTENSION', 'EXPORT_EXTENSION', 'LOG_LEVEL', 'LOG_FILE',
	'TERMINAL_WIDTH', 'TERMINAL_HEIGHT'
]
