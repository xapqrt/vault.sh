# vault.sh – Minimal Encrypted Vault (Refactored)

> Quick, minimal, password‑protected vault for notes with AES-256-GCM encryption and a simple CLI.

## Quick Start (Just What You Need)

1. Create virtual env & install deps:
	```
	python -m venv .venv
	./.venv/Scripts/Activate.ps1   # Windows PowerShell
	pip install -r config/requirements.txt
	```
2. (Optional) Choose vault file location:
	```
	$env:VAULT_PATH="myvault.dat"   # PowerShell
	# or export VAULT_PATH=myvault.dat (bash)
	```
3. Initialize (creates encrypted vault):
	```
	python -m src.main init
	```
4. Add a note:
	```
	python -m src.main add-note
	```
5. List notes:
	```
	python -m src.main list
	```
6. Check password strength:
	```
	python -m src.main pw-strength "MyPassw0rd!"
	```
7. Show vault metadata:
	```
	python -m src.main info
	```
8. Run tests (optional):
	```
	pytest -q
	```

Need to recreate the vault? Use:
```
python -m src.main init --force
```

That’s it. See “Full Details” below only if you want more context.

### One-Click Run / Install

Unix/macOS quick install (reviews script first recommended):
```
curl -fsSL https://raw.githubusercontent.com/xapqrt/vault.sh/main/scripts/install.sh | bash
```
Windows PowerShell quick install:
```
powershell -NoProfile -ExecutionPolicy Bypass -Command "iwr https://raw.githubusercontent.com/xapqrt/vault.sh/main/scripts/install.ps1 -UseBasicParsing | iex"
```
Local dev one-click (already cloned):
```
./scripts/oneclick.sh    # or scripts/oneclick.ps1 on Windows
```
After first release tag (e.g. v0.1.0), a direct binary URL will appear at:
```
https://github.com/xapqrt/vault.sh/releases/latest
```


This codebase is a **pared-down, auditable implementation** of a simple encrypted “vault” with:

- Deterministic AES-256-GCM encryption (PBKDF2 key derivation)
- Basic entry management (notes) with ID sequencing
- Password strength scoring utility
- Click-based CLI for common operations
- Lean test suite covering crypto, storage, and CLI paths

All legacy / extraneous modules were removed; only the necessary files remain by design.

---
## 1. Repository Layout

```
src/
	main.py                # CLI entry dispatcher
	cli/commands.py        # Click commands (init, info, add-note, list, pw-strength)
	lib/crypto.py          # VaultCrypto, password strength
	lib/utils.py           # VaultStorage, EntryManager and models
	lib/auth.py            # Password hashing utilities (bcrypt)
config/
	requirements.txt       # Runtime + CLI dependencies
	settings.py            # Central constants
	.env.example           # Example environment variable (VAULT_PATH)
scripts/
	backup.py              # Backup helper
	deploy.sh              # Simple CI/deploy script
	prune_repo.py          # Optional repo pruning tool
tests/                   # Pytest test modules
docs/                    # This README + api/setup guides
```

---
## 2. Requirements

Python 3.11+ recommended.

Install system libs (Windows typically fine out-of-box). On Linux you may need build tooling:
```
sudo apt-get update && sudo apt-get install -y build-essential python3-dev
```

---
## 3. Environment Setup

Clone & create virtual environment (PowerShell example):
```
python -m venv .venv
./.venv/Scripts/Activate.ps1
python -m pip install --upgrade pip
pip install -r config/requirements.txt
```

Verify installation:
```
python -m pytest -q
```

---
## 4. Configuration

The vault file path is resolved from the environment variable `VAULT_PATH` or defaults to `vault_data/vault.dat`.

To customise:
```
copy config\.env.example .env   # (optional pattern if you use a loader)
set VAULT_PATH=custom/location/myvault.dat  # Windows (cmd)
$env:VAULT_PATH="custom/location/myvault.dat"             # PowerShell
export VAULT_PATH=custom/location/myvault.dat              # Linux / macOS
```

No secret values are stored in plaintext; the file contains: salt + AES-GCM(iv+ciphertext+tag).

---
## 5. CLI Usage

Invoke via module:
```
python -m src.main --help
```

### How to Run (Windows PowerShell)

1) Create and activate a virtual environment, install deps:

```powershell
python -m venv .venv
./.venv/Scripts/Activate.ps1
pip install -r config/requirements.txt
```

2) (Optional) Choose a custom vault file location:

```powershell
$env:VAULT_PATH = "C:/path/to/myvault.dat"
```

3) Initialize and use the CLI:

```powershell
python -m src.main init                 # create real vault
python -m src.main add-note             # add a note
python -m src.main list                 # list notes
python -m src.main show 1               # show a note
python -m src.main info                 # metadata
python -m src.main pw-strength "Passw0rd!@#"  # check strength
```

### Initialise Vault
```
python -m src.main init
# or recreate if it already exists
python -m src.main init --force
```

### Show Vault Metadata
```
python -m src.main info
```

### Add Note
```
python -m src.main add-note
```
Prompts for password, title, and content.

### List Notes
```
python -m src.main list
```

### Show Note Content
```
python -m src.main show 1
```
Prompts for the password, then prints the full note body.

Read-once notes:
```
python -m src.main note create --title "Secret" --content "One-shot" --read-once
python -m src.main note read 1  # prints and removes, shows "🔥 File Burned"
```

### Stealth/Decoy Vault Mode

Create a decoy vault protected by a separate password. When you enter the decoy password in any command, the tool transparently opens the decoy vault; entering the real password opens the real vault. The real vault remains fully hidden when the decoy is in use.

```
python -m src.main init            # create real vault
python -m src.main init-decoy      # create decoy vault (you'll be prompted for a decoy password)
python -m src.main list            # enter either password; you'll see the corresponding vault
```

Notes:
- The decoy vault file sits next to the real one, named like: vault.decoy.dat
- The decoy initializer seeds harmless, realistic dummy entries by default.

### Password Strength Check
```
python -m src.main pw-strength "CandidatePassword123!"
```

---
## 6. Programmatic Use

```python
from src.lib.crypto import VaultCrypto, check_password_strength
from src.lib.utils import VaultStorage, EntryManager

crypto = VaultCrypto()
salt = crypto.generate_salt()
key = crypto.derive_key('master', salt)
enc = crypto.encrypt_text('secret data', key)
plain = crypto.decrypt_text(enc, key)

storage = VaultStorage()            # path from VAULT_PATH or default
storage.init('master')              # create
data = storage.load('master')       # dict structure
em = EntryManager()
logical = {'entries': data['data']['entries'], 'metadata': {}}
eid = em.create_entry(logical, 'Title', 'note', 'Body text')
data['data']['entries'] = logical['entries']
storage.save('master', data)
```

---
## 7. Testing

Run all tests:
```
pytest -q
```

Windows (using the venv explicitly):

```powershell
./.venv/Scripts/python.exe -m pytest -q
```

Selected test groups:
```
pytest tests/test_crypto_extended.py::test_encrypt_decrypt_various_sizes -q
pytest tests/test_cli_commands.py::test_cli_add_and_list -q
```

Coverage (optional):
```
pip install coverage
coverage run -m pytest
coverage html  # view htmlcov/index.html
```

---
## 8. Backup

```
python -m scripts.backup --dest backups/
```
Produces timestamped copy of the vault file.

---
## 9. Pruning (Repository Hygiene)

The script `scripts/prune_repo.py` can remove everything not in the declared whitelist.

Dry run:
```
python scripts/prune_repo.py
```
Execute:
```
python scripts/prune_repo.py --execute
```

Include caches / remove .venv:
```
python scripts/prune_repo.py --execute --include-caches --include-venv
```

---
## 10. Security Notes

This is **not a production-grade password manager**; missing features include:
- Key stretching alternatives (Argon2, scrypt)
- Integrity metadata beyond GCM tag
- Versioned schema migrations
- Secure in-memory secret wiping
- Multi-user access control

Use only for educational or prototype purposes unless you harden further.

---
## 11. Troubleshooting

| Issue | Cause | Resolution |
|-------|-------|------------|
| `Error: Vault exists` during `init` | File already present | Use `--force` to recreate |
| `Invalid password` | Wrong master password | Re-enter correct password |
| `cryptography` build errors | Missing compiler toolchain | Install build essentials (see section 2) |
| Pylance missing import warnings for deleted files | Cached editor state | Close/reopen workspace or clear `.vscode` / reload window |

### Pylance Warnings About Removed Modules
If your editor still shows diagnostics for `vault_storage`, `entry_manager`, or `crypto_utils`, those files were intentionally removed. Delete any open tabs referencing them and clear caches. They are replaced by:
- `src/lib/utils.py`  (VaultStorage, EntryManager)
- `src/lib/crypto.py` (VaultCrypto, password functions)

---
## 12. Extending

Ideas:
1. Add search / tag filters to CLI list.
2. Implement attachment encryption.
3. Add JSON export/import commands.
4. Integrate Argon2id via `argon2-cffi` for stronger key derivation.
5. Stealth vault enhancements: configurable decoy file name, multiple decoys.

---
## 13. License

Add your preferred license (MIT / Apache-2.0). Currently unspecified.

---
## 14. Minimal Quickstart

```
python -m venv .venv
./.venv/Scripts/Activate.ps1   # Windows PowerShell
pip install -r config/requirements.txt
python -m src.main init
python -m src.main add-note
python -m src.main list
```

---
## 15. FAQ

**Why only notes?** Simplifies model; extend EntryManager for other types.

**Why embed salt at file start?** Allows stateless key derivation without separate metadata file.

**How to rotate the master password?** Load with old password, decrypt, generate new salt, re-init with new password, save data.

---
Happy hacking.


