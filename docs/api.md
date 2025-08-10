# API Overview

Crypto:
- VaultCrypto.generate_salt()
- VaultCrypto.derive_key(password, salt)
- VaultCrypto.encrypt/decrypt & encrypt_text/decrypt_text
- check_password_strength(password) -> (score, feedback)

Storage:
- VaultStorage.init(password)
- VaultStorage.load(password)
- VaultStorage.save(password, data)

Entries:
- EntryManager.create_entry(data, title, type, content, tags)
- EntryManager.get_entry(data, id)
- EntryManager.list_entries(data)

