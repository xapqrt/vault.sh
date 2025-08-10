from src.lib.crypto import VaultCrypto, check_password_strength
from src.lib.utils import EntryManager

def test_crypto_roundtrip():
	c = VaultCrypto()
	salt = c.generate_salt()
	key = c.derive_key('pass', salt)
	blob = c.encrypt(b'data', key)
	assert c.decrypt(blob, key) == b'data'

def test_password_strength_contains_guidelines():
	score, fb = check_password_strength('weak')
	assert 'Strong' in fb

def test_entry_manager():
	em = EntryManager(); data = {}
	eid = em.create_entry(data, 'Title', 'note', 'Body')
	assert eid == '1'
	assert em.get_entry(data, eid) is not None
	assert len(em.list_entries(data)) == 1

