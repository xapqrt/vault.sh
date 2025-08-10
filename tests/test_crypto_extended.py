import pytest
from src.lib.crypto import VaultCrypto, CryptoError, check_password_strength

def test_derive_key_consistency():
    c = VaultCrypto()
    salt = c.generate_salt()
    k1 = c.derive_key('secret', salt)
    k2 = c.derive_key('secret', salt)
    assert k1 == k2 and len(k1) == 32

def test_encrypt_decrypt_various_sizes():
    c = VaultCrypto(); salt = c.generate_salt(); key = c.derive_key('pw', salt)
    for payload in [b'', b'a', b'hello world', b'x'*1024, b'y'*4096]:
        blob = c.encrypt(payload, key)
        assert payload != blob
        assert c.decrypt(blob, key) == payload

def test_decrypt_wrong_key():
    c = VaultCrypto(); s1 = c.generate_salt(); s2 = c.generate_salt()
    k1 = c.derive_key('pw', s1); k2 = c.derive_key('pw', s2)
    blob = c.encrypt(b'data', k1)
    with pytest.raises(CryptoError):
        c.decrypt(blob, k2)

def test_decrypt_corrupted():
    c = VaultCrypto(); salt = c.generate_salt(); key = c.derive_key('pw', salt)
    blob = c.encrypt(b'data', key)
    corrupted = blob[:-5] + b'abcde'
    with pytest.raises(CryptoError):
        c.decrypt(corrupted, key)

@pytest.mark.parametrize('pwd,expected_min', [
    ('weak', 0),
    ('Stronger12!', 60),
    ('VeryStrongPassword#2024', 60)
])
def test_password_strength_scores(pwd, expected_min):
    score, feedback = check_password_strength(pwd)
    assert score >= expected_min
    assert 'Strong' in feedback
