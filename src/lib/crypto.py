"""Cryptographic utilities (encryption + password strength)."""
from __future__ import annotations
import base64, secrets, hashlib
from typing import Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config.settings import (
	DEFAULT_ITERATIONS, SALT_LENGTH, KEY_LENGTH, IV_LENGTH, AUTH_TAG_LENGTH
)

class CryptoError(Exception):
	pass

class VaultCrypto:
	def __init__(self):
		self._backend = default_backend()

	def generate_salt(self) -> bytes:
		return secrets.token_bytes(SALT_LENGTH)

	def derive_key(self, password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
		if not password:
			raise CryptoError("Password empty")
		kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LENGTH, salt=salt, iterations=iterations, backend=self._backend)
		return kdf.derive(password.encode())

	def encrypt(self, data: bytes, key: bytes) -> bytes:
		if len(key) != KEY_LENGTH: raise CryptoError("Bad key length")
		iv = secrets.token_bytes(IV_LENGTH)
		cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=self._backend)
		enc = cipher.encryptor()
		ct = enc.update(data) + enc.finalize()
		return iv + ct + enc.tag

	def decrypt(self, blob: bytes, key: bytes) -> bytes:
		if len(key) != KEY_LENGTH: raise CryptoError("Bad key length")
		if len(blob) < IV_LENGTH + AUTH_TAG_LENGTH: raise CryptoError("Ciphertext too short")
		iv = blob[:IV_LENGTH]; tag = blob[-AUTH_TAG_LENGTH:]; ct = blob[IV_LENGTH:-AUTH_TAG_LENGTH]
		cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=self._backend)
		dec = cipher.decryptor()
		try:
			return dec.update(ct) + dec.finalize()
		except Exception as e:  # pragma: no cover (error path)
			raise CryptoError(f"Decrypt failed: {e}")

	def encrypt_text(self, text: str, key: bytes) -> str:
		return base64.b64encode(self.encrypt(text.encode('utf-8'), key)).decode('ascii')

	def decrypt_text(self, token: str, key: bytes) -> str:
		return self.decrypt(base64.b64decode(token), key).decode('utf-8')

def check_password_strength(password: str) -> Tuple[int, str]:
	score = 0; fb = []
	L = len(password)
	if L >= 12: score += 30
	elif L >= 8: score += 20; fb.append('Use 12+ chars')
	else: fb.append('Too short (min 8)')
	sets = [any(c.islower() for c in password), any(c.isupper() for c in password), any(c.isdigit() for c in password), any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)]
	score += sum(sets)*15
	if sum(sets) < 4: fb.append('Add diverse character sets')
	common = ['password','qwerty','abc','123','111']
	if any(p in password.lower() for p in common):
		score -= 15; fb.append('Avoid common patterns')
	if len(set(password)) < L*0.6:
		score -= 10; fb.append('Too many repeats')
	score = max(0, min(100, score))
	if score >= 80: label='Very Strong'
	elif score >= 60: label='Strong'
	elif score >= 40: label='Moderate'
	elif score >= 20: label='Weak'
	else: label='Very Weak'
	text = f"{label} ({score}/100)"
	if fb: text += ' - ' + ', '.join(fb)
	if 'Strong' not in text: text += ' | Strong password guidelines: mix upper/lower/digits/symbols.'
	return score, text

def sha256_bytes(data: bytes) -> str:
	return hashlib.sha256(data).hexdigest()

