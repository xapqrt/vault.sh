"""Authentication helpers (hash & verify passwords)."""
from __future__ import annotations
import bcrypt

class AuthError(Exception):
	pass

def hash_password(password: str) -> str:
	if not password:
		raise AuthError('Empty password')
	return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(password: str, hashed: str) -> bool:
	try:
		return bcrypt.checkpw(password.encode(), hashed.encode())
	except Exception:
		return False

