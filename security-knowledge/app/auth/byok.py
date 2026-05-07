"""BYOK (Bring Your Own Key) encryption helpers.

Security design:
- Keys are encrypted with Fernet (AES-128-CBC + HMAC-SHA256).
- The encryption key comes from BYOK_ENCRYPTION_KEY env var (base64-urlsafe 32 bytes).
- If the env var is absent a derived key is used (SECRET_KEY → HKDF) — still safe but
  means key rotation requires SECRET_KEY rotation too.
- The plaintext key is NEVER logged, traced, or returned by any API endpoint.
- If decryption fails (wrong key, corrupted data) we return None so callers fall back
  to the system-wide provider key gracefully.
"""
import base64
import hashlib
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.config import settings


def _get_fernet() -> Fernet:
    raw = settings.BYOK_ENCRYPTION_KEY
    if raw:
        key = base64.urlsafe_b64decode(raw.encode() + b"==")[:32]
        key = base64.urlsafe_b64encode(key)
    else:
        # Derive from SECRET_KEY via HKDF — acceptable fallback
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"sk-byok-v1",
            info=b"byok-encryption",
        )
        derived = hkdf.derive(settings.SECRET_KEY.encode())
        key = base64.urlsafe_b64encode(derived)
    return Fernet(key)


def encrypt_key(plaintext: str) -> str:
    """Encrypt a provider API key for storage. Returns Fernet token (base64 string)."""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_key(token: str) -> Optional[str]:
    """Decrypt a stored key. Returns None on failure (wrong encryption key / corruption)."""
    try:
        return _get_fernet().decrypt(token.encode()).decode()
    except (InvalidToken, Exception):
        return None


def key_hint(plaintext: str) -> str:
    """Return last-4-char hint for UI display, e.g. '...ab3f'."""
    return f"...{plaintext[-4:]}" if len(plaintext) >= 4 else "..."


def value_hash(value: str) -> str:
    """Canonical SHA-256 hash for IOC values and provider key lookups."""
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()
