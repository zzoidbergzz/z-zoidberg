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


def decrypt_key(token: str) -> str | None:
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


# Providers that currently honour user-supplied BYOK overrides. Keep this
# list in sync with the provider modules that accept an ``api_key`` arg
# and with the settings UI under templates/settings.html.
BYOK_PROVIDERS: tuple[str, ...] = (
    "virustotal",
    "greynoise",
    "ipinfo",
    "shodan",
    "anthropic",
    "abuseipdb",
    "urlscan",
)


async def resolve_user_provider_key(db, user_id, provider: str) -> str | None:
    """Return the decrypted BYOK for ``user_id``+``provider`` or None.

    Safe to call with ``user_id=None`` (returns None). Decryption failures
    are swallowed so callers fall back to the system-wide key.
    """
    if not user_id:
        return None
    if provider not in BYOK_PROVIDERS:
        return None
    import uuid as _uuid

    from sqlalchemy import select

    from app.models.auth import UserProviderKey

    try:
        uid = _uuid.UUID(str(user_id))
    except (ValueError, TypeError):
        return None
    result = await db.execute(
        select(UserProviderKey).where(
            UserProviderKey.user_id == uid,
            UserProviderKey.provider == provider,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return None
    return decrypt_key(row.encrypted_key)
