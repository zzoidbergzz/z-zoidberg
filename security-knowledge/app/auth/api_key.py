import hashlib
import secrets
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.auth import ApiKey


def generate_api_key() -> tuple[str, str]:
    raw = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    return raw, key_hash


async def validate_api_key(db: AsyncSession, raw_key: str) -> ApiKey | None:
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == key_hash, ApiKey.active == True))  # noqa: E712
    return result.scalar_one_or_none()
