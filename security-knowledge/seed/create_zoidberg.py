"""Create the zoidberg ingest user and API key.

Run with:
    cd security-knowledge
    . .venv/bin/activate
    python -m seed.create_zoidberg
"""
import asyncio
import sys
from pathlib import Path
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.auth.api_key import generate_api_key

ZOIDBERG_EMAIL = "zoidberg@z.je"
KEY_NAME = "ZOIDBERG-KEY"
SCOPES = "superadmin read write admin enrichment watch contact export"


async def main() -> None:
    import bcrypt
    from app.models.auth import Tenant, User, ApiKey, UserStatus, UserRole

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        # Resolve default tenant
        t_result = await db.execute(select(Tenant).where(Tenant.slug == "default"))
        tenant = t_result.scalar_one_or_none()
        if not tenant:
            print("ERROR: default tenant not found — run seed_data.py first", file=sys.stderr)
            sys.exit(1)

        # Create zoidberg user if not exists
        u_result = await db.execute(select(User).where(User.email == ZOIDBERG_EMAIL))
        user = u_result.scalar_one_or_none()
        if not user:
            hashed = bcrypt.hashpw(b"not-used-api-key-auth-only", bcrypt.gensalt()).decode()
            user = User(
                tenant_id=tenant.id,
                email=ZOIDBERG_EMAIL,
                hashed_password=hashed,
                full_name="Zoidberg Ingest Agent",
                business_sector="UK-General",
                status=UserStatus.approved,
                role=UserRole.admin,
            )
            db.add(user)
            await db.flush()
            print(f"Created user: {user.email} ({user.id})")
        else:
            print(f"User already exists: {user.email} ({user.id})")

        # Create or recreate ZOIDBERG-KEY
        k_result = await db.execute(
            select(ApiKey).where(ApiKey.user_id == user.id, ApiKey.name == KEY_NAME)
        )
        existing_key = k_result.scalar_one_or_none()
        if not existing_key:
            raw_key, key_hash = generate_api_key()
            api_key = ApiKey(
                tenant_id=tenant.id,
                user_id=user.id,
                key_hash=key_hash,
                name=KEY_NAME,
                scopes=SCOPES,
                active=True,
            )
            db.add(api_key)
            await db.flush()
            print(f"\n{'='*60}")
            print(f"ZOIDBERG API KEY (save this — shown only once):")
            print(f"  {raw_key}")
            print(f"{'='*60}\n")

            # Persist to .runtime/
            log_path = Path(__file__).parent.parent / ".runtime" / f"zoidberg-key-{datetime.utcnow().strftime('%Y-%m-%d')}.log"
            log_path.parent.mkdir(exist_ok=True)
            log_path.write_text(
                f"user: {user.email} ({user.id})\nkey_name: {KEY_NAME}\napi_key: {raw_key}\nscopes: {SCOPES}\n"
            )
            log_path.chmod(0o600)
            print(f"Key saved to: {log_path}")
        else:
            print(f"{KEY_NAME} already exists (not regenerated). Check .runtime/ for the key.")

        await db.commit()
        print("Done.")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
