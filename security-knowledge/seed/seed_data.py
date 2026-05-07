"""Seed: creates default tenant, m@z.je admin, and ADMIN API key.

Run with: python -m seed.seed_data
"""
import asyncio
import hashlib
import secrets
import sys

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app.auth.api_key import generate_api_key

SECTORS_SEED = [
    ("uk-general", "UK General", None),
    ("financial-banking", "Financial & Banking", "FS-ISAC"),
    ("retail", "Retail", None),
    ("infrastructure-energy", "Infrastructure & Energy", "E-ISAC"),
    ("healthcare", "Healthcare", "H-ISAC"),
    ("education", "Education", None),
    ("government-defence", "Government & Defence", None),
    ("technology", "Technology", None),
    ("transportation-logistics", "Transportation & Logistics", None),
    ("legal-professional", "Legal & Professional Services", None),
    ("manufacturing", "Manufacturing", None),
    ("media-entertainment", "Media & Entertainment", None),
    ("charity-ngo", "Charity & NGO", None),
]


async def main() -> None:
    import bcrypt
    from app.models.auth import Tenant, User, ApiKey, UserStatus, UserRole
    from app.models.sectors import Sector

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with async_session() as db:
        # 1. Create default tenant if not exists
        t_result = await db.execute(select(Tenant).where(Tenant.slug == "default"))
        tenant = t_result.scalar_one_or_none()
        if not tenant:
            tenant = Tenant(name="Default", slug="default")
            db.add(tenant)
            await db.flush()
            print(f"Created tenant: {tenant.name} ({tenant.id})")
        else:
            print(f"Tenant already exists: {tenant.name} ({tenant.id})")

        # 2. Create admin user if not exists
        u_result = await db.execute(select(User).where(User.email == "m@z.je"))
        user = u_result.scalar_one_or_none()
        if not user:
            hashed = bcrypt.hashpw(b"change-me-on-first-login", bcrypt.gensalt()).decode()
            user = User(
                tenant_id=tenant.id,
                email="m@z.je",
                hashed_password=hashed,
                full_name="Admin",
                business_sector="UK-General",
                status=UserStatus.approved,
                role=UserRole.admin,
            )
            db.add(user)
            await db.flush()
            print(f"Created admin user: {user.email} ({user.id})")
        else:
            print(f"Admin user already exists: {user.email}")

        # 3. Create ADMIN API key
        raw_key, key_hash = generate_api_key()
        k_result = await db.execute(
            select(ApiKey).where(ApiKey.user_id == user.id, ApiKey.name == "ADMIN-KEY")
        )
        existing_key = k_result.scalar_one_or_none()
        if not existing_key:
            api_key = ApiKey(
                tenant_id=tenant.id,
                user_id=user.id,
                key_hash=key_hash,
                name="ADMIN-KEY",
                scopes="superadmin read write admin enrichment watch contact export",
                active=True,
            )
            db.add(api_key)
            await db.flush()
            print(f"\n{'='*60}")
            print(f"ADMIN API KEY (save this — shown only once):")
            print(f"  {raw_key}")
            print(f"{'='*60}\n")
        else:
            print("ADMIN-KEY already exists (not regenerated)")

        # 4. Seed sectors (idempotent via ON CONFLICT DO NOTHING)
        for slug, name, isac_name in SECTORS_SEED:
            s_result = await db.execute(select(Sector).where(Sector.slug == slug))
            if not s_result.scalar_one_or_none():
                sector = Sector(slug=slug, name=name, isac_name=isac_name)
                db.add(sector)

        await db.commit()
        print("Seed complete.")

    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
