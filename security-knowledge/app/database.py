from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.config import settings

engine = create_async_engine(settings.DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            # Auto-commit on successful response so write endpoints don't have to
            # call db.commit() explicitly. Endpoints that already commit are still
            # fine: a second commit on a clean session is a no-op.
            if session.in_transaction():
                await session.commit()
        except Exception:
            await session.rollback()
            raise
