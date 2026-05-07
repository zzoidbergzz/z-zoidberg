from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.models.enrichment import EnrichmentUsage
import structlog

logger = structlog.get_logger(__name__)


async def check_budget(db: AsyncSession, provider: str, tenant_id: str) -> bool:
    from datetime import date
    today = date.today().isoformat()
    result = await db.execute(
        select(EnrichmentUsage).where(
            EnrichmentUsage.provider == provider,
            EnrichmentUsage.tenant_id == tenant_id,
            EnrichmentUsage.date == today,
        )
    )
    usage = result.scalar_one_or_none()
    if usage is None:
        return True
    return usage.count < usage.budget


async def increment_usage(db: AsyncSession, provider: str, tenant_id: str) -> None:
    from datetime import date
    today = date.today().isoformat()
    result = await db.execute(
        select(EnrichmentUsage).where(
            EnrichmentUsage.provider == provider,
            EnrichmentUsage.tenant_id == tenant_id,
            EnrichmentUsage.date == today,
        )
    )
    usage = result.scalar_one_or_none()
    if usage is None:
        usage = EnrichmentUsage(provider=provider, tenant_id=tenant_id, date=today, count=1)
        db.add(usage)
    else:
        usage.count += 1
    await db.flush()


class BudgetTracker:
    """Class-based budget tracker for use in tests."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def check_and_increment(self, tenant_id: str, provider: str) -> bool:
        allowed = await check_budget(self.db, provider, tenant_id)
        if allowed:
            await increment_usage(self.db, provider, tenant_id)
        return allowed
