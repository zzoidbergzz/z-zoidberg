import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.enrichment import EnrichmentUsage

logger = structlog.get_logger(__name__)

# Map provider name → config attribute name for daily budget.
# Looked up lazily so we don't import settings at module level (avoids
# circular imports during startup).
_BUDGET_ATTR: dict[str, str] = {
    "virustotal": "VIRUSTOTAL_DAILY_BUDGET",
    "shodan": "SHODAN_DAILY_BUDGET",
    "greynoise": "GREYNOISE_DAILY_BUDGET",
    "crowdstrike": "CROWDSTRIKE_DAILY_BUDGET",
    "bgp_he": "BGP_HE_DAILY_BUDGET",
}
_DEFAULT_BUDGET = 1000


def _daily_budget(provider: str) -> int:
    """Return the configured daily budget for *provider*, falling back to 1000."""
    from app.config import settings

    attr = _BUDGET_ATTR.get(provider)
    if attr:
        return int(getattr(settings, attr, _DEFAULT_BUDGET))
    return _DEFAULT_BUDGET


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
        usage = EnrichmentUsage(
            provider=provider,
            tenant_id=tenant_id,
            date=today,
            count=1,
            budget=_daily_budget(provider),  # use configured value, not hardcoded 1000
        )
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
