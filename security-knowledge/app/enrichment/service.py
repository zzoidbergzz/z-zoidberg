from sqlalchemy.ext.asyncio import AsyncSession
from app.enrichment.registry import get_provider, list_providers
from app.enrichment.budget import check_budget, increment_usage
from app.models.enrichment import EnrichmentCache
from datetime import datetime, timedelta, timezone
import structlog

logger = structlog.get_logger(__name__)


class EnrichmentService:
    def __init__(self, db: AsyncSession, tenant_id: str):
        self.db = db
        self.tenant_id = tenant_id

    async def enrich(self, provider_name: str, entity_kind: str, entity_value: str) -> dict:
        from sqlalchemy import select
        cached = await self.db.execute(
            select(EnrichmentCache).where(
                EnrichmentCache.provider == provider_name,
                EnrichmentCache.entity_kind == entity_kind,
                EnrichmentCache.entity_value == entity_value,
                EnrichmentCache.tenant_id == self.tenant_id,
            )
        )
        row = cached.scalar_one_or_none()
        if row and (row.expires_at is None or row.expires_at > datetime.now(timezone.utc)):
            return row.normalized

        provider_cls = get_provider(provider_name)
        if not provider_cls:
            return {}

        has_budget = await check_budget(self.db, provider_name, self.tenant_id)
        if not has_budget:
            logger.warning("enrichment_budget_exceeded", provider=provider_name)
            return {}

        provider = provider_cls()
        result = await provider.enrich(entity_kind, entity_value)
        await increment_usage(self.db, provider_name, self.tenant_id)

        cache = EnrichmentCache(
            tenant_id=self.tenant_id,
            provider=provider_name,
            entity_kind=entity_kind,
            entity_value=entity_value,
            raw_response=result,
            normalized=result,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        self.db.add(cache)
        await self.db.flush()
        return result
