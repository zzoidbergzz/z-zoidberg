from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

import app.enrichment.providers  # noqa: F401 — side-effect: registers all providers
from app.auth.byok import resolve_user_provider_key
from app.enrichment.budget import check_budget, increment_usage
from app.enrichment.registry import get_provider
from app.models.enrichment import EnrichmentCache

logger = structlog.get_logger(__name__)

# Per-provider TTL (seconds) — loaded lazily to avoid circular imports at startup
_TTL_ATTR: dict[str, str] = {
    "virustotal": "ENRICHMENT_TTL_VIRUSTOTAL",
    "shodan": "ENRICHMENT_TTL_SHODAN",
    "ipinfo": "ENRICHMENT_TTL_IPINFO",
    "greynoise": "ENRICHMENT_TTL_GREYNOISE",
    "crowdstrike": "ENRICHMENT_TTL_CROWDSTRIKE",
    "bgp_he": "ENRICHMENT_TTL_BGP_HE",
    "otx": "ENRICHMENT_TTL_OTX",
    "recordedfuture": "ENRICHMENT_TTL_RF",
    "abuseipdb": "ENRICHMENT_TTL_ABUSEIPDB",
    "urlscan": "ENRICHMENT_TTL_URLSCAN",
}
_DEFAULT_TTL_HOURS = 24


def _provider_ttl(provider_name: str) -> timedelta:
    from app.config import settings

    attr = _TTL_ATTR.get(provider_name)
    if attr:
        seconds = getattr(settings, attr, None)
        if seconds:
            return timedelta(seconds=int(seconds))
    return timedelta(hours=_DEFAULT_TTL_HOURS)


class EnrichmentService:
    def __init__(self, db: AsyncSession, tenant_id: str, user_id: str | None = None):
        self.db = db
        self.tenant_id = tenant_id
        self.user_id = user_id

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
        if row and (row.expires_at is None or row.expires_at > datetime.now(UTC)):
            return row.normalized

        provider_cls = get_provider(provider_name)
        if not provider_cls:
            return {}

        has_budget = await check_budget(self.db, provider_name, self.tenant_id)
        if not has_budget:
            logger.warning("enrichment_budget_exceeded", provider=provider_name)
            return {}

        byok = await resolve_user_provider_key(self.db, self.user_id, provider_name)
        if byok:
            logger.info("enrichment_using_byok", provider=provider_name, user_id=self.user_id)
        provider = provider_cls(api_key=byok) if byok else provider_cls()
        result = await provider.enrich(entity_kind, entity_value)
        await increment_usage(self.db, provider_name, self.tenant_id)

        cache = EnrichmentCache(
            tenant_id=self.tenant_id,
            provider=provider_name,
            entity_kind=entity_kind,
            entity_value=entity_value,
            raw_response=result,
            normalized=result,
            expires_at=datetime.now(UTC) + _provider_ttl(provider_name),
        )
        self.db.add(cache)
        await self.db.flush()
        return result
