"""Enrichment diff computation and force-refresh service."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.enrichment import EnrichmentCache, EnrichmentDiff
from app.enrichment.registry import get_provider
import structlog

logger = structlog.get_logger(__name__)


def compute_diff(old: dict, new: dict) -> dict:
    """Returns {added: {k: v}, removed: {k: v}, changed: {k: [old, new]}}"""
    added = {k: v for k, v in new.items() if k not in old}
    removed = {k: v for k, v in old.items() if k not in new}
    changed = {
        k: [old[k], new[k]]
        for k in old
        if k in new and old[k] != new[k]
    }
    return {"added": added, "removed": removed, "changed": changed}


async def force_refresh_enrichment(
    entity_value: str,
    entity_kind: str,
    provider: str,
    user_id: str | None,
    tenant_id: str,
    db: AsyncSession,
) -> tuple[dict, EnrichmentDiff | None]:
    """Force fresh lookup bypassing cache. Returns (new_data, diff_or_None)."""
    from datetime import timedelta

    # 1. Fetch current cache entry (if any)
    result = await db.execute(
        select(EnrichmentCache).where(
            EnrichmentCache.provider == provider,
            EnrichmentCache.entity_kind == entity_kind,
            EnrichmentCache.entity_value == entity_value,
            EnrichmentCache.tenant_id == uuid.UUID(tenant_id) if tenant_id else None,
        )
    )
    existing = result.scalar_one_or_none()
    old_normalized: dict = existing.normalized if existing else {}

    # 2. Call provider fresh (no cache read)
    provider_cls = get_provider(provider)
    if not provider_cls:
        logger.warning("force_refresh_unknown_provider", provider=provider)
        return {}, None

    prov = provider_cls()
    new_data = await prov.enrich(entity_kind, entity_value)

    # 3. Compute diff
    diff_summary = compute_diff(old_normalized, new_data)
    has_changes = bool(diff_summary["added"] or diff_summary["removed"] or diff_summary["changed"])

    # 4. Store EnrichmentDiff row
    diff_row = EnrichmentDiff(
        cache_entry_id=existing.id if existing else None,
        provider=provider,
        entity_kind=entity_kind,
        entity_value=entity_value,
        previous_normalized=old_normalized,
        new_normalized=new_data,
        diff_summary=diff_summary,
        has_changes=has_changes,
        requested_by_user_id=uuid.UUID(user_id) if user_id else None,
        requested_by_tenant_id=uuid.UUID(tenant_id) if tenant_id else None,
    )
    db.add(diff_row)

    # 5. Update/create cache entry
    if existing:
        existing.normalized = new_data
        existing.raw_response = new_data
        existing.expires_at = datetime.now(timezone.utc) + timedelta(hours=24)
    else:
        cache = EnrichmentCache(
            tenant_id=uuid.UUID(tenant_id) if tenant_id else None,
            provider=provider,
            entity_kind=entity_kind,
            entity_value=entity_value,
            raw_response=new_data,
            normalized=new_data,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
        )
        db.add(cache)

    await db.flush()

    # Notify IOC watchers if data changed
    if has_changes:
        try:
            from app.services.diff_alerting import notify_diff_watchers
            await notify_diff_watchers(
                entity_value=entity_value,
                entity_kind=entity_kind,
                provider=provider,
                diff_summary=diff_summary,
                has_changes=has_changes,
                diff_id=diff_row.id,
                db=db,
            )
        except Exception as alert_exc:
            logger.warning("diff_alerting_failed", error=str(alert_exc))

    return new_data, diff_row
