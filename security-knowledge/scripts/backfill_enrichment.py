#!/usr/bin/env python3
"""
Retrospective enrichment backfill.

Iterates every entity in the database and triggers enrichment for every
registered provider that:
  1. Supports the entity's kind
  2. Does NOT already have a valid (non-expired, non-empty) cache entry
  3. Has not exceeded its daily budget

Usage:
    cd security-knowledge
    .venv/bin/python3 scripts/backfill_enrichment.py [--dry-run] [--force] [--tenant-id <uuid>] [--kinds ip_address,domain]

Options:
    --dry-run       Print what would be enriched without calling any APIs
    --force         Delete expired/empty cache entries before re-enriching
                    (overrides TTL checks so old stale {} entries get refreshed)
    --tenant-id     Restrict to a single tenant (default: all tenants)
    --kinds         Comma-separated list of entity kinds to process
                    (default: ip_address,domain,asn,cve,vulnerability,hash,sha256,technique,tactic)
    --limit         Max entities to process (default: unlimited)
    --delay         Seconds to sleep between entity batches (default: 1)
"""

import argparse
import asyncio
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Ensure app imports work when run directly
sys.path.insert(0, str(Path(__file__).parent.parent))

import structlog
from sqlalchemy import select, text

from app.database import AsyncSessionLocal
from app.enrichment.registry import list_providers
from app.enrichment.service import EnrichmentService
from app.models.enrichment import EnrichmentCache

# Import all providers so @register fires
import app.enrichment.providers  # noqa: F401

logger = structlog.get_logger(__name__)


# Providers that require credentials we don't have / aren't applicable to most entities
_SKIP_ALWAYS = {"misp", "opencti", "crowdstrike"}

# Per-kind allow-list of providers that are actually useful
_KIND_PROVIDERS: dict[str, set[str]] = {
    "ip_address": {"virustotal", "greynoise", "shodan", "ipinfo", "bgp_he", "abuseipdb"},
    "ip":         {"virustotal", "greynoise", "shodan", "ipinfo", "bgp_he", "abuseipdb"},
    "domain":     {"virustotal", "greynoise", "ipinfo", "bgp_he", "urlscan"},
    "hostname":   {"virustotal", "greynoise", "ipinfo"},
    "asn":        {"bgp_he"},
    "cve":        {"nvd"},
    "vulnerability": {"nvd"},
    "hash":       {"virustotal"},
    "md5":        {"virustotal"},
    "sha256":     {"virustotal"},
    "sha1":       {"virustotal"},
    "technique":  {"mitre_attack"},
    "tactic":     {"mitre_attack"},
}


async def get_all_entities(db, tenant_id: str | None, kinds: list[str]):
    from app.models.entities import Entity
    q = select(Entity)
    if tenant_id:
        from sqlalchemy import cast
        import uuid
        q = q.where(Entity.tenant_id == uuid.UUID(tenant_id))
    if kinds:
        q = q.where(Entity.kind.in_(kinds))
    q = q.order_by(Entity.kind, Entity.canonical_name)
    result = await db.execute(q)
    return list(result.scalars().all())


async def has_fresh_data(db, tenant_id: str, provider: str, kind: str, value: str) -> bool:
    """Return True only if there is a valid, non-empty, non-expired cache entry."""
    import uuid
    result = await db.execute(
        select(EnrichmentCache).where(
            EnrichmentCache.tenant_id == uuid.UUID(tenant_id),
            EnrichmentCache.provider == provider,
            EnrichmentCache.entity_kind == kind,
            EnrichmentCache.entity_value == value,
        )
    )
    row = result.scalar_one_or_none()
    if row is None:
        return False
    if row.expires_at and row.expires_at < datetime.now(timezone.utc):
        return False  # expired
    normalized = row.normalized or {}
    return bool(normalized and normalized != {})


async def delete_cache_entry(db, tenant_id: str, provider: str, kind: str, value: str) -> None:
    await db.execute(
        text("""
            DELETE FROM enrichment_cache
             WHERE tenant_id  = CAST(:tid AS uuid)
               AND provider     = :prov
               AND entity_kind  = :kind
               AND entity_value = :val
        """),
        {"tid": tenant_id, "prov": provider, "kind": kind, "val": value},
    )


async def backfill(
    dry_run: bool,
    force: bool,
    tenant_id: str | None,
    kinds: list[str],
    limit: int | None,
    delay: float,
) -> None:
    stats: dict[str, int] = {
        "checked": 0,
        "skipped_fresh": 0,
        "skipped_budget": 0,
        "enriched": 0,
        "errors": 0,
    }

    async with AsyncSessionLocal() as db:
        entities = await get_all_entities(db, tenant_id, kinds)

    if limit:
        entities = entities[:limit]
    total = len(entities)
    tag = "[DRY-RUN] " if dry_run else ""
    print(f"\n{tag}Backfill: {total} entities, kinds={kinds}\n")

    for i, entity in enumerate(entities, 1):
        tid    = str(entity.tenant_id)
        kind   = entity.kind
        value  = entity.canonical_name
        target = _KIND_PROVIDERS.get(kind, set()) - _SKIP_ALWAYS

        if not target:
            continue

        print(f"[{i}/{total}] {kind} {value!r}  (tenant {tid[:8]}…)")

        async with AsyncSessionLocal() as db:
            svc = EnrichmentService(db, tid)

            for provider_name in sorted(target):
                stats["checked"] += 1

                if not dry_run:
                    fresh = await has_fresh_data(db, tid, provider_name, kind, value)
                    if fresh:
                        print(f"  ✓ {provider_name:<15} cached")
                        stats["skipped_fresh"] += 1
                        continue

                    if force:
                        await delete_cache_entry(db, tid, provider_name, kind, value)
                        await db.flush()

                if dry_run:
                    print(f"  → would enrich {provider_name}")
                    stats["enriched"] += 1
                    continue

                try:
                    from app.enrichment.budget import check_budget
                    if not await check_budget(db, provider_name, tid):
                        print(f"  ✗ {provider_name:<15} budget exhausted")
                        stats["skipped_budget"] += 1
                        continue

                    result = await svc.enrich(provider_name, kind, value)
                    await db.commit()
                    got = bool(result and result != {})
                    print(f"  {'✓' if got else '○'} {provider_name:<15} {'got data' if got else 'no data returned'}")
                    if got:
                        stats["enriched"] += 1
                except Exception as exc:
                    await db.rollback()
                    print(f"  ✗ {provider_name:<15} ERROR: {exc}")
                    stats["errors"] += 1

        if delay and i < total:
            time.sleep(delay)

    print(f"""
─────────────────────────────────────
Backfill complete
  Entities processed  : {total}
  Provider calls made : {stats['checked']}
  Already fresh (skip): {stats['skipped_fresh']}
  Budget exhausted    : {stats['skipped_budget']}
  Enriched (got data) : {stats['enriched']}
  Errors              : {stats['errors']}
─────────────────────────────────────
""")


def main() -> None:
    p = argparse.ArgumentParser(description="Retrospective enrichment backfill")
    p.add_argument("--dry-run",   action="store_true",
                   help="Show what would be enriched, call no APIs")
    p.add_argument("--force",     action="store_true",
                   help="Delete stale/empty cache entries before re-enriching")
    p.add_argument("--tenant-id", default=None,
                   help="Restrict to one tenant UUID")
    p.add_argument(
        "--kinds",
        default="ip_address,ip,domain,hostname,asn,cve,vulnerability,hash,md5,sha256,technique,tactic",
        help="Comma-separated entity kinds to process",
    )
    p.add_argument("--limit",  type=int,   default=None, help="Max entities to process")
    p.add_argument("--delay",  type=float, default=1.0,  help="Sleep seconds between batches")
    args = p.parse_args()

    kinds = [k.strip() for k in args.kinds.split(",") if k.strip()]
    asyncio.run(backfill(
        dry_run=args.dry_run,
        force=args.force,
        tenant_id=args.tenant_id,
        kinds=kinds,
        limit=args.limit,
        delay=args.delay,
    ))


if __name__ == "__main__":
    main()
