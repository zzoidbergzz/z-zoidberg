"""Backfill enrichment for entities that lack any cached results.

Enqueues run_enrichment arq jobs for every entity whose (entity_id, provider)
pair is missing from enrichment_cache, scoped by the auto-enrichment provider map.

Idempotent: run as often as you like; existing cache entries are skipped by the
provider services themselves. Limit per-kind via --per-kind to avoid overwhelming
external APIs / quotas.
"""
from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.entities import Entity
from app.models.enrichment import EnrichmentCache
from app.config import settings
from app.worker import _AUTO_ENRICHMENT_PROVIDERS


async def main(per_kind: int, dry_run: bool) -> None:
    async with AsyncSessionLocal() as db:
        # Map (entity_value, provider) → already cached
        cache_rows = (await db.execute(
            select(EnrichmentCache.entity_value, EnrichmentCache.provider)
        )).all()
        cached: set[tuple] = {(r[0], r[1]) for r in cache_rows}

        # Collect candidate entities by kind
        plan: dict[str, list[tuple]] = defaultdict(list)
        for kind, providers in _AUTO_ENRICHMENT_PROVIDERS.items():
            entities = (await db.execute(
                select(Entity.id, Entity.tenant_id, Entity.canonical_name)
                .where(Entity.kind == kind)
                .limit(per_kind)
            )).all()
            for eid, tid, name in entities:
                for prov in providers:
                    if (name, prov) not in cached:
                        plan[kind].append((eid, tid, prov, name))

    print("Backfill plan:")
    total = 0
    for kind, items in plan.items():
        print(f"  {kind}: {len(items)} jobs ({len(set((i[0],) for i in items))} entities)")
        total += len(items)
    print(f"  TOTAL: {total} jobs")

    if dry_run or total == 0:
        return

    from arq import create_pool
    from arq.connections import RedisSettings

    pool = await create_pool(RedisSettings.from_dsn(settings.REDIS_URL))
    enqueued = 0
    for kind, items in plan.items():
        for eid, tid, prov, name in items:
            try:
                await pool.enqueue_job("run_enrichment", str(eid), str(tid), provider=prov)
                enqueued += 1
            except Exception as exc:
                print(f"  enqueue failed {kind} {name} {prov}: {exc}")
    await pool.aclose()
    print(f"Enqueued {enqueued} jobs.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--per-kind", type=int, default=200, help="max entities per kind to process")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    asyncio.run(main(args.per_kind, args.dry_run))
