"""ARQ worker: EUVD (EU Vulnerability Database) incremental sync.

Runs every 20 minutes. On first run (empty DB), performs bulk seed.
Subsequent runs fetch only records updated since last sync.
Upserts into corpus_documents with full metadata preservation.
"""

from __future__ import annotations

import time
import uuid
from datetime import UTC, datetime, timedelta

import structlog
from arq import cron
from sqlalchemy import select, text, func
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import AsyncSessionLocal
from app.integrations.euvd.client import EUVDClient
from app.integrations.euvd.normalizer import normalize_euvd_record
from app.models.corpus import CorpusDocument

logger = structlog.get_logger(__name__)

# Default tenant ID (matches bootstrap admin)
_DEFAULT_TENANT = "bcc8ab78-0982-4ea3-81d3-7e4bd166881a"


async def euvd_sync(ctx: dict) -> dict:
    """Sync EUVD vulnerability data into corpus_documents."""
    start = time.monotonic()
    client = EUVDClient(page_delay=1.0)

    new_count = 0
    updated_count = 0

    async with AsyncSessionLocal() as db:
        # Check if we have any EUVD records already
        existing = await db.execute(
            select(func.count()).select_from(CorpusDocument).where(CorpusDocument.corpus == "euvd")
        )
        total_existing = existing.scalar() or 0

        if total_existing == 0:
            # Bulk seed: fetch everything (respecting rate limits)
            logger.info("euvd_bulk_seed_start")
            records = await client.bulk_fetch_all(size=100, max_pages=None)
        else:
            # Incremental: fetch records from last 2 days to catch updates
            since = (datetime.now(UTC) - timedelta(days=2)).strftime("%Y-%m-%d")
            logger.info("euvd_incremental_sync", since=since, existing=total_existing)
            records = await client.incremental_fetch(since_date=since, size=100)
            # Also grab the latest 8 + exploited + critical
            try:
                records.extend(await client.last_vulnerabilities())
            except Exception:
                pass
            try:
                records.extend(await client.exploited_vulnerabilities())
            except Exception:
                pass
            try:
                records.extend(await client.critical_vulnerabilities())
            except Exception:
                pass

        # Upsert each record
        for record in records:
            if not record.id:
                continue
            norm = normalize_euvd_record(record)

            stmt = pg_insert(CorpusDocument).values(
                tenant_id=uuid.UUID(_DEFAULT_TENANT),
                corpus=norm["corpus"],
                external_id=norm["external_id"],
                title=norm["title"],
                summary=norm["summary"],
                body_text=norm["body_text"],
                raw_json=norm["raw_json"],
                published_at=norm["published_at"],
                modified_at=norm["modified_at"],
            ).on_conflict_do_update(
                index_elements=["corpus", "external_id"],
                set_={
                    "title": norm["title"],
                    "summary": norm["summary"],
                    "body_text": norm["body_text"],
                    "raw_json": norm["raw_json"],
                    "published_at": norm["published_at"],
                    "modified_at": norm["modified_at"],
                    "updated_at": datetime.now(UTC),
                },
            )

            # Track new vs updated
            existing_rec = await db.execute(
                select(CorpusDocument.id).where(
                    CorpusDocument.corpus == norm["corpus"],
                    CorpusDocument.external_id == norm["external_id"],
                )
            )
            is_update = existing_rec.first() is not None

            await db.execute(stmt)

            if is_update:
                updated_count += 1
            else:
                new_count += 1

        # Update search vectors for EUVD docs
        await db.execute(text(
            "UPDATE corpus_documents SET search_vector = "
            "to_tsvector('english', coalesce(title,'') || ' ' || coalesce(summary,'') || ' ' || coalesce(body_text,'')) "
            "WHERE corpus = 'euvd' AND search_vector IS NULL"
        ))

        await db.commit()

    elapsed = time.monotonic() - start
    logger.info(
        "euvd_sync_complete",
        new=new_count,
        updated=updated_count,
        total_fetched=len(records),
        elapsed_sec=round(elapsed, 1),
    )

    return {"new": new_count, "updated": updated_count, "fetched": len(records), "elapsed_sec": round(elapsed, 1)}


# ARQ cron job definition — runs every 20 minutes
euvd_cron = cron(euvd_sync, minute={0, 20, 40}, second=0)
