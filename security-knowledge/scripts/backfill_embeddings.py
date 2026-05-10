"""Backfill pgvector embeddings for all entities and claims.

Usage:
    python3 scripts/backfill_embeddings.py [--table entities|claims] [--batch 100] [--resume]

The script is chunked and resumable: it processes rows in ascending `id` order
and skips rows that already have a non-null embedding.  Run multiple times to
pick up any rows that failed due to transient API errors.

Requirements:
    - EMBEDDING_API_URL and SEARCH_USE_SEMANTIC=true must be set in env
    - pgvector extension must be installed (migration 0037)
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

# Allow running from repo root: python3 security-knowledge/scripts/backfill_embeddings.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.config import settings
from app.embeddings.generator import generate_embedding

logger = structlog.get_logger("backfill_embeddings")


async def backfill(table: str, batch_size: int) -> None:
    if not settings.EMBEDDING_API_URL:
        logger.error("EMBEDDING_API_URL not set — cannot generate embeddings")
        return

    engine = create_async_engine(settings.DATABASE_URL, echo=False)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    total = 0
    skipped = 0
    errors = 0

    if table == "entities":
        select_sql = text(
            "SELECT id::text, kind, canonical_name FROM entities "
            "WHERE embedding IS NULL ORDER BY id LIMIT :lim OFFSET :off"
        )

        def _text_for(row) -> str:
            return f"{row.kind}: {row.canonical_name}"

    else:  # claims
        select_sql = text(
            "SELECT id::text, claim_type, description FROM claims "
            "WHERE embedding IS NULL ORDER BY id LIMIT :lim OFFSET :off"
        )

        def _text_for(row) -> str:
            return f"{row.claim_type}: {row.description or ''}"

    update_sql = text(f"UPDATE {table} SET embedding = :emb WHERE id = :id")

    offset = 0
    while True:
        async with factory() as session:
            rows = (
                await session.execute(select_sql, {"lim": batch_size, "off": offset})
            ).fetchall()

        if not rows:
            break

        logger.info("processing_batch", table=table, offset=offset, count=len(rows))

        for row in rows:
            text_val = _text_for(row)
            try:
                emb = await generate_embedding(text_val)
                if not emb or all(v == 0.0 for v in emb):
                    skipped += 1
                    continue
                async with factory() as session:
                    await session.execute(update_sql, {"emb": str(emb), "id": row.id})
                    await session.commit()
                total += 1
            except Exception as exc:
                logger.error("embedding_failed", row_id=row.id, error=str(exc))
                errors += 1

        offset += batch_size
        await asyncio.sleep(0.05)  # gentle rate-limit pause

    logger.info(
        "backfill_complete",
        table=table,
        embedded=total,
        skipped=skipped,
        errors=errors,
    )
    await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Backfill pgvector embeddings")
    parser.add_argument("--table", default="entities", choices=["entities", "claims"])
    parser.add_argument("--batch", type=int, default=100)
    args = parser.parse_args()

    asyncio.run(backfill(args.table, args.batch))


if __name__ == "__main__":
    main()
