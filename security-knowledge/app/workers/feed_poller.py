"""Feed poller worker — periodically fetches all due active sources.

Runs as an ARQ cron job every 5 minutes.  For each SourceRecord where
``active=True`` and the next fetch is due (``last_fetched_at + fetch_interval_seconds <= now()``),
it calls the 3-layer fetcher, records a FetchOutcome, and bumps
``last_fetched_at``.  Rate limits are enforced inside ``fetcher.fetch()``.
"""
from __future__ import annotations

import asyncio
import time
from datetime import UTC, datetime

import structlog
from sqlalchemy import or_, select

from app.database import AsyncSessionLocal
from app.fetcher import fetch
from app.models.sources import FetchOutcome, SourceRecord

logger = structlog.get_logger(__name__)

# Max parallel fetches per poll cycle — keeps pressure reasonable
_CONCURRENCY = 5


async def _fetch_source(source: SourceRecord) -> FetchOutcome:
    """Fetch a single source and build a FetchOutcome (not yet persisted)."""
    t0 = time.monotonic()
    try:
        result = await fetch(source.url)
        duration_ms = int((time.monotonic() - t0) * 1000)

        if result.ok:
            outcome = FetchOutcome(
                source_id=source.id,
                status="ok",
                http_status=result.status_code,
                items_fetched=1,
                duration_ms=duration_ms,
            )
            logger.info(
                "feed_fetch_ok",
                source_id=str(source.id),
                url=source.url,
                status_code=result.status_code,
                duration_ms=duration_ms,
            )
        elif result.captcha_detected:
            outcome = FetchOutcome(
                source_id=source.id,
                status="captcha",
                http_status=result.status_code,
                error_message="CAPTCHA/bot-challenge detected",
                duration_ms=duration_ms,
            )
            logger.warning("feed_fetch_captcha", source_id=str(source.id), url=source.url)
        elif result.status_code == 429:
            outcome = FetchOutcome(
                source_id=source.id,
                status="rate_limited",
                http_status=429,
                error_message=result.error or "Rate limit exceeded",
                duration_ms=duration_ms,
            )
            logger.warning("feed_fetch_rate_limited", source_id=str(source.id), url=source.url)
        else:
            outcome = FetchOutcome(
                source_id=source.id,
                status="error",
                http_status=result.status_code,
                error_message=result.error or f"HTTP {result.status_code}",
                duration_ms=duration_ms,
            )
            logger.warning(
                "feed_fetch_error",
                source_id=str(source.id),
                url=source.url,
                error=result.error,
                status_code=result.status_code,
            )
    except Exception as exc:
        duration_ms = int((time.monotonic() - t0) * 1000)
        outcome = FetchOutcome(
            source_id=source.id,
            status="error",
            error_message=str(exc),
            duration_ms=duration_ms,
        )
        logger.error("feed_fetch_exception", source_id=str(source.id), url=source.url, error=str(exc))

    return outcome


async def poll_feeds(ctx: dict) -> dict:
    """ARQ cron job — fetch all overdue active sources.

    Returns a summary dict with counts of ok / error / rate_limited / skipped.
    """
    from sqlalchemy import text

    semaphore = asyncio.Semaphore(_CONCURRENCY)

    async with AsyncSessionLocal() as db:
        # Select sources that are active and due for a fetch.
        # "Due" means last_fetched_at is NULL (never fetched) or
        # last_fetched_at + fetch_interval_seconds ≤ now.
        stmt = select(SourceRecord).where(
            SourceRecord.active == True,  # noqa: E712
            or_(
                SourceRecord.last_fetched_at == None,  # noqa: E711
                text(
                    "sources.last_fetched_at + (sources.fetch_interval_seconds * interval '1 second') <= now()"
                ),
            ),
        )
        result = await db.execute(stmt)
        sources = result.scalars().all()

    if not sources:
        logger.info("feed_poll_no_due_sources")
        return {"ok": 0, "error": 0, "rate_limited": 0, "captcha": 0, "skipped": 0, "total": 0}

    logger.info("feed_poll_starting", due_count=len(sources))

    counters: dict[str, int] = {"ok": 0, "error": 0, "rate_limited": 0, "captcha": 0}

    async def _bounded(source: SourceRecord) -> None:
        async with semaphore:
            outcome = await _fetch_source(source)
            async with AsyncSessionLocal() as db:
                db.add(outcome)
                # Update last_fetched_at regardless of outcome so we don't
                # hammer a broken source on every poll cycle.
                source_row = await db.get(SourceRecord, source.id)
                if source_row is not None:
                    source_row.last_fetched_at = datetime.now(UTC)
                await db.commit()
            counters[outcome.status if outcome.status in counters else "error"] += 1

    await asyncio.gather(*[_bounded(s) for s in sources])

    logger.info("feed_poll_complete", **counters, total=len(sources))
    return {**counters, "total": len(sources)}
