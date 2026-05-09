"""Feed poller worker — periodically fetches all due active sources.

Runs as an ARQ cron job every 5 minutes.  For each SourceRecord where
``active=True`` and the next fetch is due (``last_fetched_at + fetch_interval_seconds <= now()``),
it calls the 3-layer fetcher, records a FetchOutcome, and bumps
``last_fetched_at``.  Rate limits are enforced inside ``fetcher.fetch()``.

For sources whose ``source_type`` is ``rss`` / ``atom`` / ``feed`` the
response body is parsed with feedparser and one ``IngestionJob`` is
created (and enqueued to ARQ) per new entry.  Entries already present in
``parsed_documents`` for the same tenant are skipped.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import structlog
from sqlalchemy import or_, select

from app.database import AsyncSessionLocal
from app.fetcher import fetch
from app.models.sources import FetchOutcome, SourceRecord

logger = structlog.get_logger(__name__)

# Max parallel fetches per poll cycle — keeps pressure reasonable
_CONCURRENCY = 5

_FEED_TYPES = {"rss", "atom", "feed"}


def _entry_published_at(entry) -> datetime | None:
    """Best-effort extraction of an entry's published timestamp."""
    for attr in ("published", "updated", "created"):
        raw = getattr(entry, attr, None) or (entry.get(attr) if hasattr(entry, "get") else None)
        if not raw:
            continue
        try:
            dt = parsedate_to_datetime(raw)
        except (TypeError, ValueError):
            continue
        if dt is not None:
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt
    return None


async def _parse_and_enqueue_feed(source: SourceRecord, body: str) -> int:
    """Parse a feed body and enqueue ingest jobs for each new entry.

    Returns the count of NEW entries enqueued (i.e. not already ingested).
    """
    import feedparser

    from app.models.documents import ParsedDocument
    from app.models.jobs import IngestionJob

    parsed = feedparser.parse(body)
    entries = parsed.entries or []
    if not entries:
        return 0

    new_count = 0
    pool = None
    try:
        from arq import create_pool
        from arq.connections import RedisSettings

        from app.config import settings as app_settings

        try:
            pool = await create_pool(RedisSettings.from_dsn(app_settings.REDIS_URL))
        except Exception as exc:  # pragma: no cover - redis offline path
            logger.warning("feed_poller_arq_pool_unavailable", error=str(exc))
            pool = None

        async with AsyncSessionLocal() as db:
            for entry in entries:
                link = (entry.get("link") or "").strip()
                if not link:
                    continue

                # Dedupe against ParsedDocument (already ingested) AND any
                # in-flight IngestionJob for the same URL/tenant.
                existing_doc = await db.execute(
                    select(ParsedDocument.id).where(
                        ParsedDocument.tenant_id == source.tenant_id,
                        ParsedDocument.url == link,
                    )
                )
                if existing_doc.scalar_one_or_none() is not None:
                    continue

                existing_job = await db.execute(
                    select(IngestionJob.id).where(
                        IngestionJob.tenant_id == source.tenant_id,
                        IngestionJob.source_url == link,
                        IngestionJob.status.in_(("pending", "queued", "running")),
                    )
                )
                if existing_job.scalar_one_or_none() is not None:
                    continue

                title = (entry.get("title") or link)[:512]
                summary = entry.get("summary", "") or ""
                published_at = _entry_published_at(entry)

                job = IngestionJob(
                    tenant_id=source.tenant_id,
                    source_id=source.id,
                    source_url=link,
                    source_type="feed_entry",
                    status="pending",
                    payload={
                        "title": title,
                        "summary": summary[:4000],
                        "published_at": published_at.isoformat() if published_at else None,
                        "feed_source_id": str(source.id),
                    },
                )
                db.add(job)
                await db.flush()
                new_count += 1

                if pool is not None:
                    try:
                        await pool.enqueue_job("process_ingest_job", str(job.id))
                    except Exception as exc:
                        logger.warning(
                            "feed_poller_enqueue_failed",
                            job_id=str(job.id),
                            url=link,
                            error=str(exc),
                        )

            await db.commit()
    finally:
        if pool is not None:
            try:
                await pool.aclose()
            except Exception:
                pass

    return new_count


async def _fetch_source(source: SourceRecord) -> tuple[FetchOutcome, int]:
    """Fetch a single source, parse if feed, and build a FetchOutcome.

    Returns (outcome, new_items) where new_items is the number of new feed
    entries enqueued (0 for non-feed sources or when parsing fails).
    """
    from app.config import settings as app_settings
    custom_headers = {}
    if app_settings.FEED_POLL_USER_AGENT:
        custom_headers["User-Agent"] = app_settings.FEED_POLL_USER_AGENT

    t0 = time.monotonic()
    new_items = 0
    try:
        result = await fetch(source.url, headers=custom_headers if custom_headers else None)
        duration_ms = int((time.monotonic() - t0) * 1000)

        if result.ok:
            items_total = 1
            if (source.source_type or "").lower() in _FEED_TYPES and result.text:
                import feedparser

                try:
                    parsed = feedparser.parse(result.text)
                    items_total = len(parsed.entries or []) or 1
                    new_items = await _parse_and_enqueue_feed(source, result.text)
                except Exception as exc:
                    logger.warning(
                        "feed_parse_failed",
                        source_id=str(source.id),
                        url=source.url,
                        error=str(exc),
                    )

            outcome = FetchOutcome(
                source_id=source.id,
                status="ok",
                http_status=result.status_code,
                items_fetched=new_items if new_items else items_total,
                duration_ms=duration_ms,
            )
            logger.info(
                "feed_polled",
                source_id=str(source.id),
                url=source.url,
                status_code=result.status_code,
                items_total=items_total,
                items_new=new_items,
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

    return outcome, new_items


async def poll_feeds(ctx: dict) -> dict:
    """ARQ cron job — fetch all overdue active sources.

    Returns a summary dict with counts of ok / error / rate_limited / skipped.
    """
    from sqlalchemy import text

    semaphore = asyncio.Semaphore(_CONCURRENCY)
    now = datetime.now(UTC)

    async with AsyncSessionLocal() as db:
        # Select sources that are active and due for a fetch.
        # "Due" means last_fetched_at is NULL (never fetched) or
        # last_fetched_at + fetch_interval_seconds ≤ now.
        stmt = select(SourceRecord).where(
            SourceRecord.active == True,  # noqa: E712
            or_(
                SourceRecord.last_fetched_at == None,  # noqa: E711
                text(
                    "source_records.last_fetched_at + (source_records.fetch_interval_seconds * interval '1 second') <= now()"
                ),
            ),
        )
        result = await db.execute(stmt)
        sources = result.scalars().all()

    # Belt-and-braces: enforce fetch_interval client-side too (some callers
    # invoke poll_feeds directly with sources that were just created).
    due_sources: list[SourceRecord] = []
    for s in sources:
        if s.last_fetched_at is None:
            due_sources.append(s)
            continue
        interval = s.fetch_interval_seconds or 3600
        last = s.last_fetched_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if last + timedelta(seconds=interval) <= now:
            due_sources.append(s)

    if not due_sources:
        logger.info("feed_poll_no_due_sources")
        return {"ok": 0, "error": 0, "rate_limited": 0, "captcha": 0, "skipped": 0, "total": 0, "items_new": 0}

    logger.info("feed_poll_starting", due_count=len(due_sources))

    counters: dict[str, int] = {"ok": 0, "error": 0, "rate_limited": 0, "captcha": 0, "items_new": 0}

    async def _bounded(source: SourceRecord) -> None:
        async with semaphore:
            outcome, new_items = await _fetch_source(source)
            async with AsyncSessionLocal() as db:
                db.add(outcome)
                # Update last_fetched_at regardless of outcome so we don't
                # hammer a broken source on every poll cycle.
                source_row = await db.get(SourceRecord, source.id)
                if source_row is not None:
                    source_row.last_fetched_at = datetime.now(UTC)
                await db.commit()
            key = outcome.status if outcome.status in counters else "error"
            counters[key] += 1
            counters["items_new"] += new_items

    await asyncio.gather(*[_bounded(s) for s in due_sources])

    logger.info("feed_poll_complete", **counters, total=len(due_sources))
    return {**counters, "total": len(due_sources)}

