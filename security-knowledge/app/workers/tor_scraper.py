"""Tor-based onion site scraper for ransomware leak sites.

Runs on a configurable interval (default 20min) via ARQ cron.
Scrapes .onion URLs from SourceRecords, captures screenshots,
and enqueues AI enrichment jobs.

Requires Tor SOCKS proxy running on TOR_SOCKS_HOST:TOR_SOCKS_PORT.
"""
from __future__ import annotations

import asyncio
import time
import uuid
from datetime import UTC, datetime

import structlog
from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal
from app.models.sources import FetchOutcome, SourceRecord

logger = structlog.get_logger(__name__)

# Only scrape sources with kind "onion" or URL matching *.onion
_ONION_KINDS = {"onion", "tor", "darknet"}
_CONCURRENCY = 3
_SCREENSHOT_TIMEOUT = 30


def _is_onion_url(url: str) -> bool:
    return ".onion" in url.lower()


async def _fetch_via_tor(url: str, timeout: int = 30) -> dict:
    """Fetch a URL through the Tor SOCKS proxy."""
    import httpx

    proxy_url = f"socks5://{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}"
    headers = {}
    if settings.FEED_POLL_USER_AGENT:
        headers["User-Agent"] = settings.FEED_POLL_USER_AGENT

    t0 = time.monotonic()
    try:
        async with httpx.AsyncClient(
            proxy=proxy_url,
            timeout=timeout,
            follow_redirects=True,
            headers=headers,
        ) as client:
            resp = await client.get(url)
            elapsed = (time.monotonic() - t0) * 1000
            return {
                "ok": resp.is_success,
                "status_code": resp.status_code,
                "text": resp.text[:2_000_000],  # 2MB cap
                "headers": dict(resp.headers),
                "elapsed_ms": int(elapsed),
            }
    except Exception as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return {
            "ok": False,
            "status_code": None,
            "text": None,
            "error": str(exc),
            "elapsed_ms": int(elapsed),
        }


async def _capture_screenshot(url: str) -> bytes | None:
    """Capture a screenshot of an onion URL using Playwright through Tor proxy.

    Requires PLAYWRIGHT_ENABLED=True and a running Tor SOCKS proxy.
    """
    if not settings.PLAYWRIGHT_ENABLED:
        return None

    try:
        from app.browser_pool import browser_pool

        browser = await browser_pool.get()
        if not browser:
            return None

        context = await browser.new_context(
            proxy={
                "server": f"socks5://{settings.TOR_SOCKS_HOST}:{settings.TOR_SOCKS_PORT}"
            }
        )
        page = await context.new_page()

        try:
            await page.goto(url, timeout=_SCREENSHOT_TIMEOUT * 1000, wait_until="domcontentloaded")
            screenshot = await page.screenshot(full_page=False, type="png")
            return screenshot
        finally:
            await context.close()
    except Exception as exc:
        logger.warning("tor_screenshot_failed", url=url, error=str(exc))
        return None


async def _ai_enrich_content(content: str, url: str) -> dict | None:
    """Use LLM to analyze scraped onion content for ransomware victims, claims, etc."""
    provider = settings.AI_ENRICHMENT_PROVIDER
    if not provider or (provider == "openai" and not settings.OPENAI_API_KEY) or \
       (provider == "anthropic" and not settings.ANTHROPIC_API_KEY):
        return None

    prompt = f"""Analyze the following content scraped from a dark web site ({url}).
Identify:
1. New ransomware victims mentioned (organization names, sectors, countries)
2. Any new claims or announcements by the threat actor
3. Bitcoin or cryptocurrency wallet addresses
4. Email addresses or contact information
5. Any indicators of compromise (IPs, domains, hashes)

Content:
{content[:15000]}

Respond in JSON format with keys: victims, claims, wallets, emails, iocs"""

    try:
        if provider == "openai":
            import httpx as _httpx
            async with _httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                    json={
                        "model": settings.AI_ENRICHMENT_MODEL,
                        "messages": [{"role": "user", "content": prompt}],
                        "response_format": {"type": "json_object"},
                        "temperature": 0.1,
                    },
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]

        elif provider == "anthropic":
            import httpx as _httpx
            async with _httpx.AsyncClient(timeout=60) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": settings.ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json",
                    },
                    json={
                        "model": settings.AI_ENRICHMENT_MODEL,
                        "max_tokens": 4096,
                        "messages": [{"role": "user", "content": prompt}],
                    },
                )
                resp.raise_for_status()
                content_blocks = resp.json().get("content", [])
                return next((b["text"] for b in content_blocks if b["type"] == "text"), None)

    except Exception as exc:
        logger.warning("tor_ai_enrichment_failed", url=url, error=str(exc))
        return None


async def _scrape_source(source: SourceRecord) -> tuple[FetchOutcome, int]:
    """Scrape a single onion source through Tor."""
    t0 = time.monotonic()
    new_items = 0

    result = await _fetch_via_tor(source.url)
    duration_ms = result["elapsed_ms"]

    if result["ok"] and result["text"]:
        # Capture screenshot
        screenshot = await _capture_screenshot(source.url)

        # AI enrichment
        ai_result = await _ai_enrich_content(result["text"], source.url)

        # Create ingestion job for the scraped content
        from app.models.documents import ParsedDocument
        from app.models.jobs import IngestionJob

        async with AsyncSessionLocal() as db:
            job = IngestionJob(
                tenant_id=source.tenant_id,
                source_id=source.id,
                source_url=source.url,
                source_type="tor_scrape",
                status="pending",
                payload={
                    "title": f"Tor scrape: {source.title or source.url}",
                    "body": result["text"][:50000],
                    "scraped_at": datetime.now(UTC).isoformat(),
                    "screenshot_captured": screenshot is not None,
                    "ai_enrichment": ai_result,
                },
            )
            db.add(job)
            await db.commit()
            new_items = 1

        outcome = FetchOutcome(
            source_id=source.id,
            status="ok",
            http_status=result["status_code"],
            items_fetched=new_items,
            duration_ms=duration_ms,
        )
        logger.info("tor_scrape_ok", source_id=str(source.id), url=source.url, ai_enriched=ai_result is not None)
    else:
        error = result.get("error", f"HTTP {result.get('status_code')}")
        outcome = FetchOutcome(
            source_id=source.id,
            status="error",
            http_status=result.get("status_code"),
            error_message=error,
            items_fetched=0,
            duration_ms=duration_ms,
        )
        logger.warning("tor_scrape_error", source_id=str(source.id), url=source.url, error=error)

    return outcome, new_items


async def scrape_onion_sources(ctx: dict) -> dict:
    """ARQ cron job — scrape all active onion sources through Tor.

    Only runs when TOR_SCRAPE_ENABLED=true.
    """
    if not settings.TOR_SCRAPE_ENABLED:
        return {"skipped": True, "reason": "TOR_SCRAPE_ENABLED=false"}

    semaphore = asyncio.Semaphore(_CONCURRENCY)
    now = datetime.now(UTC)

    async with AsyncSessionLocal() as db:
        stmt = select(SourceRecord).where(
            SourceRecord.active == True,  # noqa: E712
            SourceRecord.kind.in_(_ONION_KINDS),
        )
        sources = (await db.execute(stmt)).scalars().all()

    # Also include sources with .onion URLs regardless of kind
    all_sources = list(sources)
    async with AsyncSessionLocal() as db:
        stmt2 = select(SourceRecord).where(
            SourceRecord.active == True,  # noqa: E712
        )
        remaining = (await db.execute(stmt2)).scalars().all()
        for s in remaining:
            if _is_onion_url(s.url) and s not in all_sources:
                all_sources.append(s)

    if not all_sources:
        return {"ok": 0, "error": 0, "total": 0, "items_new": 0}

    counters = {"ok": 0, "error": 0, "items_new": 0}

    async def _bounded(source: SourceRecord) -> None:
        async with semaphore:
            outcome, new_items = await _scrape_source(source)
            async with AsyncSessionLocal() as db:
                db.add(outcome)
                src = await db.get(SourceRecord, source.id)
                if src:
                    src.last_fetched_at = datetime.now(UTC)
                await db.commit()
            key = "ok" if outcome.status == "ok" else "error"
            counters[key] += 1
            counters["items_new"] += new_items

    await asyncio.gather(*[_bounded(s) for s in all_sources])

    logger.info("tor_scrape_complete", **counters, total=len(all_sources))
    return {**counters, "total": len(all_sources)}
