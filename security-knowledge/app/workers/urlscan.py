from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import structlog
from sqlalchemy import select

from app.config import settings
from app.database import AsyncSessionLocal
from app.enrichment.providers.urlscan import UrlscanProvider
from app.models.enrichment import EnrichmentCache

logger = structlog.get_logger(__name__)


async def poll_pending_urlscan_scans(ctx: dict, *, _otel_ctx: dict | None = None) -> dict:
    from app.observability.trace_propagation import trace_from_job

    with trace_from_job(ctx, "worker.poll_pending_urlscan_scans", _otel_ctx):
        updated = 0
        checked = 0
        async with AsyncSessionLocal() as db:
            rows = (
                await db.execute(
                    select(EnrichmentCache).where(EnrichmentCache.provider == "urlscan")
                )
            ).scalars().all()
            async with httpx.AsyncClient(timeout=20, headers={"Accept": "application/json"}) as client:
                for row in rows:
                    normalized = row.normalized if isinstance(row.normalized, dict) else {}
                    rescan = normalized.get("rescan") if isinstance(normalized.get("rescan"), dict) else None
                    if not rescan or rescan.get("status") != "requested/pending":
                        continue
                    scan_id = rescan.get("scan_id")
                    if not scan_id:
                        continue
                    checked += 1
                    result_url = rescan.get("scan_url") or f"https://urlscan.io/api/v1/result/{scan_id}/"
                    try:
                        resp = await client.get(result_url)
                    except httpx.HTTPError as exc:
                        logger.warning("urlscan_pending_poll_failed", error=str(exc), scan_id=scan_id)
                        continue
                    if resp.status_code == 404:
                        continue
                    if resp.status_code != 200:
                        logger.warning(
                            "urlscan_pending_poll_status",
                            scan_id=scan_id,
                            status=resp.status_code,
                        )
                        continue
                    try:
                        payload = resp.json()
                    except ValueError:
                        logger.warning("urlscan_pending_poll_invalid_json", scan_id=scan_id)
                        continue

                    after = UrlscanProvider._shape_result_payload(payload)
                    before = rescan.get("before")
                    completed_rescan = {
                        **rescan,
                        "status": "complete",
                        "completed_at": datetime.now(UTC).isoformat(),
                        "after": after,
                        "delta": UrlscanProvider._diff(before, after),
                        "errors": [],
                        "last_checked_at": datetime.now(UTC).isoformat(),
                    }
                    normalized["rescan"] = completed_rescan
                    row.normalized = normalized
                    row.raw_response = payload
                    row.expires_at = datetime.now(UTC) + timedelta(
                        seconds=getattr(settings, "ENRICHMENT_TTL_URLSCAN", 3600)
                    )
                    updated += 1
            if updated:
                await db.commit()
        return {"checked": checked, "updated": updated}
