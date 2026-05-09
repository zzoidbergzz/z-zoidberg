"""Recorded Future enrichment provider.

BYOK: set RecordedFutureAPI in .env or via admin settings.
API docs: https://api.recordedfuture.com/index.html
"""
from __future__ import annotations

import time
from typing import Any

import httpx
import structlog

from app.config import settings
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

_SUPPORTED_KINDS = {"ip_address", "domain", "hash", "cve", "url"}


@register
class RecordedFutureProvider(BaseEnrichmentProvider):
    name = "recordedfuture"
    display_name = "Recorded Future"

    async def enrich(self, kind: str, value: str) -> dict[str, Any]:
        if not settings.RECORDED_FUTURE_API_KEY:
            return {"provider": self.name, "status": "skipped", "error": "No API key configured"}

        if kind not in _SUPPORTED_KINDS:
            return {"provider": self.name, "status": "skipped", "error": f"Unsupported kind: {kind}"}

        headers = {"X-RFToken": settings.RECORDED_FUTURE_API_KEY}
        base = "https://api.recordedfuture.com/v2"

        t0 = time.monotonic()
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                if kind == "ip_address":
                    resp = await client.get(f"{base}/ip/{value}", params={"fields": "risk,internal"}, headers=headers)
                elif kind == "domain":
                    resp = await client.get(f"{base}/domain/{value}", params={"fields": "risk,internal"}, headers=headers)
                elif kind == "hash":
                    resp = await client.get(f"{base}/hash/{value}", headers=headers)
                elif kind == "cve":
                    resp = await client.get(f"{base}/vulnerability/{value}", headers=headers)
                elif kind == "url":
                    # Use search for URLs
                    resp = await client.get(f"{base}/search", params={"q": value, "limit": 5}, headers=headers)
                else:
                    return {"provider": self.name, "status": "skipped"}

                resp.raise_for_status()
                elapsed = int((time.monotonic() - t0) * 1000)

                return {
                    "provider": self.name,
                    "status": "ok",
                    "data": resp.json(),
                    "elapsed_ms": elapsed,
                }

        except httpx.HTTPStatusError as exc:
            elapsed = int((time.monotonic() - t0) * 1000)
            return {
                "provider": self.name,
                "status": "error",
                "error": f"HTTP {exc.response.status_code}",
                "elapsed_ms": elapsed,
            }
        except Exception as exc:
            elapsed = int((time.monotonic() - t0) * 1000)
            return {
                "provider": self.name,
                "status": "error",
                "error": str(exc),
                "elapsed_ms": elapsed,
            }
