"""
VirusTotal enrichment provider.

Free-tier constraints (2025):
  - 4 requests / minute
  - 500 requests / day
  - 15.5 K requests / month
  - Must NOT be used in commercial products/services

The module-level rate limiter enforces the per-minute cap with a sliding
window of timestamps so we never burst past 4 req/min.
"""

import asyncio
import time
from collections import deque

import httpx
import structlog

from app.config import settings
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Per-minute rate-limiter (module-level, shared across all requests)
# ---------------------------------------------------------------------------

_rate_lock = asyncio.Lock()
_req_timestamps: deque[float] = deque()
_VT_MAX_PER_MINUTE = 4


async def _rate_limit() -> None:
    """Block until we have capacity under the 4 req/min sliding window."""
    async with _rate_lock:
        now = time.monotonic()
        # Drop timestamps older than 60 s
        while _req_timestamps and (now - _req_timestamps[0]) > 60.0:
            _req_timestamps.popleft()
        if len(_req_timestamps) >= _VT_MAX_PER_MINUTE:
            # Sleep until the oldest request falls out of the window
            sleep_for = 60.0 - (now - _req_timestamps[0]) + 0.05
            if sleep_for > 0:
                await asyncio.sleep(sleep_for)
            # Re-trim after sleeping
            now = time.monotonic()
            while _req_timestamps and (now - _req_timestamps[0]) > 60.0:
                _req_timestamps.popleft()
        _req_timestamps.append(time.monotonic())


# ---------------------------------------------------------------------------
# Provider
# ---------------------------------------------------------------------------

# Maps entity kind → VT API resource path segment.
# Include both the old short forms and the canonical model kinds.
_KIND_MAP: dict[str, str] = {
    "ip":         "ip_addresses",
    "ip_address": "ip_addresses",  # ← was missing; canonical kind from lookup.py
    "domain":     "domains",
    "hostname":   "domains",
    "hash":       "files",
    "md5":        "files",
    "sha1":       "files",
    "sha256":     "files",
    "url":        "urls",
    "indicator":  None,            # need more info; skip
}


@register
class VirusTotalProvider(BaseEnrichmentProvider):
    name = "virustotal"
    kind = "indicator"
    supported_kinds = {"ip", "ip_address", "domain", "hostname", "url", "hash", "md5", "sha1", "sha256", "indicator"}

    async def enrich(self, entity_kind: str, entity_value: str) -> dict:
        api_key = self.api_key_override or settings.VIRUSTOTAL_API_KEY
        if not api_key:
            return {}

        resource_type = _KIND_MAP.get(entity_kind)
        if not resource_type:
            return {}

        await _rate_limit()

        url = f"https://www.virustotal.com/api/v3/{resource_type}/{entity_value}"
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, headers={"x-apikey": api_key})
                if resp.status_code == 404:
                    return {"value": entity_value, "not_found": True}
                if resp.status_code == 429:
                    logger.warning("virustotal: rate-limited (429), backing off 60s")
                    await asyncio.sleep(60)
                    return {}
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPError as exc:
            logger.error("virustotal: http error", error=str(exc))
            return {}

        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        votes = attrs.get("total_votes", {})

        result: dict = {
            "value": entity_value,
            "resource_type": resource_type,
            # Detection stats
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "timeout":     stats.get("timeout", 0),
            # Reputation / votes
            "reputation":       attrs.get("reputation"),
            "votes_malicious":  votes.get("malicious", 0),
            "votes_harmless":   votes.get("harmless", 0),
            # Temporal
            "last_analysis_date": attrs.get("last_analysis_date"),
            "last_modification_date": attrs.get("last_modification_date"),
            # Tags / categories
            "tags":       attrs.get("tags", []),
            "categories": attrs.get("categories", {}),
            # VT link
            "vt_link": f"https://www.virustotal.com/gui/{resource_type.rstrip('s')}/{entity_value}",
        }

        # --- IP-specific fields ---
        if resource_type == "ip_addresses":
            result.update({
                "country":        attrs.get("country"),
                "continent":      attrs.get("continent"),
                "as_owner":       attrs.get("as_owner"),
                "asn":            attrs.get("asn"),
                "network":        attrs.get("network"),
                "whois":          attrs.get("whois", "")[:2000],  # cap at 2 KB
                "regional_internet_registry": attrs.get("regional_internet_registry"),
            })

        # --- Domain-specific fields ---
        elif resource_type == "domains":
            result.update({
                "registrar":     attrs.get("registrar"),
                "creation_date": attrs.get("creation_date"),
                "last_dns_records": attrs.get("last_dns_records", [])[:20],
                "popularity_ranks": attrs.get("popularity_ranks", {}),
                "jarm":          attrs.get("jarm"),
            })

        # --- File-specific fields ---
        elif resource_type == "files":
            result.update({
                "file_type":    attrs.get("type_description"),
                "file_size":    attrs.get("size"),
                "md5":          attrs.get("md5"),
                "sha1":         attrs.get("sha1"),
                "sha256":       attrs.get("sha256"),
                "ssdeep":       attrs.get("ssdeep"),
                "tlsh":         attrs.get("tlsh"),
                "meaningful_name": attrs.get("meaningful_name"),
                "names":        attrs.get("names", [])[:10],
                "signature_info": attrs.get("signature_info"),
                "popular_threat_classification": attrs.get("popular_threat_classification"),
            })

        return result
