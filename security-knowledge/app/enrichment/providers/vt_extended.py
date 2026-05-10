"""Enhanced VirusTotal provider with extended graph data extraction.

Adds _fetch_extended_file_data() which calls the VT v3 API for:
- /files/{hash}/contacted_ips
- /files/{hash}/contacted_domains
- /files/{hash}/dropped_files
- /file_behaviours/{hash}_CAPA (ATT&CK + MBC)

The basic enrich() method calls the extended fetch and stores results
under prefixed keys (_contacted_ips, _dropped_files, _capa_attack)
that the graph materializer can consume.

Drop-in replacement — the original virustotal.py enrichment result is
preserved; the extended data is additive.
"""

from __future__ import annotations

import asyncio
import base64
import time
from collections import deque

import httpx
import structlog

from app.config import settings
from app.enrichment import budget
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.providers._rescan_common import utcnow_iso
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

# Rate limiter — reuse the same module-level state as the original VT provider
# (importing the original ensures we share the deque)
from app.enrichment.providers.virustotal import _rate_limit  # noqa: F401

_VT_BASE = "https://www.virustotal.com/api/v3"


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).rstrip(b"=").decode()


async def _vt_get(client: httpx.AsyncClient, path: str, api_key: str) -> tuple[dict | None, str | None]:
    """Rate-limited GET to VT v3 API. Returns (data_dict, error_str)."""
    from app.enrichment.providers.virustotal import _rate_limit as rl
    await rl()
    try:
        resp = await client.get(f"{_VT_BASE}{path}", headers={"x-apikey": api_key})
    except httpx.HTTPError as exc:
        return None, f"http_error:{exc.__class__.__name__}"
    if resp.status_code == 404:
        return None, "not_found"
    if resp.status_code == 429:
        return None, "rate_limited_429"
    if resp.status_code >= 400:
        return None, f"status_{resp.status_code}"
    try:
        return resp.json(), None
    except ValueError:
        return None, "invalid_json"


async def fetch_extended_file_data(sha256: str, api_key: str) -> dict:
    """Fetch extended file data from VT: contacted IPs, dropped files, CAPA.

    Returns dict with keys:
      _contacted_ips: list[str]
      _contacted_domains: list[str]
      _dropped_files: list[str]  (SHA256 hashes)
      _capa_attack: list[dict]   (ATT&CK technique objects)
      _capa_mbc: list[dict]      (MBC behavior objects)
      _capa_signatures: list[dict]

    All fields are best-effort — missing data returns empty lists.
    """
    result: dict = {
        "_contacted_ips": [],
        "_contacted_domains": [],
        "_dropped_files": [],
        "_capa_attack": [],
        "_capa_mbc": [],
        "_capa_signatures": [],
    }

    async with httpx.AsyncClient(timeout=20) as client:
        # Contacted IPs
        try:
            data, err = await _vt_get(client, f"/files/{sha256}/contacted_ips", api_key)
            if data and not err:
                for item in (data.get("data") or []):
                    ip = item.get("id", "").strip()
                    if ip:
                        result["_contacted_ips"].append(ip)
        except Exception as exc:
            logger.debug("vt_extended_contacted_ips_failed", error=str(exc))

        # Contacted domains
        try:
            data, err = await _vt_get(client, f"/files/{sha256}/contacted_domains", api_key)
            if data and not err:
                for item in (data.get("data") or []):
                    dom = item.get("id", "").strip()
                    if dom:
                        result["_contacted_domains"].append(dom)
        except Exception as exc:
            logger.debug("vt_extended_contacted_domains_failed", error=str(exc))

        # Dropped files
        try:
            data, err = await _vt_get(client, f"/files/{sha256}/dropped_files", api_key)
            if data and not err:
                for item in (data.get("data") or []):
                    drop_hash = item.get("id", "").strip()
                    if drop_hash and len(drop_hash) == 64:  # SHA256
                        result["_dropped_files"].append(drop_hash)
        except Exception as exc:
            logger.debug("vt_extended_dropped_files_failed", error=str(exc))

        # CAPA behavioural analysis
        try:
            data, err = await _vt_get(client, f"/file_behaviours/{sha256}_CAPA", api_key)
            if data and not err:
                attrs = (data.get("data") or {}).get("attributes") or {}
                result["_capa_attack"] = attrs.get("mitre_attack_techniques", [])
                result["_capa_mbc"] = attrs.get("mbc", [])
                result["_capa_signatures"] = [
                    {"name": s.get("name"), "description": s.get("description")}
                    for s in attrs.get("signature_matches", [])
                ]
        except Exception as exc:
            logger.debug("vt_extended_capa_failed", error=str(exc))

    return result
