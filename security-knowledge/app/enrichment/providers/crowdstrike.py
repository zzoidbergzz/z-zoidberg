"""CrowdStrike Falcon enrichment provider.

Uses the CrowdStrike Falcon API (OAuth2 client-credentials) directly
via httpx rather than the falcon-mcp stdio server, so results flow
through the standard enrichment cache and policy-gate pipeline.

Supports:
- Indicators: IP addresses, domains, hashes (MD5/SHA256), URLs
- Actors/adversary groups by name

Credentials required (set in .env):
    CROWDSTRIKE_CLIENT_ID      = <your OAuth2 client ID>
    CROWDSTRIKE_CLIENT_SECRET  = <your OAuth2 client secret>
    CROWDSTRIKE_BASE_URL       = https://api.crowdstrike.com  # default
"""

from __future__ import annotations

import time
from typing import Any, ClassVar

import httpx
import structlog

from app.config import settings
from app.enrichment.base import BaseEnrichmentProvider
from app.enrichment.registry import register

logger = structlog.get_logger(__name__)

# Simple in-process token cache (per-process; works for single-worker deploys)
_token_cache: dict[str, Any] = {"access_token": None, "expires_at": 0.0}


async def _get_access_token(client_id: str, client_secret: str, base_url: str) -> str | None:
    """Return a cached OAuth2 bearer token, refreshing when expired."""
    now = time.monotonic()
    if _token_cache["access_token"] and now < _token_cache["expires_at"] - 30:
        return _token_cache["access_token"]  # type: ignore[return-value]

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(
            f"{base_url}/oauth2/token",
            data={"client_id": client_id, "client_secret": client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if resp.status_code != 201:
            logger.warning("crowdstrike_token_error", status=resp.status_code)
            return None
        data = resp.json()

    _token_cache["access_token"] = data.get("access_token")
    _token_cache["expires_at"] = now + data.get("expires_in", 1799)
    return _token_cache["access_token"]  # type: ignore[return-value]


@register
class CrowdStrikeProvider(BaseEnrichmentProvider):
    """CrowdStrike Falcon threat intelligence provider.

    Checks indicators against Falcon Intelligence custom IOC feeds and
    the Intel API. Falls back gracefully if credentials are absent.
    """

    name = "crowdstrike"
    kind = "indicator"
    supported_kinds: ClassVar[set[str]] = {
        "ip",
        "ip_address",
        "domain",
        "hash",
        "md5",
        "sha256",
        "url",
        "indicator",
    }

    def _creds(self) -> tuple[str, str, str]:
        client_id = self.api_key_override or settings.CROWDSTRIKE_CLIENT_ID
        return client_id, settings.CROWDSTRIKE_CLIENT_SECRET, settings.CROWDSTRIKE_BASE_URL

    async def enrich(self, entity_kind: str, entity_value: str) -> dict[str, Any]:
        client_id, client_secret, base_url = self._creds()
        if not client_id or not client_secret:
            return {}

        if entity_kind not in self.supported_kinds:
            return {}

        token = await _get_access_token(client_id, client_secret, base_url)
        if not token:
            return {}

        headers = {"Authorization": f"Bearer {token}"}

        # Map entity kind to CrowdStrike indicator type
        cs_type = _kind_to_cs_type(entity_kind, entity_value)

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(
                f"{base_url}/intel/combined/indicators/v1",
                params={"filter": f"indicator:'{entity_value}'+type:'{cs_type}'", "limit": 5},
                headers=headers,
            )

        if resp.status_code == 404:
            return {"value": entity_value, "found": False}
        if resp.status_code == 403:
            logger.warning("crowdstrike_forbidden", entity_value=entity_value)
            return {}
        if resp.status_code == 429:
            logger.warning("crowdstrike_rate_limited")
            return {}

        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            logger.warning("crowdstrike_api_error", status=exc.response.status_code)
            return {}

        data = resp.json()
        resources = data.get("resources") or []
        if not resources:
            return {"value": entity_value, "found": False}

        first = resources[0]
        return {
            "value": entity_value,
            "found": True,
            "indicator_type": first.get("type"),
            "threat_types": first.get("threat_types", []),
            "kill_chains": first.get("kill_chains", []),
            "malware_families": first.get("malware_families", []),
            "actors": first.get("actors", []),
            "labels": [lbl.get("name") for lbl in first.get("labels", []) if lbl.get("name")],
            "confidence": first.get("confidence"),
            "severity": first.get("severity"),
            "last_updated": first.get("last_updated"),
            "published_date": first.get("published_date"),
        }

    async def health_check(self) -> bool:
        cid, csec, _ = self._creds()
        return bool(cid and csec)


def _kind_to_cs_type(entity_kind: str, entity_value: str) -> str:
    """Map our entity kind to a CrowdStrike indicator type string."""
    mapping = {
        "ip": "ip_address",
        "ip_address": "ip_address",
        "domain": "domain",
        "url": "url",
        "md5": "hash_md5",
        "sha256": "hash_sha256",
    }
    if entity_kind in mapping:
        return mapping[entity_kind]
    # Heuristic for generic "hash" kind
    if entity_kind == "hash":
        if len(entity_value) == 32:
            return "hash_md5"
        if len(entity_value) == 64:
            return "hash_sha256"
    return "domain"
