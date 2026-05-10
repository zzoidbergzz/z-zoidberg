"""GET /api/v1/capabilities — live machine-readable service inventory."""

from __future__ import annotations

import subprocess
from typing import Any

from fastapi import APIRouter, Request

router = APIRouter(prefix="/capabilities", tags=["capabilities"])


def _git_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


@router.get("", summary="Live service capability inventory")
async def get_capabilities(request: Request) -> dict[str, Any]:
    """Return what this service can do right now — honest about stubs."""
    import app.mcp  # noqa: F401 — trigger tool registration side-effects
    from app.config import settings
    from app.enrichment.registry import list_providers
    from app.mcp.registry import list_tools

    registered = list_providers()
    configured = [p for p in registered if _provider_has_creds(p, settings)]
    missing_providers = [p for p in ["ipinfo", "greynoise", "crowdstrike"] if p not in registered]

    routes = sorted(
        set(route.path for route in request.app.routes if hasattr(route, "path") and route.path.startswith("/api/"))
    )

    mcp_tools = [t.name for t in list_tools()]

    return {
        "version": _git_sha(),
        "endpoints": routes,
        "mcp_tools": mcp_tools,
        "providers": {
            "registered": registered,
            "configured": configured,
            "missing": missing_providers,
        },
        "feature_flags": {
            "ingest_worker_pipeline": True,
            "fts_search": True,
            "graphql_resolvers": True,
            "enrich_entity_mcp_tool": True,
            "rate_limiting": settings.RATE_LIMIT_ENABLED,
            "search_use_mv": getattr(settings, "SEARCH_USE_MV", False),
            "graph_cte_pathfinding": True,
            "pgvector_semantic_search": True,
            "byok_enrichment": True,
            "data_retention": True,
        },
        "new_endpoints": {
            "profiles": "GET /api/v1/entities/{id}/profile",
            "cve_detail": "GET /api/v1/cve/{cve_id}",
            "timeline": "GET /api/v1/entities/{id}/timeline",
            "provenance": "GET /api/v1/entities/{id}/provenance",
            "breaches": "GET /api/v1/breaches",
            "graph_path": "GET /api/v1/graph/path",
            "graph_stats": "GET /api/v1/graph/stats",
            "semantic_search": "POST /api/v1/search/semantic",
            "data_freshness": "GET /api/v1/health/freshness",
            "slow_queries": "GET /api/v1/admin/slow-queries",
        },
        "stale_paths": [
            "POST /api/v1/ingest/  (queues job; pipeline runs in worker — verify with fixture URL)",
            "POST /api/v1/mcp/call enrich_entity  (works; returns empty if no providers configured)",
        ],
    }


def _provider_has_creds(provider: str, settings) -> bool:
    cred_map = {
        "virustotal": bool(settings.VIRUSTOTAL_API_KEY),
        "shodan": bool(settings.SHODAN_API_KEY),
        "ipinfo": bool(settings.IPINFO_TOKEN),
        "greynoise": bool(settings.GREYNOISE_API_KEY),
        "crowdstrike": bool(settings.CROWDSTRIKE_CLIENT_ID and settings.CROWDSTRIKE_CLIENT_SECRET),
        "opencti": bool(settings.OPENCTI_URL and settings.OPENCTI_TOKEN),
        "misp": bool(settings.MISP_URL and settings.MISP_KEY),
        "nvd": True,  # NVD works without key (rate limited)
        "mitre_attack": True,  # Local data
    }
    return cred_map.get(provider, False)
