"""MCP tool: look up an arbitrary IoC and run / return enrichment."""

from __future__ import annotations

import structlog

from app.lookup.classifier import classify_input
from app.mcp.registry import register_tool
from app.routers.lookup import (
    _KIND_MAP,
    _dispatch_enrichment,
    _get_enrichment_results,
    _record_dispatch,
    _should_dispatch,
    _upsert_entity,
)

logger = structlog.get_logger(__name__)


async def _lookup_ioc(args: dict, db, auth) -> dict:
    """Classify an IoC, upsert the entity, dispatch enrichment, return cached
    results. Honors caller BYOK because the dispatch path uses ``user_id``."""
    query = (args.get("query") or "").strip()
    if not query:
        return {"error": "query is required"}
    force = bool(args.get("force_repoll", False))

    classified = classify_input(query)
    if classified["type"] == "empty":
        return {"error": "empty_or_unclassifiable", "query": query}

    kind = _KIND_MAP.get(classified["type"], "indicator")
    canonical = classified["value"]
    tenant_id = str(auth.tenant_id)
    user_id = str(auth.user_id) if auth.user_id else None

    entity = await _upsert_entity(db, tenant_id, kind, canonical)
    await db.commit()

    dispatched = False
    if await _should_dispatch(db, str(entity.id), tenant_id, force):
        await _record_dispatch(db, str(entity.id), tenant_id, force)
        await db.commit()
        try:
            await _dispatch_enrichment(entity, tenant_id, force, db, user_id)
            dispatched = True
        except Exception as exc:  # noqa: BLE001
            logger.warning("mcp_lookup_dispatch_error", error=str(exc), entity=canonical)

    enrichments = await _get_enrichment_results(db, tenant_id, kind, canonical)
    return {
        "entity_id": str(entity.id),
        "kind": kind,
        "canonical": canonical,
        "classified_as": classified["type"],
        "enrichment_dispatched": dispatched,
        "enrichments": enrichments,
        "count": len(enrichments),
    }


register_tool(
    name="lookup_ioc",
    fn=_lookup_ioc,
    schema={
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {
                "type": "string",
                "description": "An IoC to look up (IP, CIDR, domain, URL, email, hash sha256/sha1/md5, ASN, CVE).",
            },
            "force_repoll": {
                "type": "boolean",
                "description": "Re-run enrichment even if cached results exist (default false; subject to debounce).",
            },
        },
    },
    description="Classify and look up any IoC. Auto-dispatches enrichment (urlscan/VT/etc) using your BYOK keys when registered.",
    scope="read",
)
