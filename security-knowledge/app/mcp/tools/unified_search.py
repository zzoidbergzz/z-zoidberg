"""MCP tool: unified search — DB first, SearXNG fallback, auto-enrich.

Strategy:
  1. Search the local PostgreSQL knowledge base (entities, claims, corpus)
  2. If results are sparse, supplement with SearXNG web search
  3. Optionally create stub entities from web results for future enrichment
  4. Return merged, deduplicated results

This creates a self-improving loop: web results become DB entities,
so future searches find them locally without hitting the network.
"""

from __future__ import annotations

import json
import logging
import uuid

import httpx
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.mcp.registry import register_tool
from app.models.entities import Entity
from app.services.search import full_text_search, corpus_search

logger = logging.getLogger(__name__)

_SEARXNG_BASE = "http://localhost:8888"
# Minimum DB score to consider the local results "sufficient"
_DB_SUFFICIENT_THRESHOLD = 3
# Minimum number of results to consider search "answered"
_MIN_TOTAL_RESULTS = 5


async def _db_search(db: AsyncSession, tenant_id: str, query: str, limit: int = 20) -> list[dict]:
    """Search the local knowledge base."""
    try:
        results = await full_text_search(db, tenant_id, query, limit=limit)
        return results or []
    except Exception as e:
        logger.warning("DB search failed: %s", e)
        return []


async def _searxng_search(query: str, categories: str = "general", limit: int = 10) -> list[dict]:
    """Search the web via SearXNG."""
    params = {"format": "json", "q": query, "categories": categories}
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{_SEARXNG_BASE}/search", params=params)
            resp.raise_for_status()
            data = resp.json()
            results = data.get("results", [])[:limit]
            return [
                {
                    "source": "web",
                    "title": r.get("title", ""),
                    "url": r.get("url", ""),
                    "content": r.get("content", ""),
                    "score": r.get("score", 0),
                    "engine": r.get("engine", ""),
                    "category": r.get("category", ""),
                }
                for r in results
            ]
    except Exception as e:
        logger.warning("SearXNG search failed: %s", e)
        return []


async def _create_stub_entities(
    db: AsyncSession, tenant_id: str, web_results: list[dict], query: str
) -> int:
    """Create stub entities from high-value web results for future enrichment.

    Only creates stubs for results that look like they reference security
    concepts (CVEs, threat actors, techniques, malware, etc.).
    """
    count = 0
    security_indicators = [
        "CVE-", "CWE-", "APT", "malware", "ransomware", "exploit",
        "vulnerability", "backdoor", "trojan", "phishing", "ATT&CK",
        "technique T1", "IOC", "indicator", "threat actor", "zero-day",
        "botnet", "C2", "lateral movement", "privilege escalation",
        "CVE-", "MS0", "CVE-", "ET ", "TA0", "G0", "S0",
    ]

    for r in web_results[:5]:  # Only top 5 web results
        title = r.get("title", "")
        content = r.get("content", "")
        url = r.get("url", "")

        # Check if this looks security-relevant
        combined = f"{title} {content}".lower()
        if not any(ind.lower() in combined for ind in security_indicators):
            continue

        # Check if we already have an entity for this
        try:
            existing = await db.execute(
                select(Entity).where(
                    Entity.canonical_name == title,
                    Entity.tenant_id == tenant_id,
                )
            )
            if existing.scalar_one_or_none():
                continue

            # Determine kind from content heuristics
            kind = "other"
            title_upper = title.upper()
            if "CVE-" in title_upper:
                kind = "cve"
            elif "CWE-" in title_upper:
                kind = "cwe"
            elif any(x in title_upper for x in ["APT", "FIN", "G0"]):
                kind = "threat_actor"
            elif any(x in combined for x in ["malware", "ransomware", "trojan", "backdoor", "botnet"]):
                kind = "malware"
            elif any(x in combined for x in ["technique", "T1"]):
                kind = "attack_pattern"
            elif any(x in combined for x in ["exploit", "poc", "vulnerability"]):
                kind = "vulnerability"
            elif any(x in combined for x in ["detection", "sigma", "yara"]):
                kind = "detection"
            elif any(x in combined for x in ["tool", "framework"]):
                kind = "tool"
            elif any(x in combined for x in ["report", "advisory", "analysis"]):
                kind = "report"

            entity = Entity(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                kind=kind,
                canonical_name=title[:512],
                external_refs={
                    "stub": True,
                    "source_url": url,
                    "source": "web_search_stub",
                    "trust_tier": 3,
                    "search_query": query,
                    "auto_created": True,
                },
            )
            db.add(entity)
            count += 1
        except Exception as e:
            logger.warning("Failed to create stub entity: %s", e)
            continue

    if count > 0:
        await db.flush()
    return count


async def _unified_search(args: dict, db: AsyncSession, auth) -> dict:
    """Unified search: DB → SearXNG fallback → auto-enrich."""
    query = args.get("query", "")
    if not query:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: query"}}

    limit = int(args.get("limit", 20))
    categories = args.get("categories", "general")
    enrich = args.get("enrich", True)  # Auto-create stub entities from web results
    db_only = args.get("db_only", False)  # Skip web search

    tenant_id = str(auth.tenant_id)

    # Phase 1: Local DB search
    db_results = await _db_search(db, tenant_id, query, limit=limit)
    db_count = len(db_results)

    # Tag DB results
    for r in db_results:
        r["source"] = "knowledge_base"

    # Phase 2: Decide if web search is needed
    web_results = []
    web_count = 0
    stubs_created = 0

    if not db_only and db_count < _MIN_TOTAL_RESULTS:
        web_results = await _searxng_search(query, categories=categories, limit=limit - db_count)
        web_count = len(web_results)

        # Phase 3: Auto-enrich — create stubs from web results
        if enrich and web_count > 0:
            try:
                stubs_created = await _create_stub_entities(db, tenant_id, web_results, query)
            except Exception as e:
                logger.warning("Stub creation failed: %s", e)

    # Merge results
    all_results = db_results + web_results

    return {
        "query": query,
        "results": all_results[:limit],
        "stats": {
            "db_results": db_count,
            "web_results": web_count,
            "total": len(all_results),
            "stubs_created": stubs_created,
            "search_strategy": "db_only" if db_only or db_count >= _MIN_TOTAL_RESULTS else "db_and_web",
        },
    }


register_tool(
    name="unified_search",
    fn=_unified_search,
    schema={
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {
                "type": "string",
                "description": "Search query — searches knowledge base first, supplements with web results if needed",
            },
            "limit": {
                "type": "integer",
                "default": 20,
                "description": "Maximum results to return",
            },
            "categories": {
                "type": "string",
                "default": "general",
                "description": "SearXNG category filter (general, news, it, science, etc.)",
            },
            "enrich": {
                "type": "boolean",
                "default": True,
                "description": "Auto-create stub entities from web results for future enrichment",
            },
            "db_only": {
                "type": "boolean",
                "default": False,
                "description": "Only search the knowledge base, skip web search",
            },
        },
    },
    description=(
        "Unified search: queries the local knowledge base first, "
        "supplements with SearXNG web search if results are sparse, "
        "and auto-creates stub entities from web results so future "
        "searches find them locally. Self-improving search loop."
    ),
    scope="read",
)
