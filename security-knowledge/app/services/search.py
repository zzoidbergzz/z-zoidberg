"""Full-text + trigram hybrid search across entities and claims.

Migration 0005 adds a ``search_vector`` tsvector column (GIN-indexed) and a
``canonical_name gin_trgm_ops`` index to ``entities``, and a
``search_vector`` column (GIN-indexed) to ``claims``.

Results are enriched with claim descriptions (assertion text), tags,
CVSS scores and external reference links so the search UI can render
rich cards without needing a separate detail-page round-trip.
"""
from __future__ import annotations

import re
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

# Entity search: LEFT JOIN the most-relevant claim for a description snippet.
_ENTITY_SQL = text(
    """
    SELECT
        e.id::text                                                                AS id,
        e.canonical_name                                                          AS name,
        e.kind,
        e.external_refs,
        e.mitre_attack_id,
        COALESCE(ts_rank_cd(e.search_vector, plainto_tsquery('english', :q)), 0)
            + 0.4 * COALESCE(similarity(e.canonical_name, :q), 0)               AS score,
        (
            SELECT c.value->>'assertion'
            FROM claims c
            WHERE c.entity_id = e.id
              AND c.claim_type IN (
                  'vulnerability_detail', 'technique_detail', 'actor_profile',
                  'product_detail', 'framework_detail', 'tool_capability',
                  'detection_detail'
              )
            ORDER BY c.created_at DESC
            LIMIT 1
        ) AS description,
        (
            SELECT c.value->'tags'
            FROM claims c
            WHERE c.entity_id = e.id
            ORDER BY c.created_at DESC
            LIMIT 1
        ) AS tags,
        (
            SELECT c.value->>'confidence'
            FROM claims c
            WHERE c.entity_id = e.id
            ORDER BY c.created_at DESC
            LIMIT 1
        ) AS confidence
    FROM entities e
    WHERE e.tenant_id = :tenant_id
      AND (
          e.search_vector @@ plainto_tsquery('english', :q)
          OR e.canonical_name % :q
      )
    ORDER BY score DESC, e.updated_at DESC
    LIMIT :lim
    """
)

# Claim search: JOIN the parent entity to get its external_refs + kind so we
# can still surface CVSS / MITRE links even when the entity is reached via
# a claim rather than its canonical_name.
_CLAIM_SQL = text(
    """
    SELECT
        COALESCE(e.id::text, c.id::text)                                          AS id,
        c.id::text                                                                 AS claim_id,
        c.entity_id::text                                                         AS entity_id,
        COALESCE(e.kind, c.claim_type)                                            AS kind,
        COALESCE(e.canonical_name, c.value->>'title', c.claim_type)              AS name,
        e.external_refs,
        e.mitre_attack_id,
        c.value->>'assertion'                                                     AS description,
        c.value->'tags'                                                           AS tags,
        c.value->>'confidence'                                                    AS confidence,
        COALESCE(ts_rank_cd(c.search_vector, plainto_tsquery('english', :q)), 0)
            + 0.4 * COALESCE(similarity(c.claim_type, :q), 0)                   AS score
    FROM claims c
    LEFT JOIN entities e ON e.id = c.entity_id
    WHERE c.tenant_id = :tenant_id
      AND (
          c.search_vector @@ plainto_tsquery('english', :q)
          OR c.claim_type % :q
      )
    ORDER BY score DESC, c.updated_at DESC
    LIMIT :lim
    """
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_MITRE_RE = re.compile(r"^[TGSC]\d{4}(\.\d{3})?$")


def _nvd_link(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"


def _mitre_link(attack_id: str) -> str:
    base = "https://attack.mitre.org"
    aid = attack_id.upper()
    if "." in aid:
        parent, sub = aid.split(".", 1)
        return f"{base}/techniques/{parent}/{sub}/"
    if aid.startswith("T"):
        return f"{base}/techniques/{aid}/"
    if aid.startswith("G"):
        return f"{base}/groups/{aid}/"
    if aid.startswith("S"):
        return f"{base}/software/{aid}/"
    return f"{base}/"


def _severity_from_cvss(cvss_str: str | None) -> str:
    """Map CVSS numeric score string to severity label."""
    if not cvss_str:
        return ""
    try:
        score = float(cvss_str)
    except ValueError:
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _build_entity_result(row: Any) -> dict[str, Any]:
    ext = row["external_refs"] or {}
    kind: str = row["kind"] or "entity"
    name: str = row["name"]
    mitre_id: str | None = row["mitre_attack_id"] or ext.get("attack_id") or ext.get("mitre_id")

    result: dict[str, Any] = {
        "kind": kind,
        "id": row["id"],
        "name": name,
        "score": float(row["score"]),
        "description": row["description"] or "",
        "tags": list(row["tags"]) if row["tags"] else [],
        "confidence": row["confidence"] or "",
        "cvss": None,
        "severity": "",
        "detail_url": None,
        "nvd_link": None,
        "mitre_link": None,
    }

    # CVE-specific enrichment
    cve_id: str | None = ext.get("cve") or (name if _CVE_RE.match(name) else None)
    if cve_id:
        cvss_str = ext.get("cvss") or ext.get("cvss_score")
        result["cvss"] = cvss_str
        result["severity"] = _severity_from_cvss(cvss_str)
        result["nvd_link"] = _nvd_link(cve_id)

    # MITRE technique/group/software enrichment
    if mitre_id and _MITRE_RE.match(mitre_id):
        result["mitre_link"] = _mitre_link(mitre_id)
    elif _MITRE_RE.match(name):
        result["mitre_link"] = _mitre_link(name)

    return result


async def full_text_search(
    db: AsyncSession, tenant_id: str, query: str, limit: int = 20
) -> list[dict[str, Any]]:
    """Return enriched search results across entities and claims.

    Each result includes description (from claim assertion), CVSS/severity
    for CVEs, NVD/MITRE links, and tag lists so the UI can render rich cards.
    Entity-linked claims are deduplicated — if an entity matches via both the
    entity row and an associated claim, only the entity result is kept.
    """
    params = {"q": query, "tenant_id": tenant_id, "lim": limit}

    entity_rows = await db.execute(_ENTITY_SQL, params)
    claim_rows = await db.execute(_CLAIM_SQL, params)

    results: list[dict[str, Any]] = []
    seen_entity_ids: set[str] = set()

    for row in entity_rows.mappings().all():
        r = _build_entity_result(row)
        results.append(r)
        seen_entity_ids.add(row["id"])

    for row in claim_rows.mappings().all():
        eid = row["entity_id"]
        result_id = row["id"]  # already COALESCED to entity id if available
        # Skip if we already have the parent entity in results (avoid duplicates)
        if eid and eid in seen_entity_ids:
            continue
        if eid and eid not in seen_entity_ids:
            seen_entity_ids.add(eid)

        ext = row["external_refs"] or {}
        kind: str = row["kind"] or "claim"
        name: str = row["name"] or kind
        mitre_id: str | None = row["mitre_attack_id"] or ext.get("attack_id") or ext.get("mitre_id")

        r: dict[str, Any] = {
            "kind": kind,
            "id": result_id,
            "name": name,
            "score": float(row["score"]),
            "description": row["description"] or "",
            "tags": list(row["tags"]) if row["tags"] else [],
            "confidence": row["confidence"] or "",
            "cvss": None,
            "severity": "",
            "detail_url": f"/entities/{eid}" if eid else None,
            "nvd_link": None,
            "mitre_link": None,
        }

        # Enrich with entity data if we have it
        cve_id: str | None = ext.get("cve") or (name if _CVE_RE.match(name) else None)
        if cve_id:
            cvss_str = ext.get("cvss") or ext.get("cvss_score")
            r["cvss"] = cvss_str
            r["severity"] = _severity_from_cvss(cvss_str)
            r["nvd_link"] = _nvd_link(cve_id)

        if mitre_id and _MITRE_RE.match(mitre_id):
            r["mitre_link"] = _mitre_link(mitre_id)
        elif _MITRE_RE.match(name):
            r["mitre_link"] = _mitre_link(name)

        results.append(r)

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:limit]
