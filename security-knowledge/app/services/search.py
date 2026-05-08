"""Full-text + trigram hybrid search across entities and claims.

Migration 0005 adds a ``search_vector`` tsvector column (GIN-indexed) and a
``canonical_name gin_trgm_ops`` index to ``entities``, and a
``search_vector`` column (GIN-indexed) to ``claims``.

The query ranks results using:
    score = ts_rank_cd(search_vector, query)  -- FTS relevance
          + 0.4 * similarity(<name_col>, :q)  -- trigram fuzzy bonus
and filters on:
    search_vector @@ query  OR  <name_col> % :q
so that both exact semantic hits and near-miss fuzzy matches surface.
"""
from __future__ import annotations

from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

_ENTITY_SQL = text(
    """
    SELECT
        id::text                                                              AS id,
        canonical_name                                                        AS name,
        COALESCE(ts_rank_cd(search_vector, plainto_tsquery('english', :q)), 0)
            + 0.4 * COALESCE(similarity(canonical_name, :q), 0)             AS score
    FROM entities
    WHERE tenant_id = :tenant_id
      AND (
          search_vector @@ plainto_tsquery('english', :q)
          OR canonical_name % :q
      )
    ORDER BY score DESC, updated_at DESC
    LIMIT :lim
    """
)

_CLAIM_SQL = text(
    """
    SELECT
        id::text                                                              AS id,
        claim_type || ': ' || left(value::text, 80)                          AS name,
        COALESCE(ts_rank_cd(search_vector, plainto_tsquery('english', :q)), 0)
            + 0.4 * COALESCE(similarity(claim_type, :q), 0)                 AS score
    FROM claims
    WHERE tenant_id = :tenant_id
      AND (
          search_vector @@ plainto_tsquery('english', :q)
          OR claim_type % :q
      )
    ORDER BY score DESC, updated_at DESC
    LIMIT :lim
    """
)


async def full_text_search(
    db: AsyncSession, tenant_id: str, query: str, limit: int = 20
) -> list[dict[str, Any]]:
    """Return flat list of search results across entities and claims.

    Results are ranked by combined FTS + trigram score (descending) and
    capped at *limit* after merging the two tables.
    """
    params = {"q": query, "tenant_id": tenant_id, "lim": limit}

    entity_rows = await db.execute(_ENTITY_SQL, params)
    claim_rows = await db.execute(_CLAIM_SQL, params)

    results: list[dict[str, Any]] = []

    for row in entity_rows.mappings().all():
        results.append(
            {
                "kind": "entity",
                "id": row["id"],
                "name": row["name"],
                "score": float(row["score"]),
            }
        )

    for row in claim_rows.mappings().all():
        results.append(
            {
                "kind": "claim",
                "id": row["id"],
                "name": row["name"],
                "score": float(row["score"]),
            }
        )

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:limit]
