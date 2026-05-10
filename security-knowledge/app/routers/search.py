from typing import Optional
import httpx
from fastapi import APIRouter, Depends, Query
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.config import settings
from app.database import get_db
from app.auth.dependencies import require_read
from app.lookup.normalizer import looks_defanged, normalize_indicator
from app.services.search import corpus_search, full_text_search
from app.services.web_search import searxng_search
from app.embeddings.generator import generate_embedding

router = APIRouter(prefix="/search", tags=["search"])


class SearchResult(BaseModel):
    kind: str
    id: str
    name: str
    score: float = 1.0
    description: Optional[str] = None
    tags: list[str] = []
    confidence: Optional[str] = None
    cvss: Optional[str] = None
    severity: Optional[str] = None
    nvd_link: Optional[str] = None
    mitre_link: Optional[str] = None
    detail_url: Optional[str] = None


def _web_to_search_result(item: dict) -> SearchResult:
    url = str(item.get("url") or "")
    title = str(item.get("title") or url or "Web result")
    content = str(item.get("content") or "")
    score = float(item.get("score") or 0.01)
    rid = url or f"web:{abs(hash((title, content)))}"
    return SearchResult(
        kind="web_result",
        id=rid,
        name=title,
        score=score,
        description=content,
        tags=["web"],
        confidence=None,
        cvss=None,
        severity=None,
        nvd_link=None,
        mitre_link=None,
        detail_url=url or None,
    )


def _tenant_id(auth) -> str:
    if isinstance(auth, dict):
        return str(auth["tenant_id"])
    return str(auth.tenant_id)


@router.get("/", response_model=list[SearchResult])
async def search(
    q: str = Query(..., min_length=2),
    limit: int = Query(20, le=100),
    corpus: Optional[str] = Query(None, description="Filter to corpus: cve, gcve, exploitdb"),
    mode: Optional[str] = Query(None, description="Search mode: 'hybrid' enables semantic+FTS fusion"),
    web_fallback: bool = Query(True, description="Use SearXNG web fallback when DB results are sparse"),
    web_only: bool = Query(False, description="Bypass DB and search only SearXNG web results"),
    web_categories: str = Query("general", description="SearXNG categories for fallback"),
    db: AsyncSession = Depends(get_db),
    auth = Depends(require_read),
):
    if web_only:
        try:
            web = await searxng_search(q, categories=web_categories, limit=limit)
        except (httpx.HTTPError, ValueError):
            web = []
        return [_web_to_search_result(item) for item in web][:limit]

    if corpus:
        results = await corpus_search(db, _tenant_id(auth), q, corpus=corpus, limit=limit)
    elif mode == "hybrid" and settings.SEARCH_USE_SEMANTIC:
        results = await _hybrid_search(db, _tenant_id(auth), q, limit)
    else:
        results = await full_text_search(db, _tenant_id(auth), q, limit)

        # Defanged-input fallback: if the query looks defanged (8[.]8[.]8[.]8,
        # hxxps://, user[at]example, etc.), also search the refanged form and
        # merge results so analysts can paste straight from threat reports.
        if looks_defanged(q):
            normed = normalize_indicator(q)
            if normed and normed != q and len(normed) >= 2:
                seen_ids = {(r.get("kind"), r.get("id")) for r in results}
                extra = await full_text_search(db, _tenant_id(auth), normed, limit)
                for r in extra:
                    key = (r.get("kind"), r.get("id"))
                    if key not in seen_ids:
                        seen_ids.add(key)
                        results.append(r)
                results = results[:limit]
    out = [SearchResult(**r) for r in results]

    if (
        not corpus
        and web_fallback
        and settings.SEARCH_WEB_FALLBACK_ENABLED
        and len(out) < settings.SEARCH_WEB_FALLBACK_MIN_DB_RESULTS
    ):
        missing = min(limit - len(out), max(settings.SEARCH_WEB_FALLBACK_MIN_DB_RESULTS - len(out), 0))
        if missing > 0:
            try:
                web = await searxng_search(q, categories=web_categories, limit=missing)
            except (httpx.HTTPError, ValueError):
                web = []

            seen_ids = {r.id for r in out}
            for item in web:
                sr = _web_to_search_result(item)
                if sr.id in seen_ids:
                    continue
                out.append(sr)
                seen_ids.add(sr.id)
                if len(out) >= limit:
                    break

    return out[:limit]


# ---------------------------------------------------------------------------
# Semantic search endpoint (pgvector)
# ---------------------------------------------------------------------------

_SEMANTIC_SQL = """
SELECT
    e.id::text,
    e.kind,
    e.canonical_name,
    1 - (e.embedding <=> :q_emb) AS score
FROM entities e
WHERE e.tenant_id = :tid
  AND e.embedding IS NOT NULL
  AND (:kind IS NULL OR e.kind = :kind)
ORDER BY e.embedding <=> :q_emb
LIMIT :lim
"""


class SemanticSearchRequest(BaseModel):
    query: str
    limit: int = 10
    kind: Optional[str] = None


@router.post("/semantic", response_model=list[SearchResult])
async def semantic_search(
    req: SemanticSearchRequest,
    db: AsyncSession = Depends(get_db),
    auth = Depends(require_read),
):
    """Semantic (vector cosine) search over entities with pgvector embeddings.

    Requires ``SEARCH_USE_SEMANTIC=true`` and the pgvector extension to be
    installed (migration 0037).  Returns 503 if semantic search is disabled.
    """
    from fastapi import HTTPException
    if not settings.SEARCH_USE_SEMANTIC:
        raise HTTPException(status_code=503, detail="Semantic search not enabled")

    q_emb = await generate_embedding(req.query)
    if not q_emb or all(v == 0.0 for v in q_emb):
        raise HTTPException(status_code=503, detail="Embedding provider unavailable")

    rows = await db.execute(
        text(_SEMANTIC_SQL),
        {
            "q_emb": str(q_emb),
            "tid": _tenant_id(auth),
            "kind": req.kind,
            "lim": min(req.limit, 100),
        },
    )
    return [
        SearchResult(kind=r.kind, id=r.id, name=r.canonical_name, score=float(r.score))
        for r in rows.fetchall()
    ]


async def _hybrid_search(
    db: AsyncSession,
    tenant_id: str,
    query: str,
    limit: int,
) -> list[dict]:
    """Combine FTS and semantic cosine scores (0.4 FTS + 0.6 semantic)."""
    fts_results = await full_text_search(db, tenant_id, query, limit * 2)
    fts_map: dict[str, float] = {r["id"]: float(r.get("score", 0.5)) for r in fts_results}

    q_emb = await generate_embedding(query)
    sem_map: dict[str, float] = {}
    if q_emb and not all(v == 0.0 for v in q_emb):
        rows = await db.execute(
            text(_SEMANTIC_SQL),
            {"q_emb": str(q_emb), "tid": tenant_id, "kind": None, "lim": limit * 2},
        )
        for r in rows.fetchall():
            sem_map[r.id] = float(r.score)

    # Normalise FTS scores to [0,1]
    max_fts = max(fts_map.values(), default=1.0) or 1.0
    fts_norm = {k: v / max_fts for k, v in fts_map.items()}

    all_ids = set(fts_norm) | set(sem_map)
    scored = []
    fts_lookup = {r["id"]: r for r in fts_results}
    for eid in all_ids:
        fts_s = fts_norm.get(eid, 0.0)
        sem_s = sem_map.get(eid, 0.0)
        combined = 0.4 * fts_s + 0.6 * sem_s
        base = fts_lookup.get(eid, {})
        scored.append({**base, "id": eid, "score": combined})

    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:limit]
