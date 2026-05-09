from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.database import get_db
from app.auth.dependencies import require_read
from app.lookup.normalizer import looks_defanged, normalize_indicator
from app.services.search import corpus_search, full_text_search

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


@router.get("/", response_model=list[SearchResult])
async def search(
    q: str = Query(..., min_length=2),
    limit: int = Query(20, le=100),
    corpus: Optional[str] = Query(None, description="Filter to corpus: cve, gcve, exploitdb"),
    db: AsyncSession = Depends(get_db),
    auth = Depends(require_read),
):
    if corpus:
        results = await corpus_search(db, str(auth.tenant_id), q, corpus=corpus, limit=limit)
    else:
        results = await full_text_search(db, str(auth.tenant_id), q, limit)

        # Defanged-input fallback: if the query looks defanged (8[.]8[.]8[.]8,
        # hxxps://, user[at]example, etc.), also search the refanged form and
        # merge results so analysts can paste straight from threat reports.
        if looks_defanged(q):
            normed = normalize_indicator(q)
            if normed and normed != q and len(normed) >= 2:
                seen_ids = {(r.get("kind"), r.get("id")) for r in results}
                extra = await full_text_search(db, str(auth.tenant_id), normed, limit)
                for r in extra:
                    key = (r.get("kind"), r.get("id"))
                    if key not in seen_ids:
                        seen_ids.add(key)
                        results.append(r)
                results = results[:limit]
    return [SearchResult(**r) for r in results]
