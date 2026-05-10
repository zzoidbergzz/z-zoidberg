"""EUVD-specific search endpoint with rich filter support.

Searches local corpus_documents (corpus='euvd') for fast querying.
Returns full metadata from raw_json for pivot richness.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select, func, or_, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_auth, AuthContext
from app.database import get_db
from app.models.corpus import CorpusDocument

router = APIRouter(prefix="/euvd", tags=["euvd"])


class EUVDSearchHit(BaseModel):
    id: str
    euvd_id: str
    title: str | None
    summary: str | None
    published_at: str | None
    modified_at: str | None
    cvss_score: float | None
    cvss_version: str | None
    cvss_vector: str | None
    epss: float | None
    aliases: list[str]
    vendors: list[str]
    products: list[str]
    references: list[str]
    assigner: str | None
    raw_json: dict | None = None

    model_config = {"from_attributes": True}


class EUVDSearchResponse(BaseModel):
    total: int
    offset: int
    limit: int
    results: list[EUVDSearchHit]


def _extract_from_raw(raw: dict | None) -> dict:
    """Extract EUVD-specific fields from raw_json."""
    if not raw:
        return {}
    return {
        "cvss_score": raw.get("baseScore"),
        "cvss_version": raw.get("baseScoreVersion"),
        "cvss_vector": raw.get("baseScoreVector"),
        "epss": raw.get("epss"),
        "aliases": [a.strip() for a in raw.get("aliases", "").split("\n") if a.strip()] if raw.get("aliases") else [],
        "vendors": [v.get("vendor", {}).get("name", "") for v in raw.get("enisaIdVendor", []) if v.get("vendor", {}).get("name")],
        "products": [p.get("product", {}).get("name", "") for p in raw.get("enisaIdProduct", []) if p.get("product", {}).get("name")],
        "references": [r.strip() for r in raw.get("references", "").split("\n") if r.strip()] if raw.get("references") else [],
        "assigner": raw.get("assigner"),
    }


@router.get("/search", response_model=EUVDSearchResponse)
async def search_euvd(
    q: Optional[str] = Query(None, description="Full-text search query"),
    vendor: Optional[str] = Query(None, description="Filter by vendor name"),
    product: Optional[str] = Query(None, description="Filter by product name"),
    min_score: Optional[float] = Query(None, ge=0, le=10, description="Minimum CVSS score"),
    max_score: Optional[float] = Query(None, ge=0, le=10, description="Maximum CVSS score"),
    min_epss: Optional[float] = Query(None, ge=0, le=1, description="Minimum EPSS score"),
    exploited: Optional[bool] = Query(None, description="Only exploited vulnerabilities"),
    assigner: Optional[str] = Query(None, description="Filter by CNA assigner"),
    limit: int = Query(20, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    """Search EUVD vulnerability data with rich filters."""
    # Build base query
    stmt = select(CorpusDocument).where(CorpusDocument.corpus == "euvd")
    count_stmt = select(func.count()).select_from(CorpusDocument).where(CorpusDocument.corpus == "euvd")

    # Full-text search
    if q:
        ts_query = f"websearch_to_tsquery('english', :q)"
        stmt = stmt.filter(text(f"search_vector @@ {ts_query}"))
        count_stmt = count_stmt.filter(text(f"search_vector @@ {ts_query}"))

    # JSONB filters on raw_json
    if vendor:
        stmt = stmt.filter(text("raw_json::text ILIKE :vendor"))
        count_stmt = count_stmt.filter(text("raw_json::text ILIKE :vendor"))
    if product:
        stmt = stmt.filter(text("raw_json::text ILIKE :product"))
        count_stmt = count_stmt.filter(text("raw_json::text ILIKE :product"))
    if assigner:
        stmt = stmt.filter(text("raw_json->>'assigner' ILIKE :assigner"))
        count_stmt = count_stmt.filter(text("raw_json->>'assigner' ILIKE :assigner"))
    if min_score is not None:
        stmt = stmt.filter(text("COALESCE((raw_json->>'baseScore')::float, 0) >= :min_score"))
        count_stmt = count_stmt.filter(text("COALESCE((raw_json->>'baseScore')::float, 0) >= :min_score"))
    if max_score is not None:
        stmt = stmt.filter(text("COALESCE((raw_json->>'baseScore')::float, 0) <= :max_score"))
        count_stmt = count_stmt.filter(text("COALESCE((raw_json->>'baseScore')::float, 0) <= :max_score"))
    if min_epss is not None:
        stmt = stmt.filter(text("COALESCE((raw_json->>'epss')::float, 0) >= :min_epss"))
        count_stmt = count_stmt.filter(text("COALESCE((raw_json->>'epss')::float, 0) >= :min_epss"))
    if exploited:
        stmt = stmt.filter(text("raw_json::text ILIKE '%exploited%'"))
        count_stmt = count_stmt.filter(text("raw_json::text ILIKE '%exploited%'"))

    # Get total count
    params = {}
    if q:
        params["q"] = q
    if vendor:
        params["vendor"] = f'%{vendor}%'
    if product:
        params["product"] = f'%{product}%'
    if assigner:
        params["assigner"] = f'%{assigner}%'
    if min_score is not None:
        params["min_score"] = min_score
    if max_score is not None:
        params["max_score"] = max_score
    if min_epss is not None:
        params["min_epss"] = min_epss

    total_result = await db.execute(count_stmt, params)
    total = total_result.scalar() or 0

    # Fetch results
    stmt = stmt.order_by(CorpusDocument.published_at.desc()).offset(offset).limit(limit)
    result = await db.execute(stmt, params)
    docs = result.scalars().all()

    hits = []
    for doc in docs:
        extra = _extract_from_raw(doc.raw_json)
        hits.append(EUVDSearchHit(
            id=str(doc.id),
            euvd_id=doc.external_id,
            title=doc.title,
            summary=doc.summary,
            published_at=doc.published_at.isoformat() if doc.published_at else None,
            modified_at=doc.modified_at.isoformat() if doc.modified_at else None,
            cvss_score=extra.get("cvss_score"),
            cvss_version=extra.get("cvss_version"),
            cvss_vector=extra.get("cvss_vector"),
            epss=extra.get("epss"),
            aliases=extra.get("aliases", []),
            vendors=extra.get("vendors", []),
            products=extra.get("products", []),
            references=extra.get("references", []),
            assigner=extra.get("assigner"),
            raw_json=doc.raw_json,
        ))

    return EUVDSearchResponse(total=total, offset=offset, limit=limit, results=hits)
