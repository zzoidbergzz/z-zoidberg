"""Ticker router — feed ticker data for the UI dashboard."""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_read, AuthContext
from app.database import get_db
from app.models.claims import Claim
from app.models.entities import Entity
from app.models.flags import FlaggedItem
from app.models.documents import ParsedDocument

router = APIRouter(prefix="/ticker", tags=["ticker"])


class TickerItem(BaseModel):
    id: str
    title: str
    meta: str
    source: str
    url: str | None = None


class FlaggedItemOut(BaseModel):
    id: uuid.UUID
    source_type: str
    title: str
    body: str | None
    url: str | None
    flagged_at: datetime
    acked_by: str | None
    acked_at: datetime | None

    model_config = {"from_attributes": True}


class FlagBody(BaseModel):
    source_type: str  # trend, news, breach
    title: str
    body: str | None = None
    url: str | None = None
    external_id: str | None = None  # dedup key


class AckBody(BaseModel):
    acked_by: str = "anonymous"


# ── Ticker endpoints ──────────────────────────────────────────────────────────

@router.get("/trends", response_model=list[TickerItem])
async def ticker_trends(
    limit: int = Query(10, le=50),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Locally observed trends: recent entity clusters with high claim activity."""
    since = datetime.now(UTC) - timedelta(days=7)
    stmt = (
        select(
            Entity.canonical_name,
            Entity.kind,
            func.count(Claim.id).label("claim_count"),
            func.max(Claim.created_at).label("latest"),
        )
        .join(Claim, Claim.entity_id == Entity.id)
        .where(Claim.tenant_id == auth.tenant_id, Claim.created_at >= since)
        .group_by(Entity.id, Entity.canonical_name, Entity.kind)
        .order_by(func.count(Claim.id).desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    items = []
    for name, kind, count, latest in rows:
        ago = _human_ago(latest)
        items.append(TickerItem(
            id=f"trend-{kind}-{name[:30]}",
            title=f"{name} — {count} recent claims",
            meta=f"{kind} · {ago}",
            source="trends",
            url=f"/entities?q={name}",
        ))
    return items


@router.get("/news", response_model=list[TickerItem])
async def ticker_news(
    limit: int = Query(10, le=50),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Recent cyber security news from ingested documents."""
    since = datetime.now(UTC) - timedelta(hours=48)
    stmt = (
        select(ParsedDocument)
        .where(
            ParsedDocument.tenant_id == auth.tenant_id,
            ParsedDocument.created_at >= since,
        )
        .order_by(ParsedDocument.created_at.desc())
        .limit(limit)
    )
    docs = (await db.execute(stmt)).scalars().all()
    items = []
    for doc in docs:
        title = (doc.title or doc.url or "Untitled")[:100]
        ago = _human_ago(doc.created_at)
        items.append(TickerItem(
            id=f"news-{doc.id}",
            title=title,
            meta=f"{'feed' if doc.source_id else 'ingest'} · {ago}",
            source="news",
            url=doc.url,
        ))
    return items


@router.get("/breaches", response_model=list[TickerItem])
async def ticker_breaches(
    limit: int = Query(10, le=50),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Recent breach/ransomware claims from entities."""
    since = datetime.now(UTC) - timedelta(days=7)
    breach_kinds = {"actor", "campaign"}
    stmt = (
        select(Entity, func.max(Claim.created_at).label("latest_claim"))
        .join(Claim, Claim.entity_id == Entity.id)
        .where(
            Claim.tenant_id == auth.tenant_id,
            Claim.created_at >= since,
            Entity.kind.in_(breach_kinds),
        )
        .group_by(Entity.id)
        .order_by(func.max(Claim.created_at).desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    items = []
    for entity, latest in rows:
        ago = _human_ago(latest)
        items.append(TickerItem(
            id=f"breach-{entity.id}",
            title=entity.canonical_name,
            meta=f"{entity.kind} · {ago}",
            source="breaches",
            url=f"/entities/{entity.id}",
        ))
    return items


# ── Flag endpoints ─────────────────────────────────────────────────────────────

@router.post("/flag", response_model=FlaggedItemOut, status_code=201)
async def create_flag(
    body: FlagBody,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Flag a ticker item for follow-up."""
    # Dedup by external_id
    if body.external_id:
        existing = await db.execute(
            select(FlaggedItem).where(
                FlaggedItem.tenant_id == auth.tenant_id,
                FlaggedItem.external_id == body.external_id,
            )
        )
        if existing.scalar_one_or_none():
            return existing.scalar_one()

    item = FlaggedItem(
        tenant_id=auth.tenant_id,
        user_id=auth.user_id if hasattr(auth, "user_id") else None,
        source_type=body.source_type,
        title=body.title,
        body=body.body,
        url=body.url,
        external_id=body.external_id,
        flagged_at=datetime.now(UTC),
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return item


@router.get("/flags", response_model=list[FlaggedItemOut])
async def list_flags(
    period: str = Query("today", enum=["today", "yesterday", "week", "lastweek", "30d", "all"]),
    source_type: str | None = None,
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """List flagged items with time-period filtering."""
    since = _period_start(period)
    stmt = select(FlaggedItem).where(
        FlaggedItem.tenant_id == auth.tenant_id,
        FlaggedItem.flagged_at >= since,
    )
    if source_type:
        stmt = stmt.where(FlaggedItem.source_type == source_type)
    stmt = stmt.order_by(FlaggedItem.flagged_at.desc()).limit(limit)
    return (await db.execute(stmt)).scalars().all()


@router.post("/flag/{item_id}/ack", response_model=FlaggedItemOut)
async def ack_flag(
    item_id: uuid.UUID,
    body: AckBody,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """ACK a flagged item as reviewed/completed."""
    item = await db.get(FlaggedItem, item_id)
    if not item or item.tenant_id != auth.tenant_id:
        from fastapi import HTTPException
        raise HTTPException(404, "Flagged item not found")
    item.acked_by = body.acked_by
    item.acked_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(item)
    return item


@router.delete("/flag/{item_id}", status_code=204)
async def delete_flag(
    item_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Remove a flag."""
    item = await db.get(FlaggedItem, item_id)
    if not item or item.tenant_id != auth.tenant_id:
        from fastapi import HTTPException
        raise HTTPException(404, "Flagged item not found")
    await db.delete(item)
    await db.commit()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _human_ago(dt: datetime | None) -> str:
    if not dt:
        return "unknown"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    diff = datetime.now(UTC) - dt
    if diff.total_seconds() < 60:
        return "just now"
    if diff.total_seconds() < 3600:
        return f"{int(diff.total_seconds() / 60)}m ago"
    if diff.total_seconds() < 86400:
        return f"{int(diff.total_seconds() / 3600)}h ago"
    return f"{int(diff.total_seconds() / 86400)}d ago"


def _period_start(period: str) -> datetime:
    now = datetime.now(UTC)
    if period == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "yesterday":
        return (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "week":
        return (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "lastweek":
        return (now - timedelta(days=now.weekday() + 7)).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "30d":
        return now - timedelta(days=30)
    # "all"
    return datetime(2000, 1, 1, tzinfo=UTC)
