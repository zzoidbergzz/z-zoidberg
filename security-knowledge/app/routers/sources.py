import uuid
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_read
from app.database import get_db
from app.models.sources import FetchOutcome, SourceRecord

router = APIRouter(prefix="/sources", tags=["sources"])


class SourceOut(BaseModel):
    id: uuid.UUID
    url: str
    source_type: str | None
    tenant_id: uuid.UUID
    model_config = {"from_attributes": True}


class LastOutcome(BaseModel):
    status: str
    http_status: int | None
    error_message: str | None
    items_fetched: int
    duration_ms: int
    recorded_at: datetime


class FeedStatus(BaseModel):
    id: uuid.UUID
    url: str
    title: str
    kind: str
    source_type: str
    active: bool
    fetch_interval_seconds: int
    last_fetched_at: datetime | None
    next_due_at: datetime | None
    is_overdue: bool
    last_outcome: LastOutcome | None


@router.get("/", response_model=list[SourceOut])
async def list_sources(
    limit: int = Query(20, le=200),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(
        select(SourceRecord).where(SourceRecord.tenant_id == auth["tenant_id"]).limit(limit)
    )
    return result.scalars().all()


@router.get("/status", response_model=list[FeedStatus])
async def feed_status(
    active_only: bool = Query(True),
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    """Return per-feed health: last fetch time, next due time, last outcome, overdue flag."""
    stmt = select(SourceRecord).where(SourceRecord.tenant_id == auth["tenant_id"])
    if active_only:
        stmt = stmt.where(SourceRecord.active == True)  # noqa: E712
    stmt = stmt.limit(limit)
    sources_result = await db.execute(stmt)
    sources = sources_result.scalars().all()

    if not sources:
        return []

    source_ids = [s.id for s in sources]

    # Fetch the most recent FetchOutcome per source in one query using a lateral join approach.
    # We use a subquery to get the latest outcome id per source.
    from sqlalchemy import and_, func

    # Latest outcome per source
    subq = (
        select(
            FetchOutcome.source_id,
            func.max(FetchOutcome.created_at).label("latest_at"),
        )
        .where(FetchOutcome.source_id.in_(source_ids))
        .group_by(FetchOutcome.source_id)
        .subquery()
    )
    outcomes_stmt = select(FetchOutcome).join(
        subq,
        and_(
            FetchOutcome.source_id == subq.c.source_id,
            FetchOutcome.created_at == subq.c.latest_at,
        ),
    )
    outcomes_result = await db.execute(outcomes_stmt)
    outcomes_by_source: dict[uuid.UUID, FetchOutcome] = {
        o.source_id: o for o in outcomes_result.scalars().all()
    }

    now = datetime.now(UTC)
    statuses: list[FeedStatus] = []
    for source in sources:
        last_at = source.last_fetched_at
        if last_at and last_at.tzinfo is None:
            last_at = last_at.replace(tzinfo=UTC)
        next_due = (last_at + timedelta(seconds=source.fetch_interval_seconds)) if last_at else None
        is_overdue = (next_due is None) or (next_due <= now)

        outcome = outcomes_by_source.get(source.id)
        last_outcome: LastOutcome | None = None
        if outcome:
            last_outcome = LastOutcome(
                status=outcome.status,
                http_status=outcome.http_status,
                error_message=outcome.error_message,
                items_fetched=outcome.items_fetched,
                duration_ms=outcome.duration_ms,
                recorded_at=outcome.created_at,
            )

        statuses.append(
            FeedStatus(
                id=source.id,
                url=source.url,
                title=source.title,
                kind=source.kind,
                source_type=source.source_type,
                active=source.active,
                fetch_interval_seconds=source.fetch_interval_seconds,
                last_fetched_at=last_at,
                next_due_at=next_due,
                is_overdue=is_overdue,
                last_outcome=last_outcome,
            )
        )

    return statuses
