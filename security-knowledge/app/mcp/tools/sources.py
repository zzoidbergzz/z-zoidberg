"""MCP tools: feed/source listing, status, and creation."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, func, select

from app.mcp.registry import register_tool
from app.models.sources import FetchOutcome, SourceRecord


async def _list_sources(args: dict, db, auth) -> dict:
    limit = min(int(args.get("limit", 50)), 500)
    active_only = bool(args.get("active_only", False))
    stmt = select(SourceRecord).where(SourceRecord.tenant_id == auth.tenant_id)
    if active_only:
        stmt = stmt.where(SourceRecord.active == True)  # noqa: E712
    stmt = stmt.limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {
        "count": len(rows),
        "sources": [
            {
                "id": str(r.id),
                "url": r.url,
                "title": getattr(r, "title", None),
                "kind": getattr(r, "kind", None),
                "source_type": getattr(r, "source_type", None),
                "active": getattr(r, "active", True),
                "fetch_interval_seconds": getattr(r, "fetch_interval_seconds", None),
                "last_fetched_at": str(getattr(r, "last_fetched_at", "") or "") or None,
            }
            for r in rows
        ],
    }


async def _feed_status(args: dict, db, auth) -> dict:
    """Health summary: what's overdue, what's failing, what's idle."""
    limit = min(int(args.get("limit", 200)), 500)
    stmt = (
        select(SourceRecord)
        .where(SourceRecord.tenant_id == auth.tenant_id, SourceRecord.active == True)  # noqa: E712
        .limit(limit)
    )
    sources = (await db.execute(stmt)).scalars().all()
    if not sources:
        return {"count": 0, "overdue": 0, "errored": 0, "feeds": []}

    source_ids = [s.id for s in sources]
    subq = (
        select(
            FetchOutcome.source_id,
            func.max(FetchOutcome.created_at).label("latest_at"),
        )
        .where(FetchOutcome.source_id.in_(source_ids))
        .group_by(FetchOutcome.source_id)
        .subquery()
    )
    outcomes = (
        await db.execute(
            select(FetchOutcome).join(
                subq,
                and_(
                    FetchOutcome.source_id == subq.c.source_id,
                    FetchOutcome.created_at == subq.c.latest_at,
                ),
            )
        )
    ).scalars().all()
    by_src = {o.source_id: o for o in outcomes}

    now = datetime.now(UTC)
    feeds = []
    overdue = errored = 0
    for s in sources:
        last_at = s.last_fetched_at
        if last_at and last_at.tzinfo is None:
            last_at = last_at.replace(tzinfo=UTC)
        next_due = (last_at + timedelta(seconds=s.fetch_interval_seconds)) if last_at else None
        is_overdue = next_due is None or next_due <= now
        if is_overdue:
            overdue += 1
        last = by_src.get(s.id)
        if last and last.status not in ("ok", "skipped"):
            errored += 1
        feeds.append({
            "id": str(s.id),
            "url": s.url,
            "title": s.title,
            "is_overdue": is_overdue,
            "last_status": last.status if last else None,
            "last_http": last.http_status if last else None,
            "last_error": last.error_message if last else None,
            "items_last_fetch": last.items_fetched if last else None,
            "last_fetched_at": str(last_at) if last_at else None,
            "next_due_at": str(next_due) if next_due else None,
        })
    return {"count": len(feeds), "overdue": overdue, "errored": errored, "feeds": feeds}


async def _add_source(args: dict, db, auth) -> dict:
    url = (args.get("url") or "").strip()
    if not url:
        return {"error": "url is required"}
    title = args.get("title") or url
    kind = args.get("kind", "feed")
    source_type = args.get("source_type", "rss")
    interval = int(args.get("fetch_interval_seconds", 3600))

    existing = (
        await db.execute(
            select(SourceRecord).where(
                SourceRecord.tenant_id == auth.tenant_id,
                SourceRecord.url == url,
            )
        )
    ).scalars().first()
    if existing:
        return {
            "id": str(existing.id),
            "url": existing.url,
            "created": False,
            "note": "Source already exists.",
        }
    src = SourceRecord(
        tenant_id=auth.tenant_id,
        url=url,
        title=title,
        kind=kind,
        source_type=source_type,
        fetch_interval_seconds=interval,
        active=True,
    )
    db.add(src)
    await db.flush()
    await db.commit()
    return {
        "id": str(src.id),
        "url": src.url,
        "title": src.title,
        "fetch_interval_seconds": src.fetch_interval_seconds,
        "created": True,
    }


register_tool(
    name="list_sources",
    fn=_list_sources,
    schema={
        "type": "object",
        "properties": {
            "limit": {"type": "integer"},
            "active_only": {"type": "boolean"},
        },
    },
    description="List ingestion sources (feeds) for the caller's tenant.",
    scope="read",
)

register_tool(
    name="feed_status",
    fn=_feed_status,
    schema={"type": "object", "properties": {"limit": {"type": "integer"}}},
    description="Health summary of all active feeds: overdue count, error count, per-feed last status.",
    scope="read",
)

register_tool(
    name="add_source",
    fn=_add_source,
    schema={
        "type": "object",
        "required": ["url"],
        "properties": {
            "url": {"type": "string"},
            "title": {"type": "string"},
            "kind": {"type": "string", "description": "feed | document | api (default feed)"},
            "source_type": {"type": "string", "description": "rss | atom | json | sitemap (default rss)"},
            "fetch_interval_seconds": {"type": "integer", "description": "Default 3600"},
        },
    },
    description="Register a new ingestion source. Idempotent on (tenant, url).",
    scope="write",
)
