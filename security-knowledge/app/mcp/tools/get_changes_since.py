"""MCP tool: get entity/claim changes since a given datetime."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select

from app.mcp.registry import register_tool
from app.models.changes import Change


async def _get_changes_since(args: dict, db, auth) -> dict:
    since_raw = args.get("since")
    if not since_raw:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: since"}}
    try:
        since_dt = datetime.fromisoformat(since_raw)
    except ValueError:
        return {"error": {"code": "invalid_arg", "message": "since must be an ISO 8601 datetime"}}

    limit = int(args.get("limit", 100))
    stmt = (
        select(Change)
        .where(
            Change.tenant_id == uuid.UUID(str(auth.tenant_id)),
            Change.created_at >= since_dt,
        )
        .order_by(Change.created_at.desc())
        .limit(limit)
    )
    result = await db.execute(stmt)
    changes = result.scalars().all()
    return {
        "changes": [
            {
                "id": str(c.id),
                "resource_type": c.resource_type,
                "resource_id": c.resource_id,
                "change_type": c.change_type,
                "summary": c.summary,
                "source": c.source,
                "entity_id": str(c.entity_id) if c.entity_id else None,
                "created_at": c.created_at.isoformat() if c.created_at else None,
            }
            for c in changes
        ],
        "count": len(changes),
    }


register_tool(
    name="get_changes_since",
    fn=_get_changes_since,
    schema={
        "type": "object",
        "required": ["since"],
        "properties": {
            "since": {"type": "string", "description": "ISO 8601 datetime"},
            "limit": {"type": "integer", "default": 100},
        },
    },
    description="Get entity/claim changes since a given datetime",
    scope="read",
)
