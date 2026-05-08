"""MCP tools: digest subscriptions list/create."""

from __future__ import annotations

from sqlalchemy import select

from app.mcp.registry import register_tool
from app.models.digests import DigestSubscription


async def _list_digests(args: dict, db, auth) -> dict:
    rows = (
        await db.execute(
            select(DigestSubscription).where(
                DigestSubscription.tenant_id == auth.tenant_id
            )
        )
    ).scalars().all()
    return {
        "count": len(rows),
        "digests": [
            {
                "id": str(r.id),
                "name": r.name,
                "frequency": r.frequency,
                "active": r.active,
            }
            for r in rows
        ],
    }


async def _create_digest(args: dict, db, auth) -> dict:
    name = (args.get("name") or "").strip()
    if not name:
        return {"error": "name is required"}
    sub = DigestSubscription(
        tenant_id=auth.tenant_id,
        name=name,
        frequency=args.get("frequency", "daily"),
        channels=args.get("channels", []),
        filters=args.get("filters", {}),
    )
    db.add(sub)
    await db.flush()
    await db.commit()
    return {
        "id": str(sub.id),
        "name": sub.name,
        "frequency": sub.frequency,
        "active": sub.active,
    }


register_tool(
    name="list_digests",
    fn=_list_digests,
    schema={"type": "object", "properties": {}},
    description="List digest subscriptions for the caller's tenant.",
    scope="read",
)

register_tool(
    name="create_digest",
    fn=_create_digest,
    schema={
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {"type": "string"},
            "frequency": {"type": "string", "description": "daily | weekly | hourly"},
            "channels": {"type": "array", "items": {"type": "string"}},
            "filters": {"type": "object"},
        },
    },
    description="Create a digest subscription.",
    scope="write",
)
