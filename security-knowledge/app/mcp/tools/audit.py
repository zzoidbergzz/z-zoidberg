"""MCP tool: query the audit log."""

from __future__ import annotations

from sqlalchemy import select

from app.mcp.registry import register_tool
from app.models.audit import AuditEvent


async def _query_audit_log(args: dict, db, auth) -> dict:
    limit = min(int(args.get("limit", 50)), 500)
    offset = max(int(args.get("offset", 0)), 0)
    action = args.get("action")

    stmt = select(AuditEvent).where(AuditEvent.tenant_id == auth.tenant_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    stmt = stmt.order_by(AuditEvent.created_at.desc()).limit(limit).offset(offset)

    rows = (await db.execute(stmt)).scalars().all()
    return {
        "count": len(rows),
        "events": [
            {
                "id": str(r.id),
                "action": r.action,
                "resource_type": getattr(r, "resource_type", None) or getattr(r, "resource_kind", None),
                "resource_id": str(getattr(r, "resource_id", "") or "") or None,
                "actor": getattr(r, "actor", None) or (str(getattr(r, "actor_id", "") or "") or None),
                "ip_address": getattr(r, "ip_address", None),
                "created_at": str(r.created_at) if r.created_at else None,
            }
            for r in rows
        ],
    }


register_tool(
    name="query_audit_log",
    fn=_query_audit_log,
    schema={
        "type": "object",
        "properties": {
            "limit": {"type": "integer", "description": "Max events (<=500, default 50)"},
            "offset": {"type": "integer", "description": "Pagination offset"},
            "action": {"type": "string", "description": "Optional filter by action name"},
        },
    },
    description="Query the audit log for the caller's tenant, newest first.",
    scope="read",
)
