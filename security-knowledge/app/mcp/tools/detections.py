"""MCP tools: detection rules (Sigma/YARA/etc) listing and creation."""

from __future__ import annotations

import uuid
from sqlalchemy import select

from app.mcp.registry import register_tool
from app.models.detections import DetectionRule


async def _list_detections(args: dict, db, auth) -> dict:
    limit = min(int(args.get("limit", 50)), 500)
    rows = (
        await db.execute(
            select(DetectionRule)
            .where(DetectionRule.tenant_id == auth.tenant_id)
            .limit(limit)
        )
    ).scalars().all()
    return {
        "count": len(rows),
        "rules": [
            {
                "id": str(r.id),
                "name": getattr(r, "name", None),
                "rule_type": getattr(r, "rule_type", None),
                "severity": getattr(r, "severity", None),
                "active": getattr(r, "active", None),
                "created_at": str(getattr(r, "created_at", "") or ""),
            }
            for r in rows
        ],
    }


async def _get_detection(args: dict, db, auth) -> dict:
    rule_id = args.get("rule_id")
    if not rule_id:
        return {"error": "rule_id is required"}
    try:
        rid = uuid.UUID(rule_id)
    except ValueError:
        return {"error": "rule_id must be a UUID"}
    rule = (
        await db.execute(
            select(DetectionRule).where(
                DetectionRule.tenant_id == auth.tenant_id,
                DetectionRule.id == rid,
            )
        )
    ).scalar_one_or_none()
    if rule is None:
        return {"error": "not_found", "rule_id": rule_id}
    return {
        "id": str(rule.id),
        "name": getattr(rule, "name", None),
        "rule_type": getattr(rule, "rule_type", None),
        "severity": getattr(rule, "severity", None),
        "rule_text": getattr(rule, "rule_text", None) or getattr(rule, "content", None),
        "tags": getattr(rule, "tags", []) or [],
        "active": getattr(rule, "active", None),
        "created_at": str(getattr(rule, "created_at", "") or ""),
    }


register_tool(
    name="list_detections",
    fn=_list_detections,
    schema={
        "type": "object",
        "properties": {"limit": {"type": "integer", "description": "Max rules to return (<=500)"}},
    },
    description="List detection rules (Sigma/YARA/etc) for the caller's tenant.",
    scope="read",
)

register_tool(
    name="get_detection",
    fn=_get_detection,
    schema={
        "type": "object",
        "required": ["rule_id"],
        "properties": {"rule_id": {"type": "string", "description": "UUID of the rule"}},
    },
    description="Fetch a single detection rule with full body.",
    scope="read",
)
