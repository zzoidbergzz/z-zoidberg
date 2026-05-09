from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent

_INTERNAL_ACTORS = {"worker", "system", "automation", "scheduler", "ingest-worker", "worker-ingest"}


def source_kind_for_audit(actor: str | None, details: dict[str, Any] | None = None) -> str:
    details = details or {}
    source_kind = details.get("source_kind")
    if source_kind in {"internal automation", "external users"}:
        return source_kind
    normalized_actor = actor.strip().lower() if actor else ""
    if normalized_actor in _INTERNAL_ACTORS or normalized_actor.endswith("-worker") or normalized_actor.startswith("worker"):
        return "internal automation"
    return "external users"


def activity_url_for_audit(resource_type: str | None, resource_id: str | None, details: dict[str, Any] | None = None) -> str | None:
    details = details or {}
    explicit = details.get("activity_url")
    if isinstance(explicit, str) and explicit:
        return explicit
    if resource_type == "lookup":
        entity_id = details.get("entity_id") or resource_id
        if entity_id:
            return f"/lookup/entity/{entity_id}/results"
    if resource_type == "fingerprint":
        return "/fingerprint"
    if resource_type == "entity" and resource_id:
        return f"/entities/{resource_id}"
    return None


def serialize_audit_event(event: AuditEvent) -> dict[str, Any]:
    details = event.details if isinstance(event.details, dict) else {}
    actor = getattr(event, "actor", None) or getattr(event, "actor_id", None)
    resource_type = getattr(event, "resource_type", None) or getattr(event, "resource_kind", None)
    source_kind = source_kind_for_audit(actor, details)
    status = details.get("status")
    if not isinstance(status, str) or not status:
        status = "success" if source_kind == "external users" or source_kind == "internal automation" else "success"
    return {
        "id": event.id,
        "action": event.action,
        "actor": actor,
        "actor_id": actor,
        "actor_email": actor,
        "resource_type": resource_type,
        "resource_id": event.resource_id,
        "status": status,
        "details": details,
        "created_at": event.created_at,
        "tenant_id": event.tenant_id,
        "source_kind": source_kind,
        "activity_url": activity_url_for_audit(resource_type, event.resource_id, details),
    }


async def record_audit_event(
    db: AsyncSession,
    *,
    tenant_id: str | UUID,
    actor: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    details: dict[str, Any] | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditEvent:
    payload = dict(details or {})
    if "source_kind" not in payload:
        payload["source_kind"] = source_kind_for_audit(actor, payload)
    event = AuditEvent(
        tenant_id=UUID(str(tenant_id)),
        actor=actor or "system",
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=payload,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    db.add(event)
    return event
