from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field
import uuid
from datetime import datetime
from typing import Optional
from app.database import get_db
from app.auth.dependencies import require_read
from app.models.audit import AuditEvent
from app.services.audit import serialize_audit_event

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditOut(BaseModel):
    id: uuid.UUID
    action: str
    actor: Optional[str] = None
    actor_id: Optional[str] = None
    actor_email: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    status: Optional[str] = None
    details: dict = Field(default_factory=dict)
    created_at: Optional[datetime] = None
    tenant_id: uuid.UUID
    source_kind: Optional[str] = None
    activity_url: Optional[str] = None
    model_config = {"from_attributes": True}


def _tenant_id_from_auth(auth: object) -> uuid.UUID:
    tenant_id = getattr(auth, "tenant_id", None)
    if tenant_id is None and isinstance(auth, dict):
        tenant_id = auth.get("tenant_id")
    if tenant_id is None:
        raise ValueError("auth context is missing tenant_id")
    return uuid.UUID(str(tenant_id))


@router.get("/", response_model=list[AuditOut])
async def list_audit_events(
    limit: int = Query(50, le=500),
    offset: int = 0,
    source: str = Query("all"),
    db: AsyncSession = Depends(get_db),
    auth: object = Depends(require_read),
):
    tenant_id = _tenant_id_from_auth(auth)
    query_limit = min(max(limit * 5, 100), 500)
    result = await db.execute(
        select(AuditEvent).where(AuditEvent.tenant_id == tenant_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(query_limit)
    )
    events = [serialize_audit_event(event) for event in result.scalars().all()]
    if source in {"internal", "external"}:
        wanted = "internal automation" if source == "internal" else "external users"
        events = [event for event in events if event["source_kind"] == wanted]
    return events[offset : offset + limit]
