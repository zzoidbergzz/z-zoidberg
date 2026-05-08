from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel
import uuid
from datetime import datetime
from typing import Optional
from app.database import get_db
from app.auth.dependencies import require_read
from app.models.audit import AuditEvent

router = APIRouter(prefix="/audit", tags=["audit"])


class AuditOut(BaseModel):
    id: uuid.UUID
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    actor_id: Optional[str]
    created_at: Optional[datetime]
    tenant_id: uuid.UUID
    model_config = {"from_attributes": True}


@router.get("/", response_model=list[AuditOut])
async def list_audit_events(
    limit: int = Query(50, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(
        select(AuditEvent).where(AuditEvent.tenant_id == auth.tenant_id)
        .order_by(AuditEvent.created_at.desc())
        .limit(limit).offset(offset)
    )
    return result.scalars().all()
