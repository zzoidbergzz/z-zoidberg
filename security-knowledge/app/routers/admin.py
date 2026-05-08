"""Admin router: user management, stats, sector approvals."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.dependencies import require_scope, Scope, AuthContext
from app.models.auth import User, UserStatus
from app.models.pingback import IocWatch, IocSighting
from app.models.enrichment import EnrichmentCache
from app.models.sectors import Sector, SectorMembership

router = APIRouter(prefix="/admin", tags=["admin"])


class ApproveUserBody(BaseModel):
    action: str  # "approve" | "reject"


@router.get("/users")
async def list_users(
    status_filter: Optional[str] = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """List users, optionally filtered by status."""
    q = select(User)
    if status_filter:
        q = q.where(User.status == status_filter)
    q = q.offset((page - 1) * per_page).limit(per_page)
    result = await db.execute(q)
    users = result.scalars().all()
    return [
        {
            "id": str(u.id),
            "email": u.email,
            "full_name": u.full_name,
            "business_sector": u.business_sector,
            "status": u.status,
            "role": u.role,
            "tenant_id": str(u.tenant_id),
            "created_at": u.created_at.isoformat() if u.created_at else None,
        }
        for u in users
    ]


@router.post("/users/{user_id}/approve")
async def approve_user(
    user_id: uuid.UUID,
    body: ApproveUserBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Approve or reject a user registration."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.action == "approve":
        user.status = UserStatus.approved
        user.approved_by = uuid.UUID(auth.user_id) if auth.user_id else None
        user.approved_at = datetime.now(timezone.utc)
    elif body.action == "reject":
        user.status = UserStatus.rejected
    else:
        raise HTTPException(status_code=400, detail="action must be 'approve' or 'reject'")

    await db.flush()
    return {"id": str(user.id), "status": user.status}


@router.get("/stats")
async def get_stats(
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Basic stats: user count, sighting count, watch count, enrichment cache size."""
    from app.models.documents import ParsedDocument
    from app.models.entities import Entity
    from app.models.audit import AuditEvent
    from app.models.sources import SourceRecord

    user_count = (await db.execute(select(func.count()).select_from(User))).scalar_one()
    watch_count = (await db.execute(select(func.count()).select_from(IocWatch))).scalar_one()
    sighting_count = (await db.execute(select(func.count()).select_from(IocSighting))).scalar_one()
    cache_count = (await db.execute(select(func.count()).select_from(EnrichmentCache))).scalar_one()
    source_count = (await db.execute(select(func.count()).select_from(SourceRecord))).scalar_one()
    source_active = (await db.execute(
        select(func.count()).select_from(SourceRecord).where(SourceRecord.active == True)  # noqa: E712
    )).scalar_one()
    document_count = (await db.execute(select(func.count()).select_from(ParsedDocument))).scalar_one()
    entity_count = (await db.execute(select(func.count()).select_from(Entity))).scalar_one()
    audit_count = (await db.execute(select(func.count()).select_from(AuditEvent))).scalar_one()
    pending_users = (await db.execute(
        select(func.count()).select_from(User).where(User.status == UserStatus.pending)
    )).scalar_one()

    return {
        "user_count": user_count,
        "pending_users": pending_users,
        "watch_count": watch_count,
        "sighting_count": sighting_count,
        "enrichment_cache_size": cache_count,
        "source_count": source_count,
        "source_active": source_active,
        "document_count": document_count,
        "entity_count": entity_count,
        "audit_count": audit_count,
    }


class SourceToggleBody(BaseModel):
    active: bool


@router.post("/sources/{source_id}/toggle")
async def toggle_source(
    source_id: uuid.UUID,
    body: SourceToggleBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Activate or deactivate a feed source."""
    from app.models.sources import SourceRecord

    src = (await db.execute(select(SourceRecord).where(SourceRecord.id == source_id))).scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Source not found")
    src.active = body.active
    await db.flush()
    return {"id": str(src.id), "active": src.active, "url": src.url}
