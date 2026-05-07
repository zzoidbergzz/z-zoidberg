"""Sectors / ISAC groups router."""
from __future__ import annotations
import uuid
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.dependencies import get_auth, require_scope, Scope, AuthContext
from app.models.sectors import Sector, SectorMembership, SectorInvite
from app.config import settings

router = APIRouter(tags=["sectors"])


# ──────────────────────────────────────────────────────────────────────────────
# Schemas
# ──────────────────────────────────────────────────────────────────────────────

class SectorOut(BaseModel):
    id: str
    slug: str
    name: str
    description: Optional[str]
    isac_name: Optional[str]
    info_sharing_enabled: bool
    active: bool
    member_count: int

    model_config = {"from_attributes": True}


class MemberOut(BaseModel):
    masked_email: str
    org_name: Optional[str]
    tenant_id: str


class ApproveBody(BaseModel):
    action: str  # "approve" | "reject"


class InviteBody(BaseModel):
    email: EmailStr
    org_name: Optional[str] = None


class AcceptInviteBody(BaseModel):
    token: str


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _mask_email(email: str) -> str:
    try:
        local, domain = email.split("@", 1)
        return f"{local[0]}***@{domain}"
    except Exception:
        return "***"


async def _get_sector(slug: str, db: AsyncSession) -> Sector:
    result = await db.execute(select(Sector).where(Sector.slug == slug, Sector.active == True))  # noqa
    sector = result.scalar_one_or_none()
    if not sector:
        raise HTTPException(status_code=404, detail="Sector not found")
    return sector


# ──────────────────────────────────────────────────────────────────────────────
# Public endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/sectors", response_model=list[SectorOut])
async def list_sectors(db: AsyncSession = Depends(get_db)):
    """List all active sectors (public)."""
    result = await db.execute(select(Sector).where(Sector.active == True))  # noqa
    sectors = result.scalars().all()
    return [SectorOut(
        id=str(s.id), slug=s.slug, name=s.name,
        description=s.description, isac_name=s.isac_name,
        info_sharing_enabled=s.info_sharing_enabled,
        active=s.active, member_count=s.member_count,
    ) for s in sectors]


@router.get("/sectors/{slug}", response_model=SectorOut)
async def get_sector(slug: str, db: AsyncSession = Depends(get_db)):
    """Get sector details + member count."""
    sector = await _get_sector(slug, db)
    return SectorOut(
        id=str(sector.id), slug=sector.slug, name=sector.name,
        description=sector.description, isac_name=sector.isac_name,
        info_sharing_enabled=sector.info_sharing_enabled,
        active=sector.active, member_count=sector.member_count,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Authenticated endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/sectors/{slug}/join", status_code=status.HTTP_201_CREATED)
async def join_sector(
    slug: str,
    auth: AuthContext = Depends(require_scope(Scope.read)),
    db: AsyncSession = Depends(get_db),
):
    """Request to join a sector (creates SectorMembership status=pending)."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    sector = await _get_sector(slug, db)

    # Check if already a member
    existing = await db.execute(
        select(SectorMembership).where(
            SectorMembership.sector_id == sector.id,
            SectorMembership.user_id == uuid.UUID(auth.user_id),
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Already a member or pending")

    membership = SectorMembership(
        sector_id=sector.id,
        user_id=uuid.UUID(auth.user_id),
        tenant_id=uuid.UUID(auth.tenant_id),
        status="pending",
    )
    db.add(membership)
    await db.flush()
    return {"status": "pending", "sector": slug}


@router.delete("/sectors/{slug}/membership", status_code=status.HTTP_204_NO_CONTENT)
async def leave_sector(
    slug: str,
    auth: AuthContext = Depends(require_scope(Scope.read)),
    db: AsyncSession = Depends(get_db),
):
    """Leave a sector."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    sector = await _get_sector(slug, db)

    result = await db.execute(
        select(SectorMembership).where(
            SectorMembership.sector_id == sector.id,
            SectorMembership.user_id == uuid.UUID(auth.user_id),
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=404, detail="Not a member")

    if membership.status == "approved":
        await db.execute(
            update(Sector).where(Sector.id == sector.id)
            .values(member_count=func.greatest(Sector.member_count - 1, 0))
        )

    await db.delete(membership)
    await db.flush()


@router.get("/sectors/{slug}/members", response_model=list[MemberOut])
async def list_sector_members(
    slug: str,
    auth: AuthContext = Depends(require_scope(Scope.read)),
    db: AsyncSession = Depends(get_db),
):
    """List approved members (basic info). Requires approved membership in that sector."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    sector = await _get_sector(slug, db)

    # Check caller is an approved member
    caller = await db.execute(
        select(SectorMembership).where(
            SectorMembership.sector_id == sector.id,
            SectorMembership.user_id == uuid.UUID(auth.user_id),
            SectorMembership.status == "approved",
        )
    )
    if not caller.scalar_one_or_none():
        raise HTTPException(status_code=403, detail="Approved sector membership required")

    from app.models.auth import User
    result = await db.execute(
        select(SectorMembership, User)
        .join(User, SectorMembership.user_id == User.id)
        .where(
            SectorMembership.sector_id == sector.id,
            SectorMembership.status == "approved",
        )
    )
    rows = result.all()
    return [
        MemberOut(
            masked_email=_mask_email(user.email),
            org_name=mem.org_name,
            tenant_id=str(mem.tenant_id),
        )
        for mem, user in rows
    ]


@router.post("/sectors/{slug}/accept-invite", status_code=status.HTTP_200_OK)
async def accept_invite(
    slug: str,
    body: AcceptInviteBody,
    auth: AuthContext = Depends(require_scope(Scope.read)),
    db: AsyncSession = Depends(get_db),
):
    """Accept invite via token."""
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    sector = await _get_sector(slug, db)

    # Validate token
    invite_result = await db.execute(
        select(SectorInvite).where(
            SectorInvite.token == body.token,
            SectorInvite.sector_id == sector.id,
            SectorInvite.used == False,  # noqa
        )
    )
    invite = invite_result.scalar_one_or_none()
    if not invite:
        raise HTTPException(status_code=404, detail="Invalid or expired invite token")

    now = datetime.now(timezone.utc)
    if invite.expires_at and invite.expires_at < now:
        raise HTTPException(status_code=410, detail="Invite token has expired")

    # Update or create membership
    mem_result = await db.execute(
        select(SectorMembership).where(
            SectorMembership.sector_id == sector.id,
            SectorMembership.user_id == uuid.UUID(auth.user_id),
        )
    )
    membership = mem_result.scalar_one_or_none()
    if membership:
        membership.status = "approved"
        membership.approved_at = now
    else:
        membership = SectorMembership(
            sector_id=sector.id,
            user_id=uuid.UUID(auth.user_id),
            tenant_id=uuid.UUID(auth.tenant_id),
            status="approved",
            approved_at=now,
            invited_by=invite.invited_by,
        )
        db.add(membership)

    invite.used = True
    invite.used_at = now

    await db.execute(
        update(Sector).where(Sector.id == sector.id)
        .values(member_count=Sector.member_count + 1)
    )
    await db.flush()
    return {"status": "approved", "sector": slug}


# ──────────────────────────────────────────────────────────────────────────────
# Admin endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/admin/sectors")
async def admin_list_sectors(
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Admin: list all sectors with pending member counts."""
    result = await db.execute(select(Sector))
    sectors = result.scalars().all()

    out = []
    for s in sectors:
        pending_result = await db.execute(
            select(func.count()).select_from(SectorMembership).where(
                SectorMembership.sector_id == s.id,
                SectorMembership.status == "pending",
            )
        )
        pending_count = pending_result.scalar_one()
        out.append({
            "id": str(s.id),
            "slug": s.slug,
            "name": s.name,
            "member_count": s.member_count,
            "pending_count": pending_count,
            "active": s.active,
        })
    return out


@router.post("/admin/sectors/{slug}/members/{user_id}/approve")
async def admin_approve_member(
    slug: str,
    user_id: uuid.UUID,
    body: ApproveBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Admin: approve or reject a join request."""
    sector = await _get_sector(slug, db)

    result = await db.execute(
        select(SectorMembership).where(
            SectorMembership.sector_id == sector.id,
            SectorMembership.user_id == user_id,
        )
    )
    membership = result.scalar_one_or_none()
    if not membership:
        raise HTTPException(status_code=404, detail="Membership not found")

    if body.action == "approve":
        was_approved = membership.status == "approved"
        membership.status = "approved"
        membership.approved_by = uuid.UUID(auth.user_id) if auth.user_id else None
        membership.approved_at = datetime.now(timezone.utc)
        if not was_approved:
            await db.execute(
                update(Sector).where(Sector.id == sector.id)
                .values(member_count=Sector.member_count + 1)
            )
    elif body.action == "reject":
        membership.status = "rejected"
    else:
        raise HTTPException(status_code=400, detail="action must be 'approve' or 'reject'")

    await db.flush()
    return {"status": membership.status}


@router.post("/admin/sectors/{slug}/invite", status_code=status.HTTP_201_CREATED)
async def admin_invite_member(
    slug: str,
    body: InviteBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Admin: invite a user by email."""
    sector = await _get_sector(slug, db)
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.SECTOR_INVITE_EXPIRY_DAYS)

    invite = SectorInvite(
        sector_id=sector.id,
        invited_email=body.email,
        invited_by=uuid.UUID(auth.user_id),
        token=token,
        expires_at=expires_at,
    )
    db.add(invite)
    await db.flush()

    # Check if user already exists and create invited membership
    from app.models.auth import User
    user_result = await db.execute(select(User).where(User.email == body.email))
    user = user_result.scalar_one_or_none()
    if user:
        existing = await db.execute(
            select(SectorMembership).where(
                SectorMembership.sector_id == sector.id,
                SectorMembership.user_id == user.id,
            )
        )
        if not existing.scalar_one_or_none():
            membership = SectorMembership(
                sector_id=sector.id,
                user_id=user.id,
                tenant_id=user.tenant_id,
                status="invited",
                invited_by=uuid.UUID(auth.user_id),
                org_name=body.org_name,
            )
            db.add(membership)
            await db.flush()

    return {
        "invite_token": token,
        "email": body.email,
        "expires_at": expires_at.isoformat(),
    }
