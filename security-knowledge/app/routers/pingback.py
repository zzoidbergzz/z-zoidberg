"""Pingback router: IOC watches, sightings, inbox, contacts."""
from __future__ import annotations
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.dependencies import get_auth, require_scope, Scope, AuthContext
from app.models.pingback import IocWatch, IocSighting, IocContact
from app.models.digests import InboxItem
from app.models.sectors import Sector, SectorMembership

router = APIRouter(tags=["pingback"])


# ──────────────────────────────────────────────────────────────────────────────
# Schemas
# ──────────────────────────────────────────────────────────────────────────────

class CreateWatchBody(BaseModel):
    ioc_value: str
    ioc_kind: str
    mode: str = "ping"
    sector_context: Optional[str] = None
    contact_note: Optional[str] = None
    notify_inbox: bool = True
    notify_email: bool = False


class WatchOut(BaseModel):
    id: str
    ioc_kind: str
    ioc_value_display: str
    mode: str
    active: bool
    sighting_count: int
    last_sighted_at: Optional[datetime]
    sector_context: Optional[str]
    created_at: datetime


class SightingOut(BaseModel):
    id: str
    trigger: str
    seen_at: datetime
    sector_share: str
    seeker_sector: Optional[str]
    seeker_comment: Optional[str]


class InboxOut(BaseModel):
    id: str
    subject: str
    body: str
    read: bool
    source_type: str
    created_at: datetime


class ContactOut(BaseModel):
    id: str
    ioc_value_hash: str
    status: str
    seeker_message: Optional[str]
    watcher_response: Optional[str]
    created_at: datetime


class AcceptContactBody(BaseModel):
    response: str


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _hash_ioc(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode()).hexdigest()


async def _caller_in_sector(sector_slug: str, user_id: str, db: AsyncSession) -> bool:
    """Return True if user is an approved member of the sector with info_sharing_enabled."""
    sector_result = await db.execute(
        select(Sector).where(Sector.slug == sector_slug, Sector.active == True)  # noqa
    )
    sector = sector_result.scalar_one_or_none()
    if not sector or not sector.info_sharing_enabled:
        return False
    mem_result = await db.execute(
        select(SectorMembership).where(
            SectorMembership.sector_id == sector.id,
            SectorMembership.user_id == uuid.UUID(user_id),
            SectorMembership.status == "approved",
        )
    )
    return mem_result.scalar_one_or_none() is not None


# ──────────────────────────────────────────────────────────────────────────────
# Watch endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/iocs/watches", status_code=status.HTTP_201_CREATED)
async def create_watch(
    body: CreateWatchBody,
    auth: AuthContext = Depends(require_scope(Scope.watch)),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")

    ioc_hash = _hash_ioc(body.ioc_value)
    now = datetime.now(timezone.utc)

    # Check for existing watch
    existing = await db.execute(
        select(IocWatch).where(
            IocWatch.user_id == uuid.UUID(auth.user_id),
            IocWatch.ioc_value_hash == ioc_hash,
            IocWatch.mode == body.mode,
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Watch already exists for this IOC and mode")

    watch = IocWatch(
        user_id=uuid.UUID(auth.user_id),
        tenant_id=uuid.UUID(auth.tenant_id),
        ioc_kind=body.ioc_kind,
        ioc_value_hash=ioc_hash,
        ioc_value_display=body.ioc_value,
        mode=body.mode,
        sector_context=body.sector_context,
        contact_note=body.contact_note,
        notify_inbox=body.notify_inbox,
        notify_email=body.notify_email,
        sighting_count=0,
        created_at=now,
        updated_at=now,
    )
    db.add(watch)
    await db.flush()
    await db.refresh(watch)

    return WatchOut(
        id=str(watch.id),
        ioc_kind=watch.ioc_kind,
        ioc_value_display=watch.ioc_value_display,
        mode=watch.mode,
        active=watch.active,
        sighting_count=watch.sighting_count,
        last_sighted_at=watch.last_sighted_at,
        sector_context=watch.sector_context,
        created_at=watch.created_at,
    )


@router.get("/iocs/watches", response_model=list[WatchOut])
async def list_watches(
    auth: AuthContext = Depends(require_scope(Scope.watch)),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    result = await db.execute(
        select(IocWatch).where(IocWatch.user_id == uuid.UUID(auth.user_id))
    )
    watches = result.scalars().all()
    return [WatchOut(
        id=str(w.id),
        ioc_kind=w.ioc_kind,
        ioc_value_display=w.ioc_value_display,
        mode=w.mode,
        active=w.active,
        sighting_count=w.sighting_count,
        last_sighted_at=w.last_sighted_at,
        sector_context=w.sector_context,
        created_at=w.created_at,
    ) for w in watches]


@router.delete("/iocs/watches/{watch_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_watch(
    watch_id: uuid.UUID,
    auth: AuthContext = Depends(require_scope(Scope.watch)),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    result = await db.execute(
        select(IocWatch).where(
            IocWatch.id == watch_id,
            IocWatch.user_id == uuid.UUID(auth.user_id),
        )
    )
    watch = result.scalar_one_or_none()
    if not watch:
        raise HTTPException(status_code=404, detail="Watch not found")
    await db.delete(watch)
    await db.flush()


@router.get("/iocs/watches/{watch_id}/sightings", response_model=list[SightingOut])
async def list_sightings(
    watch_id: uuid.UUID,
    auth: AuthContext = Depends(require_scope(Scope.watch)),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")

    # Verify ownership
    w_result = await db.execute(
        select(IocWatch).where(
            IocWatch.id == watch_id,
            IocWatch.user_id == uuid.UUID(auth.user_id),
        )
    )
    watch = w_result.scalar_one_or_none()
    if not watch:
        raise HTTPException(status_code=404, detail="Watch not found")

    result = await db.execute(
        select(IocSighting).where(IocSighting.watch_id == watch_id)
    )
    sightings = result.scalars().all()

    out = []
    for s in sightings:
        # Check sector-share visibility
        show_sector_data = False
        if s.seeker_sector and s.sector_share == "full":
            show_sector_data = await _caller_in_sector(s.seeker_sector, auth.user_id, db)

        out.append(SightingOut(
            id=str(s.id),
            trigger=s.trigger,
            seen_at=s.seen_at,
            sector_share=s.sector_share,
            seeker_sector=s.seeker_sector if show_sector_data else None,
            seeker_comment=s.seeker_comment if show_sector_data else None,
        ))
    return out


# ──────────────────────────────────────────────────────────────────────────────
# Inbox endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/inbox", response_model=list[InboxOut])
async def get_inbox(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    auth: AuthContext = Depends(require_scope(Scope.watch)),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    offset = (page - 1) * per_page
    result = await db.execute(
        select(InboxItem)
        .where(InboxItem.user_id == uuid.UUID(auth.user_id))
        .order_by(InboxItem.created_at.desc())
        .offset(offset)
        .limit(per_page)
    )
    items = result.scalars().all()
    return [InboxOut(
        id=str(i.id),
        subject=i.subject,
        body=i.body or "",
        read=i.read,
        source_type=i.source_type,
        created_at=i.created_at,
    ) for i in items]


@router.put("/inbox/{item_id}/read", status_code=status.HTTP_200_OK)
async def mark_inbox_read(
    item_id: uuid.UUID,
    auth: AuthContext = Depends(require_scope(Scope.watch)),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    result = await db.execute(
        select(InboxItem).where(
            InboxItem.id == item_id,
            InboxItem.user_id == uuid.UUID(auth.user_id),
        )
    )
    item = result.scalar_one_or_none()
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item.read = True
    await db.flush()
    return {"id": str(item.id), "read": True}


# ──────────────────────────────────────────────────────────────────────────────
# Contact endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/iocs/contacts", response_model=list[ContactOut])
async def list_contacts(
    auth: AuthContext = Depends(require_scope(Scope.contact)),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    uid = uuid.UUID(auth.user_id)
    result = await db.execute(
        select(IocContact).where(
            (IocContact.seeker_user_id == uid) | (IocContact.watcher_user_id == uid)
        )
    )
    contacts = result.scalars().all()
    return [ContactOut(
        id=str(c.id),
        ioc_value_hash=c.ioc_value_hash,
        status=c.status,
        seeker_message=c.seeker_message,
        watcher_response=c.watcher_response,
        created_at=c.created_at,
    ) for c in contacts]


@router.post("/iocs/contacts/{contact_id}/accept")
async def accept_contact(
    contact_id: uuid.UUID,
    body: AcceptContactBody,
    auth: AuthContext = Depends(require_scope(Scope.contact)),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    result = await db.execute(
        select(IocContact).where(
            IocContact.id == contact_id,
            IocContact.watcher_user_id == uuid.UUID(auth.user_id),
        )
    )
    contact = result.scalar_one_or_none()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    contact.status = "accepted"
    contact.watcher_response = body.response
    contact.watcher_revealed_at = datetime.now(timezone.utc)
    contact.seeker_revealed_at = datetime.now(timezone.utc)
    await db.flush()
    return {"status": "accepted"}


@router.post("/iocs/contacts/{contact_id}/decline", status_code=status.HTTP_200_OK)
async def decline_contact(
    contact_id: uuid.UUID,
    auth: AuthContext = Depends(require_scope(Scope.contact)),
    db: AsyncSession = Depends(get_db),
):
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    result = await db.execute(
        select(IocContact).where(
            IocContact.id == contact_id,
            IocContact.watcher_user_id == uuid.UUID(auth.user_id),
        )
    )
    contact = result.scalar_one_or_none()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    contact.status = "declined"
    await db.flush()
    return {"status": "declined"}
