"""Admin router: user management, stats, sector approvals."""
from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, field_validator
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.auth.dependencies import require_scope, Scope, AuthContext
from app.models.auth import ApiKey, Tenant, User, UserProviderKey, UserStatus
from app.models.pingback import IocWatch, IocSighting
from app.models.enrichment import EnrichmentCache
from app.models.watchlists import Watchlist
from app.services.watchlists import (
    get_or_create_default_org_watchlist,
    get_or_create_default_personal_watchlist,
    normalize_watchlist_slug,
    tenant_watchlist_config,
    normalize_watchlist_expiry,
)
from app.models.sectors import Sector, SectorMembership

router = APIRouter(prefix="/admin", tags=["admin"])


def _is_superadmin(auth: AuthContext) -> bool:
    return auth.has_scope(Scope.superadmin)


def _tenant_uuid(auth: AuthContext) -> uuid.UUID:
    return uuid.UUID(auth.tenant_id)


class ApproveUserBody(BaseModel):
    action: str  # "approve" | "reject"


class CreateTenantBody(BaseModel):
    name: str
    slug: str


class MoveUserTenantBody(BaseModel):
    tenant_id: uuid.UUID


class WatchlistSettingsBody(BaseModel):
    scope_mode: str | None = None
    default_expiry_hours: int | None = None
    max_expiry_hours: int | None = None

    @field_validator("scope_mode")
    @classmethod
    def _validate_scope_mode(cls, value: str | None) -> str | None:
        if value is not None and value not in {"personal", "org", "both"}:
            raise ValueError("scope_mode must be personal, org, or both")
        return value


class CreateOrgWatchlistBody(BaseModel):
    name: str
    expiry_hours: int | None = None
    description: str | None = None
    public_slug: str | None = None
    allow_unauthenticated: bool = False


@router.get("/users")
async def list_users(
    status_filter: Optional[str] = Query(None, alias="status"),
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """List users, optionally filtered by status."""
    if status_filter == "active":
        status_filter = UserStatus.approved
    if status_filter and status_filter not in {UserStatus.pending, UserStatus.approved, UserStatus.rejected}:
        raise HTTPException(status_code=400, detail="Invalid status filter")

    q = select(User)
    if not _is_superadmin(auth):
        q = q.where(User.tenant_id == _tenant_uuid(auth))
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


@router.get("/tenants")
async def list_tenants(
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """List all tenants (superadmin only), including user counts."""
    if not _is_superadmin(auth):
        raise HTTPException(status_code=403, detail="Superadmin scope required")

    tenants = (await db.execute(select(Tenant).order_by(Tenant.slug.asc()))).scalars().all()
    rows = []
    for tenant in tenants:
        user_count = (await db.execute(
            select(func.count()).select_from(User).where(User.tenant_id == tenant.id)
        )).scalar_one()
        rows.append({
            "id": str(tenant.id),
            "name": tenant.name,
            "slug": tenant.slug,
            "active": tenant.active,
            "user_count": user_count,
            "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
        })
    return rows


@router.post("/tenants", status_code=201)
async def create_tenant(
    body: CreateTenantBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Create a tenant (superadmin only)."""
    if not _is_superadmin(auth):
        raise HTTPException(status_code=403, detail="Superadmin scope required")

    slug = body.slug.strip().lower()
    if not slug:
        raise HTTPException(status_code=400, detail="slug is required")
    existing = (await db.execute(select(Tenant).where(Tenant.slug == slug))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Tenant slug already exists")

    tenant = Tenant(name=body.name.strip(), slug=slug, active=True)
    db.add(tenant)
    await db.flush()
    await db.commit()
    return {
        "id": str(tenant.id),
        "name": tenant.name,
        "slug": tenant.slug,
        "active": tenant.active,
        "created_at": tenant.created_at.isoformat() if tenant.created_at else None,
    }


@router.post("/users/{user_id}/tenant")
async def move_user_tenant(
    user_id: uuid.UUID,
    body: MoveUserTenantBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Move a user to a different tenant (superadmin only)."""
    if not _is_superadmin(auth):
        raise HTTPException(status_code=403, detail="Superadmin scope required")

    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    tenant = (await db.execute(select(Tenant).where(Tenant.id == body.tenant_id))).scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")

    user.tenant_id = tenant.id

    api_keys = (await db.execute(select(ApiKey).where(ApiKey.user_id == user.id))).scalars().all()
    for key in api_keys:
        key.tenant_id = tenant.id
    provider_keys = (await db.execute(select(UserProviderKey).where(UserProviderKey.user_id == user.id))).scalars().all()
    for provider_key in provider_keys:
        provider_key.tenant_id = tenant.id

    await db.flush()
    await db.commit()
    return {
        "id": str(user.id),
        "email": user.email,
        "tenant_id": str(user.tenant_id),
    }


@router.post("/users/{user_id}/approve")
async def approve_user(
    user_id: uuid.UUID,
    body: ApproveUserBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    """Approve or reject a user registration."""
    q = select(User).where(User.id == user_id)
    if not _is_superadmin(auth):
        q = q.where(User.tenant_id == _tenant_uuid(auth))
    result = await db.execute(q)
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if body.action == "approve":
        user.status = UserStatus.approved
        user.approved_by = uuid.UUID(auth.user_id) if auth.user_id else None
        user.approved_at = datetime.now(timezone.utc)
        # Auto-generate first API key on approval if user has none
        from app.auth.api_key import generate_api_key
        existing_keys = (await db.execute(
            select(func.count()).select_from(ApiKey).where(ApiKey.user_id == user.id)
        )).scalar_one()
        new_key_plaintext = None
        if existing_keys == 0:
            raw, key_hash = generate_api_key()
            ak = ApiKey(
                user_id=user.id,
                tenant_id=user.tenant_id,
                key_hash=key_hash,
                name=f"auto-generated-{user.email.split('@')[0]}",
                scopes="read write enrichment watch",
                active=True,
            )
            db.add(ak)
            new_key_plaintext = raw
        tenant = (await db.execute(select(Tenant).where(Tenant.id == user.tenant_id))).scalar_one_or_none()
        config = tenant_watchlist_config(tenant)
        allowed_scopes = {"personal"} if (config.get("scope_mode") or "both") == "personal" else {"personal", "org"} if (config.get("scope_mode") or "both") == "both" else {"org"}
        if "personal" in allowed_scopes:
            await get_or_create_default_personal_watchlist(
                db,
                tenant=tenant,
                tenant_id=user.tenant_id,
                user_id=user.id,
            )
        if "org" in allowed_scopes:
            await get_or_create_default_org_watchlist(
                db,
                tenant=tenant,
                tenant_id=user.tenant_id,
                user_id=user.id,
            )
        await db.flush()
        await db.commit()
        return {"id": str(user.id), "status": user.status, "api_key": new_key_plaintext}
    elif body.action == "reject":
        user.status = UserStatus.rejected
    else:
        raise HTTPException(status_code=400, detail="action must be 'approve' or 'reject'")

    await db.flush()
    await db.commit()
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

    tenant_filter = _tenant_uuid(auth)
    if _is_superadmin(auth):
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
    else:
        user_count = (await db.execute(
            select(func.count()).select_from(User).where(User.tenant_id == tenant_filter)
        )).scalar_one()
        watch_count = (await db.execute(
            select(func.count()).select_from(IocWatch).where(IocWatch.tenant_id == tenant_filter)
        )).scalar_one()
        sighting_count = (await db.execute(
            select(func.count()).select_from(IocSighting).where(IocSighting.seeker_tenant_id == tenant_filter)
        )).scalar_one()
        cache_count = (await db.execute(
            select(func.count()).select_from(EnrichmentCache).where(EnrichmentCache.tenant_id == tenant_filter)
        )).scalar_one()
        source_count = (await db.execute(
            select(func.count()).select_from(SourceRecord).where(SourceRecord.tenant_id == tenant_filter)
        )).scalar_one()
        source_active = (await db.execute(
            select(func.count())
            .select_from(SourceRecord)
            .where(SourceRecord.tenant_id == tenant_filter, SourceRecord.active == True)  # noqa: E712
        )).scalar_one()
        document_count = (await db.execute(
            select(func.count()).select_from(ParsedDocument).where(ParsedDocument.tenant_id == tenant_filter)
        )).scalar_one()
        entity_count = (await db.execute(
            select(func.count()).select_from(Entity).where(Entity.tenant_id == tenant_filter)
        )).scalar_one()
        audit_count = (await db.execute(
            select(func.count()).select_from(AuditEvent).where(AuditEvent.tenant_id == tenant_filter)
        )).scalar_one()
        pending_users = (await db.execute(
            select(func.count())
            .select_from(User)
            .where(User.tenant_id == tenant_filter, User.status == UserStatus.pending)
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

    q = select(SourceRecord).where(SourceRecord.id == source_id)
    if not _is_superadmin(auth):
        q = q.where(SourceRecord.tenant_id == _tenant_uuid(auth))
    src = (await db.execute(q)).scalar_one_or_none()
    if not src:
        raise HTTPException(status_code=404, detail="Source not found")
    src.active = body.active
    await db.flush()
    await db.commit()
    return {"id": str(src.id), "active": src.active, "url": src.url}


@router.get("/watchlist-settings")
async def get_watchlist_settings(
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    tenant = (await db.execute(select(Tenant).where(Tenant.id == _tenant_uuid(auth)))).scalar_one_or_none()
    if not tenant:
        config = tenant_watchlist_config(None)
        config["tenant_missing"] = True
        return config
    config = tenant_watchlist_config(tenant)
    config["tenant_missing"] = False
    return config


@router.get("/settings/watchlist")
async def get_watchlist_settings_legacy(
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    return await get_watchlist_settings(auth=auth, db=db)


@router.put("/watchlist-settings")
async def update_watchlist_settings(
    body: WatchlistSettingsBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    tenant = (await db.execute(select(Tenant).where(Tenant.id == _tenant_uuid(auth)))).scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    config = tenant_watchlist_config(tenant)
    if body.scope_mode is not None:
        config["scope_mode"] = body.scope_mode
    if body.default_expiry_hours is not None:
        config["default_expiry_hours"] = normalize_watchlist_expiry(body.default_expiry_hours, tenant=tenant)
    if body.max_expiry_hours is not None:
        config["max_expiry_hours"] = normalize_watchlist_expiry(body.max_expiry_hours, tenant=tenant)
    tenant.watchlist_settings = config
    await db.flush()
    await db.commit()
    return tenant_watchlist_config(tenant)


@router.put("/settings/watchlist")
async def update_watchlist_settings_legacy(
    body: WatchlistSettingsBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    return await update_watchlist_settings(body=body, auth=auth, db=db)


@router.post("/watchlists", status_code=201)
async def create_org_watchlist(
    body: CreateOrgWatchlistBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
    db: AsyncSession = Depends(get_db),
):
    tenant = (await db.execute(select(Tenant).where(Tenant.id == _tenant_uuid(auth)))).scalar_one_or_none()
    if not tenant:
        raise HTTPException(status_code=404, detail="Tenant not found")
    config = tenant_watchlist_config(tenant)
    allowed_scopes = {"org"} if (config.get("scope_mode") or "both") in {"org", "both"} else set()
    if "org" not in allowed_scopes:
        raise HTTPException(status_code=403, detail="org watchlists are disabled for this tenant")
    watchlist = Watchlist(
        tenant_id=tenant.id,
        owner_user_id=None,
        created_by_user_id=uuid.UUID(auth.user_id) if auth.user_id else None,
        name=body.name.strip() or "Org watchlist",
        scope="org",
        description=body.description,
        expiry_hours=normalize_watchlist_expiry(body.expiry_hours, tenant=tenant),
        export_formats=dict(config.get("export_formats") or {}),
        public_slug=normalize_watchlist_slug(body.public_slug) if body.public_slug else None,
        allow_unauthenticated=body.allow_unauthenticated,
        active=True,
    )
    db.add(watchlist)
    await db.flush()
    await db.commit()
    return {
        "id": str(watchlist.id),
        "name": watchlist.name,
        "scope": watchlist.scope,
        "expiry_hours": watchlist.expiry_hours,
        "description": watchlist.description,
        "public_slug": watchlist.public_slug,
        "allow_unauthenticated": watchlist.allow_unauthenticated,
    }


class UserAgentBody(BaseModel):
    user_agent: str


@router.get("/settings/user-agent")
async def get_user_agent(
    auth: AuthContext = Depends(require_scope(Scope.admin)),
):
    """Get the configured feed poller user-agent."""
    from app.config import settings as app_settings
    return {"user_agent": app_settings.FEED_POLL_USER_AGENT}


@router.post("/settings/user-agent")
async def set_user_agent(
    body: UserAgentBody,
    auth: AuthContext = Depends(require_scope(Scope.admin)),
):
    """Set the feed poller user-agent (runtime only — set in .env for persistence)."""
    from app.config import settings as app_settings
    app_settings.FEED_POLL_USER_AGENT = body.user_agent
    return {"user_agent": app_settings.FEED_POLL_USER_AGENT, "note": "Runtime only. Set FEED_POLL_USER_AGENT in .env for persistence."}
