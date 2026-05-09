"""Watchlist collection and export endpoints."""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.auth.dependencies import AuthContext, Scope, get_auth
from app.database import get_db
from app.models.auth import Tenant
from app.models.pingback import IocWatch
from app.models.watchlists import Watchlist
from app.services.watchlists import (
    DEFAULT_WATCHLIST_EXPIRY_HOURS,
    DEFAULT_WATCHLIST_NAME,
    get_or_create_default_org_watchlist,
    get_or_create_default_personal_watchlist,
    normalize_watchlist_expiry,
    normalize_watchlist_slug,
    tenant_watchlist_config,
    watchlist_export_formats,
    watchlist_export_path,
    watchlist_public_export_path,
    watchlist_expires_at,
    watchlist_is_expired,
)

router = APIRouter(tags=["watchlists"])


def _allowed_watchlist_scopes(config: dict) -> set[str]:
    mode = config.get("scope_mode") or "both"
    if mode == "personal":
        return {"personal"}
    if mode == "org":
        return {"org"}
    return {"personal", "org"}


class WatchlistCreate(BaseModel):
    name: str
    scope: str = "personal"
    expiry_hours: int | None = None
    description: str | None = None
    public_slug: str | None = None
    allow_unauthenticated: bool = False

    @field_validator("scope")
    @classmethod
    def _scope_ok(cls, value: str) -> str:
        if value not in {"personal", "org"}:
            raise ValueError("scope must be personal or org")
        return value


class WatchlistUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    active: bool | None = None
    expiry_hours: int | None = None
    export_json: bool | None = None
    export_stix: bool | None = None
    export_misp: bool | None = None
    export_csv: bool | None = None
    public_slug: str | None = None
    allow_unauthenticated: bool | None = None


def _can_manage(auth: AuthContext, watchlist: Watchlist) -> bool:
    if auth.has_scope(Scope.admin):
        return True
    return watchlist.scope == "personal" and watchlist.owner_user_id and str(watchlist.owner_user_id) == auth.user_id


async def _tenant(db: AsyncSession, tenant_id: str) -> Tenant | None:
    return (await db.execute(select(Tenant).where(Tenant.id == uuid.UUID(tenant_id)))).scalar_one_or_none()


def _item_out(item: IocWatch) -> dict:
    now = datetime.now(UTC)
    expired = False
    if item.watchlist:
        expired = watchlist_is_expired(item.watchlist, now)
    return {
        "id": str(item.id),
        "ioc_kind": item.ioc_kind,
        "ioc_value_display": item.ioc_value_display,
        "comment": item.comment,
        "mode": item.mode,
        "active": item.active and not expired,
        "sighting_count": item.sighting_count,
        "last_sighted_at": item.last_sighted_at.isoformat() if item.last_sighted_at else None,
        "sector_context": item.sector_context,
        "created_at": item.created_at.isoformat() if item.created_at else None,
        "watchlist_id": str(item.watchlist_id) if item.watchlist_id else None,
    }


def _watchlist_out(watchlist: Watchlist, items: list[IocWatch], *, tenant_config: dict | None = None) -> dict:
    expires_at = watchlist_expires_at(watchlist)
    item_rows = [_item_out(item) for item in items]
    export_formats = watchlist_export_formats(watchlist, tenant_config=tenant_config)
    return {
        "id": str(watchlist.id),
        "name": watchlist.name,
        "scope": watchlist.scope,
        "description": watchlist.description,
        "active": watchlist.active,
        "expiry_hours": watchlist.expiry_hours,
        "expires_at": expires_at.isoformat() if expires_at else None,
        "owner_user_id": str(watchlist.owner_user_id) if watchlist.owner_user_id else None,
        "created_by_user_id": str(watchlist.created_by_user_id) if watchlist.created_by_user_id else None,
        "created_at": watchlist.created_at.isoformat() if watchlist.created_at else None,
        "updated_at": watchlist.updated_at.isoformat() if watchlist.updated_at else None,
        "public_slug": watchlist.public_slug,
        "allow_unauthenticated": watchlist.allow_unauthenticated,
        "items": item_rows,
        "counts": {
            "items": len(item_rows),
            "active_items": sum(1 for item in item_rows if item["active"]),
        },
        "exports": {
            fmt: watchlist_export_path(str(watchlist.id), fmt)
            for fmt, enabled in export_formats.items()
            if enabled
        },
        "public_exports": {
            fmt: watchlist_public_export_path(watchlist.public_slug, fmt)
            for fmt, enabled in export_formats.items()
            if enabled and watchlist.allow_unauthenticated and watchlist.public_slug
        },
    }


async def _load_watchlists(db: AsyncSession, auth: AuthContext) -> list[dict]:
    tenant = await _tenant(db, auth.tenant_id)
    config = tenant_watchlist_config(tenant)
    allowed_scopes = _allowed_watchlist_scopes(config)
    default_watchlists: list[Watchlist] = []
    if auth.user_id:
        user_uuid = uuid.UUID(auth.user_id)
        if "personal" in allowed_scopes:
            default_watchlists.append(
                await get_or_create_default_personal_watchlist(
                    db,
                    tenant=tenant,
                    tenant_id=uuid.UUID(auth.tenant_id),
                    user_id=user_uuid,
                )
            )
        if "org" in allowed_scopes:
            default_watchlists.append(
                await get_or_create_default_org_watchlist(
                    db,
                    tenant=tenant,
                    tenant_id=uuid.UUID(auth.tenant_id),
                    user_id=user_uuid,
                )
            )

    q = select(Watchlist).options(selectinload(Watchlist.items)).where(Watchlist.tenant_id == uuid.UUID(auth.tenant_id))
    q = q.where(Watchlist.active.is_(True), Watchlist.scope.in_(allowed_scopes))
    if auth.user_id:
        q = q.where((Watchlist.scope == "org") | (Watchlist.owner_user_id == uuid.UUID(auth.user_id)))
    rows = (await db.execute(q.order_by(Watchlist.scope.asc(), Watchlist.name.asc()))).scalars().all()
    rows = [w for w in rows if w.scope in allowed_scopes and (w.scope == "org" or str(w.owner_user_id) == auth.user_id)]

    seen_ids = {w.id for w in rows}
    for default_watchlist in reversed(default_watchlists):
        if default_watchlist.id not in seen_ids:
            rows = [default_watchlist] + rows
            seen_ids.add(default_watchlist.id)

    return [_watchlist_out(w, list(w.items or []), tenant_config=config) for w in rows]


@router.get("/watchlists")
async def list_watchlists(
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    auth.require_scope(Scope.watch)
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    watchlists = await _load_watchlists(db, auth)
    tenant = await _tenant(db, auth.tenant_id)
    config = tenant_watchlist_config(tenant)
    return {"watchlists": watchlists, "config": config}


@router.post("/watchlists", status_code=status.HTTP_201_CREATED)
async def create_watchlist(
    body: WatchlistCreate,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    auth.require_scope(Scope.admin)
    if not auth.user_id:
        raise HTTPException(status_code=403, detail="User context required")
    tenant = await _tenant(db, auth.tenant_id)
    config = tenant_watchlist_config(tenant)
    allowed_scopes = _allowed_watchlist_scopes(config)
    if body.scope not in allowed_scopes:
        raise HTTPException(status_code=403, detail=f"{body.scope} watchlists are disabled for this tenant")
    expiry_hours = normalize_watchlist_expiry(body.expiry_hours, tenant=tenant)
    public_slug = normalize_watchlist_slug(body.public_slug) if body.public_slug else None
    watchlist = Watchlist(
        tenant_id=uuid.UUID(auth.tenant_id),
        owner_user_id=None if body.scope == "org" else uuid.UUID(auth.user_id),
        created_by_user_id=uuid.UUID(auth.user_id),
        name=body.name.strip() or DEFAULT_WATCHLIST_NAME,
        scope=body.scope,
        description=body.description,
        expiry_hours=expiry_hours,
        export_formats=dict(config.get("export_formats") or {}),
        public_slug=public_slug,
        allow_unauthenticated=body.allow_unauthenticated,
        active=True,
    )
    db.add(watchlist)
    await db.flush()
    return _watchlist_out(watchlist, [], tenant_config=config)


@router.patch("/watchlists/{watchlist_id}")
async def update_watchlist(
    watchlist_id: uuid.UUID,
    body: WatchlistUpdate,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    auth.require_scope(Scope.watch)
    result = await db.execute(
        select(Watchlist).options(selectinload(Watchlist.items)).where(
            Watchlist.id == watchlist_id,
            Watchlist.tenant_id == uuid.UUID(auth.tenant_id),
        )
    )
    watchlist = result.scalar_one_or_none()
    if not watchlist:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    if not _can_manage(auth, watchlist):
        raise HTTPException(status_code=403, detail="Watchlist admin access required")
    tenant = await _tenant(db, auth.tenant_id)
    config = tenant_watchlist_config(tenant)
    if body.name is not None:
        watchlist.name = body.name.strip() or watchlist.name
    if body.description is not None:
        watchlist.description = body.description
    if body.active is not None:
        watchlist.active = body.active
    if body.expiry_hours is not None:
        watchlist.expiry_hours = normalize_watchlist_expiry(body.expiry_hours, tenant=tenant)
    if body.export_json is not None:
        watchlist.export_formats = {**(watchlist.export_formats or {}), "json": body.export_json}
    if body.export_stix is not None:
        watchlist.export_formats = {**(watchlist.export_formats or {}), "stix": body.export_stix}
    if body.export_misp is not None:
        watchlist.export_formats = {**(watchlist.export_formats or {}), "misp": body.export_misp}
    if body.export_csv is not None:
        watchlist.export_formats = {**(watchlist.export_formats or {}), "csv": body.export_csv}
    if body.public_slug is not None:
        watchlist.public_slug = normalize_watchlist_slug(body.public_slug) if body.public_slug else None
    if body.allow_unauthenticated is not None:
        watchlist.allow_unauthenticated = body.allow_unauthenticated
    items = list(watchlist.items or [])
    await db.flush()
    await db.refresh(
        watchlist,
        attribute_names=[
            "created_at",
            "updated_at",
            "name",
            "description",
            "active",
            "expiry_hours",
            "export_formats",
            "public_slug",
            "allow_unauthenticated",
        ],
    )
    return _watchlist_out(watchlist, items, tenant_config=config)


@router.delete("/watchlists/{watchlist_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_watchlist(
    watchlist_id: uuid.UUID,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    auth.require_scope(Scope.watch)
    result = await db.execute(select(Watchlist).where(Watchlist.id == watchlist_id, Watchlist.tenant_id == uuid.UUID(auth.tenant_id)))
    watchlist = result.scalar_one_or_none()
    if not watchlist:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    if not _can_manage(auth, watchlist):
        raise HTTPException(status_code=403, detail="Watchlist admin access required")
    await db.delete(watchlist)
    await db.flush()


def _serialise_export(watchlist: Watchlist, fmt: str) -> Response:
    rows = list(watchlist.items or [])
    if fmt == "json":
        return Response(content=json.dumps(_watchlist_out(watchlist, rows), default=str), media_type="application/json")
    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["watchlist_name", "scope", "ioc_kind", "ioc_value_display", "comment", "mode", "active", "sighting_count", "last_sighted_at"])
        for item in rows:
            writer.writerow([
                watchlist.name,
                watchlist.scope,
                item.ioc_kind,
                item.ioc_value_display,
                item.comment or "",
                item.mode,
                "yes" if item.active else "no",
                item.sighting_count,
                item.last_sighted_at.isoformat() if item.last_sighted_at else "",
            ])
        return Response(content=buf.getvalue(), media_type="text/csv")
    if fmt == "stix":
        bundle = {
            "type": "bundle",
            "id": f"bundle--{watchlist.id}",
            "objects": [
                {
                    "type": "indicator",
                    "id": f"indicator--{item.id}",
                    "name": item.ioc_value_display,
                    "description": item.comment or watchlist.name,
                    "pattern_type": "stix",
                    "pattern": f"[x-oca-asset:value = '{item.ioc_value_display}']",
                }
                for item in rows
            ],
        }
        return Response(content=json.dumps(bundle), media_type="application/stix+json")
    if fmt == "misp":
        event = {
            "Event": {
                "info": watchlist.name,
                "Tag": [{"name": "watchlist"}],
                "Attribute": [
                    {
                        "type": item.ioc_kind,
                        "value": item.ioc_value_display,
                        "comment": item.comment or watchlist.name,
                    }
                    for item in rows
                ],
            }
        }
        return Response(content=json.dumps(event), media_type="application/json")
    raise HTTPException(status_code=400, detail="Unsupported export format")


@router.get("/watchlists/{watchlist_id}/export/{fmt}")
async def export_watchlist(
    watchlist_id: uuid.UUID,
    fmt: str,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    auth.require_scope(Scope.watch)
    result = await db.execute(
        select(Watchlist).options(selectinload(Watchlist.items)).where(
            Watchlist.id == watchlist_id,
            Watchlist.tenant_id == uuid.UUID(auth.tenant_id),
        )
    )
    watchlist = result.scalar_one_or_none()
    if not watchlist:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    if not (watchlist.scope == "org" or (auth.user_id and str(watchlist.owner_user_id) == auth.user_id) or auth.has_scope(Scope.admin)):
        raise HTTPException(status_code=403, detail="Watchlist access denied")
    tenant = await _tenant(db, auth.tenant_id)
    config = tenant_watchlist_config(tenant)
    export_formats = watchlist_export_formats(watchlist, tenant_config=config)
    if not export_formats.get(fmt):
        raise HTTPException(status_code=403, detail="Export not enabled")
    return _serialise_export(watchlist, fmt)


@router.get("/watchlists/public/{public_slug}/export/{fmt}")
async def export_public_watchlist(
    public_slug: str,
    fmt: str,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Watchlist).options(selectinload(Watchlist.items)).where(
            Watchlist.public_slug == normalize_watchlist_slug(public_slug),
            Watchlist.allow_unauthenticated.is_(True),
            Watchlist.active.is_(True),
        )
    )
    watchlist = result.scalar_one_or_none()
    if not watchlist:
        raise HTTPException(status_code=404, detail="Watchlist not found")
    tenant = await _tenant(db, str(watchlist.tenant_id))
    config = tenant_watchlist_config(tenant)
    export_formats = watchlist_export_formats(watchlist, tenant_config=config)
    if not export_formats.get(fmt):
        raise HTTPException(status_code=403, detail="Export not enabled")
    return _serialise_export(watchlist, fmt)
