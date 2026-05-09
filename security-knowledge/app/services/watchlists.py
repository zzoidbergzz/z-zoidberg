"""Watchlist helper functions."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.auth import Tenant
from app.models.watchlists import Watchlist

DEFAULT_WATCHLIST_NAME = "My watchlist"
DEFAULT_ORG_WATCHLIST_NAME = "Org watchlist"
DEFAULT_WATCHLIST_SCOPE = "personal"
DEFAULT_WATCHLIST_EXPIRY_HOURS = 18 * 30 * 24
MAX_WATCHLIST_EXPIRY_HOURS = 18 * 30 * 24
DEFAULT_WATCHLIST_EXPORT_FORMATS = {"json": True, "stix": True, "misp": True, "csv": True}


def tenant_watchlist_config(tenant: Tenant | None) -> dict:
    config = dict(getattr(tenant, "watchlist_settings", None) or {})
    config.setdefault("scope_mode", "both")
    config.setdefault("default_expiry_hours", DEFAULT_WATCHLIST_EXPIRY_HOURS)
    config.setdefault("max_expiry_hours", MAX_WATCHLIST_EXPIRY_HOURS)
    export_formats = dict(DEFAULT_WATCHLIST_EXPORT_FORMATS)
    export_formats.update(config.get("export_formats") or {})
    config["export_formats"] = export_formats
    return config


def watchlist_export_formats(watchlist: Watchlist, *, tenant_config: dict | None = None) -> dict:
    config = tenant_config or {}
    tenant_formats = dict((config.get("export_formats") or DEFAULT_WATCHLIST_EXPORT_FORMATS))
    watchlist_formats = dict(getattr(watchlist, "export_formats", None) or {})
    if not watchlist_formats:
        watchlist_formats = dict(tenant_formats)
    else:
        for fmt, enabled in tenant_formats.items():
            watchlist_formats.setdefault(fmt, enabled)
    return {
        fmt: bool(watchlist_formats.get(fmt)) and bool(tenant_formats.get(fmt, False))
        for fmt in tenant_formats
    }


def normalize_watchlist_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.strip().lower()).strip("-")
    if not slug:
        raise ValueError("public_slug is required")
    return slug


def normalize_watchlist_expiry(expiry_hours: int | None, *, tenant: Tenant | None = None) -> int:
    config = tenant_watchlist_config(tenant)
    max_hours = int(config.get("max_expiry_hours") or MAX_WATCHLIST_EXPIRY_HOURS)
    if expiry_hours is None:
        return int(config.get("default_expiry_hours") or DEFAULT_WATCHLIST_EXPIRY_HOURS)
    if expiry_hours == 0:
        return 0
    if expiry_hours < 0:
        raise ValueError("expiry_hours must be >= 0")
    return min(int(expiry_hours), max_hours)


def _watchlist_expiry_hours(watchlist: Watchlist) -> int | None:
    expiry_hours = getattr(watchlist, "expiry_hours", None)
    try:
        expiry_hours = int(expiry_hours)
    except (TypeError, ValueError):
        return None
    return expiry_hours


def watchlist_expires_at(watchlist: Watchlist) -> datetime | None:
    expiry_hours = _watchlist_expiry_hours(watchlist)
    created_at = getattr(watchlist, "created_at", None)
    if expiry_hours is None or not isinstance(created_at, datetime):
        return None
    if expiry_hours == 0:
        return None
    return created_at + timedelta(hours=expiry_hours)


def watchlist_is_expired(watchlist: Watchlist, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    expires_at = watchlist_expires_at(watchlist)
    return bool(expires_at and expires_at < now)


async def get_or_create_default_personal_watchlist(
    db: AsyncSession,
    *,
    tenant: Tenant | None,
    tenant_id,
    user_id,
    scope_mode: str | None = None,
) -> Watchlist:
    if scope_mode == "org":
        name = DEFAULT_ORG_WATCHLIST_NAME
        scope = "org"
        owner = None
    else:
        name = DEFAULT_WATCHLIST_NAME
        scope = DEFAULT_WATCHLIST_SCOPE
        owner = user_id
    result = await db.execute(
        select(Watchlist).where(
            Watchlist.tenant_id == tenant_id,
            Watchlist.owner_user_id == owner,
            Watchlist.scope == scope,
            Watchlist.name == name,
        )
    )
    watchlist = result.scalar_one_or_none()
    if watchlist:
        return watchlist
    config = tenant_watchlist_config(tenant)
    watchlist = Watchlist(
        tenant_id=tenant_id,
        owner_user_id=owner,
        created_by_user_id=user_id,
        name=name,
        scope=scope,
        expiry_hours=normalize_watchlist_expiry(None, tenant=tenant),
        export_formats=dict(config.get("export_formats") or {}),
        active=True,
    )
    db.add(watchlist)
    await db.flush()
    return watchlist


async def get_or_create_default_org_watchlist(
    db: AsyncSession,
    *,
    tenant: Tenant | None,
    tenant_id,
    user_id,
) -> Watchlist:
    result = await db.execute(
        select(Watchlist).where(
            Watchlist.tenant_id == tenant_id,
            Watchlist.owner_user_id.is_(None),
            Watchlist.scope == "org",
            Watchlist.name == DEFAULT_ORG_WATCHLIST_NAME,
        )
    )
    watchlist = result.scalar_one_or_none()
    if watchlist:
        return watchlist
    config = tenant_watchlist_config(tenant)
    watchlist = Watchlist(
        tenant_id=tenant_id,
        owner_user_id=None,
        created_by_user_id=user_id,
        name=DEFAULT_ORG_WATCHLIST_NAME,
        scope="org",
        expiry_hours=normalize_watchlist_expiry(None, tenant=tenant),
        export_formats=dict(config.get("export_formats") or {}),
        active=True,
    )
    db.add(watchlist)
    await db.flush()
    return watchlist


def watchlist_export_path(watchlist_id: str, fmt: str) -> str:
    return f"/api/v1/watchlists/{watchlist_id}/export/{fmt}"


def watchlist_public_export_path(public_slug: str, fmt: str) -> str:
    return f"/api/v1/watchlists/public/{public_slug}/export/{fmt}"
