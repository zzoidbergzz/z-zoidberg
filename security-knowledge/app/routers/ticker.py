"""Ticker router — feed ticker data for the UI dashboard."""
from __future__ import annotations

import asyncio
import re
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AuthContext, require_read
from app.database import get_db
from app.integrations.necti_translator import translate_if_needed
from app.models.claims import Claim
from app.models.documents import ParsedDocument
from app.models.entities import Entity
from app.models.flags import FlaggedItem
from app.models.sources import SourceRecord

router = APIRouter(prefix="/ticker", tags=["ticker"])


class TickerItem(BaseModel):
    id: str
    title: str
    meta: str
    source: str
    url: str | None = None
    context: str | None = None
    source_url: str | None = None
    screenshot_url: str | None = None
    hover_text: str | None = None


_SCREENSHOT_NAME_RE = re.compile(r"^[0-9a-fA-F-]{36}\.png$")
_ARTIFACT_NAME_RE = re.compile(
    r"^[0-9a-fA-F-]{36}_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{12}\.[A-Za-z0-9]{1,8}$"
)
_SCREENSHOT_NAME_RE = re.compile(
    r"^[0-9a-fA-F-]{36}(?:_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8})?\.png$"
)


def _tor_screenshot_url(path_value: str | None) -> str | None:
    if not path_value:
        return None
    filename = Path(path_value).name
    if not _SCREENSHOT_NAME_RE.match(filename):
        return None
    return f"/api/v1/claims/tor-screenshot/{filename}"


def _tor_artifact_url(filename: str, *, download: bool = False) -> str | None:
    if not _ARTIFACT_NAME_RE.match(filename):
        return None
    suffix = "?download=1" if download else ""
    return f"/api/v1/claims/tor-artifact/{filename}{suffix}"


def _victim_names(value: dict) -> list[str]:
    deterministic = value.get("deterministic", {}) or {}
    ai = value.get("ai_enrichment", {}) or {}
    names: list[str] = []
    for item in deterministic.get("victims", []) or []:
        if isinstance(item, str) and item.strip():
            names.append(item.strip())
    for item in ai.get("victims", []) or []:
        if isinstance(item, str) and item.strip():
            names.append(item.strip())
            continue
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            if name:
                names.append(name)
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        key = n.casefold()
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out


def _source_display_name(source_url: str | None, source: SourceRecord | None) -> str:
    if source and source.title:
        return source.title
    if source_url:
        host = urlparse(source_url).netloc or source_url
        return host.replace(".onion", "")
    return "Unknown actor"


def _onion_view_url(url: str | None) -> str | None:
    if not url:
        return None
    host = urlparse(url).netloc or url
    if ".onion" not in host.lower():
        return None
    return f"/onion/view?url={quote(url)}"


class FlaggedItemOut(BaseModel):
    id: uuid.UUID
    source_type: str
    title: str
    body: str | None
    url: str | None
    flagged_at: datetime
    acked_by: str | None
    acked_at: datetime | None

    model_config = {"from_attributes": True}


class FlagBody(BaseModel):
    source_type: str  # trend, news, breach
    title: str
    body: str | None = None
    url: str | None = None
    external_id: str | None = None  # dedup key


class AckBody(BaseModel):
    acked_by: str = "anonymous"


class BreachArtifactOut(BaseModel):
    filename: str
    content_type: str
    size_bytes: int | None = None
    sha256: str | None = None
    source_url: str | None = None
    view_url: str | None = None
    download_url: str | None = None


class BreachSummaryOut(BaseModel):
    claim_id: uuid.UUID
    victim_name: str
    victim_profile_url: str
    actor_name: str
    actor_profile_url: str
    source_url: str
    source_analysis_url: str | None = None
    scraped_at: str | None = None
    screenshot_url: str | None = None
    leaked_evidence: list[BreachArtifactOut]
    mentions: list[str]


# ── Ticker endpoints ──────────────────────────────────────────────────────────

@router.get("/trends", response_model=list[TickerItem])
async def ticker_trends(
    limit: int = Query(10, le=50),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Locally observed trends: recent entity clusters with high claim activity."""
    since = datetime.now(UTC) - timedelta(days=7)
    stmt = (
        select(
            Entity.canonical_name,
            Entity.kind,
            func.count(Claim.id).label("claim_count"),
            func.max(Claim.created_at).label("latest"),
        )
        .join(Claim, Claim.entity_id == Entity.id)
        .where(Claim.tenant_id == auth.tenant_id, Claim.created_at >= since)
        .group_by(Entity.id, Entity.canonical_name, Entity.kind)
        .order_by(func.count(Claim.id).desc())
        .limit(limit)
    )
    rows = (await db.execute(stmt)).all()
    items = []
    for name, kind, count, latest in rows:
        ago = _human_ago(latest)
        items.append(TickerItem(
            id=f"trend-{kind}-{name[:30]}",
            title=f"{name} — {count} recent claims",
            meta=f"{kind} · {ago}",
            source="trends",
            url=f"/entities?q={name}",
        ))
    return items


@router.get("/news", response_model=list[TickerItem])
async def ticker_news(
    limit: int = Query(10, le=50),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Recent cyber security news from ingested documents."""
    since = datetime.now(UTC) - timedelta(hours=48)
    stmt = (
        select(ParsedDocument)
        .where(
            ParsedDocument.tenant_id == auth.tenant_id,
            ParsedDocument.created_at >= since,
        )
        .order_by(ParsedDocument.created_at.desc())
        .limit(limit)
    )
    docs = (await db.execute(stmt)).scalars().all()
    async def _build_item(doc: ParsedDocument) -> TickerItem:
        title = (doc.title or doc.url or "Untitled").strip()[:200]
        hover_text = None
        tr = await translate_if_needed(title)
        if tr.get("was_translated"):
            translated = str(tr.get("translated_text", title)).strip() or title
            original = str(tr.get("original_text", title)).strip() or title
            source_lang = str(tr.get("source_language", "unknown"))
            method = str(tr.get("method", "translator_api_mcp"))
            title = f"[*] {translated[:100]}"
            hover_text = (
                f"Original ({source_lang}): {original[:220]}\n"
                f"Translated (EN): {translated[:220]}\n"
                f"via translator API/MCP ({method})"
            )
        else:
            title = title[:100]
        ago = _human_ago(doc.created_at)
        return TickerItem(
            id=f"news-{doc.id}",
            title=title,
            meta=f"{'feed' if doc.source_id else 'ingest'} · {ago}",
            source="news",
            url=doc.url,
            hover_text=hover_text,
        )

    items = await asyncio.gather(*[_build_item(doc) for doc in docs])
    return items


@router.get("/breaches", response_model=list[TickerItem])
async def ticker_breaches(
    limit: int = Query(10, le=50),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Recent victim rows from tor leak-site findings."""
    since = datetime.now(UTC) - timedelta(days=7)
    stmt = (
        select(Claim)
        .where(
            Claim.tenant_id == auth.tenant_id,
            Claim.created_at >= since,
            Claim.claim_type == "tor_site_findings",
        )
        .order_by(Claim.created_at.desc())
        .limit(max(limit * 5, 50))
    )
    claims = (await db.execute(stmt)).scalars().all()

    source_urls = {
        str(v.get("source_url", "")).strip()
        for c in claims
        for v in [c.value if isinstance(c.value, dict) else {}]
        if str(v.get("source_url", "")).strip()
    }
    source_rows = (
        await db.execute(
            select(SourceRecord).where(
                SourceRecord.tenant_id == auth.tenant_id,
                SourceRecord.url.in_(list(source_urls)),
            )
        )
    ).scalars().all()
    source_map = {s.url: s for s in source_rows}

    items = []
    for claim in claims:
        value = claim.value if isinstance(claim.value, dict) else {}
        source_url = str(value.get("source_url", "")).strip()
        source = source_map.get(source_url)
        actor_name = _source_display_name(source_url, source)
        victims = _victim_names(value)
        deterministic = value.get("deterministic", {}) or {}
        artifacts = value.get("artifact_files", []) or []
        summary_bits: list[str] = []
        if deterministic.get("payment_addresses"):
            summary_bits.append(f"{len(deterministic.get('payment_addresses', []))} wallets")
        if deterministic.get("binaries"):
            summary_bits.append(f"{len(deterministic.get('binaries', []))} binaries")
        if artifacts:
            summary_bits.append(f"{len(artifacts)} cached files")
        context = " · ".join(summary_bits) if summary_bits else None
        screenshot_url = _tor_screenshot_url(value.get("screenshot_path"))
        ago = _human_ago(claim.created_at)

        for idx, victim in enumerate(victims):
            items.append(
                TickerItem(
                    id=f"breach-{claim.id}-{idx}",
                    title=victim,
                    meta=f"{actor_name} · {ago}",
                    source="breaches",
                    url=f"/breaches/{claim.id}?victim={quote(victim)}",
                    context=context,
                    source_url=source_url or None,
                    screenshot_url=screenshot_url,
                )
            )
            if len(items) >= limit:
                return items

    # Fallback: keep tile non-empty even when victim names are absent.
    if not items:
        for claim in claims[:limit]:
            value = claim.value if isinstance(claim.value, dict) else {}
            source_url = str(value.get("source_url", "")).strip()
            source = source_map.get(source_url)
            actor_name = _source_display_name(source_url, source)
            items.append(
                TickerItem(
                    id=f"breach-source-{claim.id}",
                    title=actor_name,
                    meta=f"leak-site activity · {_human_ago(claim.created_at)}",
                    source="breaches",
                    url=f"/breaches/{claim.id}",
                    source_url=source_url or None,
                    screenshot_url=_tor_screenshot_url(value.get("screenshot_path")),
                )
            )
            if len(items) >= limit:
                break
    return items


@router.get("/breaches/{claim_id}/summary", response_model=BreachSummaryOut)
async def breach_summary(
    claim_id: uuid.UUID,
    victim: str | None = None,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    claim = (
        await db.execute(
            select(Claim).where(
                Claim.id == claim_id,
                Claim.tenant_id == auth.tenant_id,
                Claim.claim_type == "tor_site_findings",
            )
        )
    ).scalar_one_or_none()
    if claim is None:
        from fastapi import HTTPException
        raise HTTPException(404, "Breach summary not found")

    value = claim.value if isinstance(claim.value, dict) else {}
    source_url = str(value.get("source_url", "")).strip()
    source = (
        await db.execute(
            select(SourceRecord).where(
                SourceRecord.tenant_id == auth.tenant_id,
                SourceRecord.url == source_url,
            ).limit(1)
        )
    ).scalar_one_or_none()
    actor_name = _source_display_name(source_url, source)

    victims = _victim_names(value)
    victim_name = victim if victim and victim.strip() else (victims[0] if victims else "Unknown victim")
    ai = value.get("ai_enrichment", {}) or {}
    deterministic = value.get("deterministic", {}) or {}
    mentions = []
    for bucket in ("binaries", "payment_addresses", "payment_urls", "emails", "domains"):
        vals = deterministic.get(bucket, []) or []
        mentions.extend([str(v) for v in vals if str(v).strip()])
    for entry in ai.get("other_extractions", []) or []:
        if isinstance(entry, dict):
            t = str(entry.get("type", "")).strip()
            v = str(entry.get("value", "")).strip()
            if t or v:
                mentions.append(f"{t}: {v}".strip(": "))
    mentions = list(dict.fromkeys(mentions))[:40]

    leaked_evidence: list[BreachArtifactOut] = []
    for artifact in value.get("artifact_files", []) or []:
        if not isinstance(artifact, dict):
            continue
        filename = str(artifact.get("filename", "")).strip()
        if not filename:
            continue
        leaked_evidence.append(
            BreachArtifactOut(
                filename=filename,
                content_type=str(artifact.get("content_type", "")).strip() or "application/octet-stream",
                size_bytes=artifact.get("size_bytes"),
                sha256=str(artifact.get("sha256", "")).strip() or None,
                source_url=str(artifact.get("original_url", "")).strip() or None,
                view_url=_tor_artifact_url(filename, download=False),
                download_url=_tor_artifact_url(filename, download=True),
            )
        )

    return BreachSummaryOut(
        claim_id=claim.id,
        victim_name=victim_name,
        victim_profile_url=f"/entities?q={quote(victim_name)}",
        actor_name=actor_name,
        actor_profile_url=f"/entities?q={quote(actor_name)}",
        source_url=source_url,
        source_analysis_url=_onion_view_url(source_url),
        scraped_at=value.get("scraped_at"),
        screenshot_url=_tor_screenshot_url(value.get("screenshot_path")),
        leaked_evidence=leaked_evidence,
        mentions=mentions,
    )


# ── Flag endpoints ─────────────────────────────────────────────────────────────

@router.post("/flag", response_model=FlaggedItemOut, status_code=201)
async def create_flag(
    body: FlagBody,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Flag a ticker item for follow-up."""
    # Dedup by external_id
    if body.external_id:
        existing = await db.execute(
            select(FlaggedItem).where(
                FlaggedItem.tenant_id == auth.tenant_id,
                FlaggedItem.external_id == body.external_id,
            )
        )
        if existing.scalar_one_or_none():
            return existing.scalar_one()

    item = FlaggedItem(
        tenant_id=auth.tenant_id,
        user_id=auth.user_id if hasattr(auth, "user_id") else None,
        source_type=body.source_type,
        title=body.title,
        body=body.body,
        url=body.url,
        external_id=body.external_id,
        flagged_at=datetime.now(UTC),
    )
    db.add(item)
    await db.commit()
    await db.refresh(item)
    return item


@router.get("/flags", response_model=list[FlaggedItemOut])
async def list_flags(
    period: str = Query("today", enum=["today", "yesterday", "week", "lastweek", "30d", "all"]),
    source_type: str | None = None,
    limit: int = Query(100, le=500),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """List flagged items with time-period filtering."""
    since = _period_start(period)
    stmt = select(FlaggedItem).where(
        FlaggedItem.tenant_id == auth.tenant_id,
        FlaggedItem.flagged_at >= since,
    )
    if source_type:
        stmt = stmt.where(FlaggedItem.source_type == source_type)
    stmt = stmt.order_by(FlaggedItem.flagged_at.desc()).limit(limit)
    return (await db.execute(stmt)).scalars().all()


@router.post("/flag/{item_id}/ack", response_model=FlaggedItemOut)
async def ack_flag(
    item_id: uuid.UUID,
    body: AckBody,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """ACK a flagged item as reviewed/completed."""
    item = await db.get(FlaggedItem, item_id)
    if not item or str(item.tenant_id) != str(auth.tenant_id):
        from fastapi import HTTPException
        raise HTTPException(404, "Flagged item not found")
    item.acked_by = body.acked_by
    item.acked_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(item)
    return item


@router.delete("/flag/{item_id}", status_code=204)
async def delete_flag(
    item_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(require_read),
):
    """Remove a flag."""
    item = await db.get(FlaggedItem, item_id)
    if not item or str(item.tenant_id) != str(auth.tenant_id):
        from fastapi import HTTPException
        raise HTTPException(404, "Flagged item not found")
    await db.delete(item)
    await db.commit()


# ── Helpers ────────────────────────────────────────────────────────────────────

def _human_ago(dt: datetime | None) -> str:
    if not dt:
        return "unknown"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    diff = datetime.now(UTC) - dt
    if diff.total_seconds() < 60:
        return "just now"
    if diff.total_seconds() < 3600:
        return f"{int(diff.total_seconds() / 60)}m ago"
    if diff.total_seconds() < 86400:
        return f"{int(diff.total_seconds() / 3600)}h ago"
    return f"{int(diff.total_seconds() / 86400)}d ago"


def _period_start(period: str) -> datetime:
    now = datetime.now(UTC)
    if period == "today":
        return now.replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "yesterday":
        return (now - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "week":
        return (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "lastweek":
        return (now - timedelta(days=now.weekday() + 7)).replace(hour=0, minute=0, second=0, microsecond=0)
    if period == "30d":
        return now - timedelta(days=30)
    # "all"
    return datetime(2000, 1, 1, tzinfo=UTC)
