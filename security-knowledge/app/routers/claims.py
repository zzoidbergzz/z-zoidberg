import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AuthContext, require_read, require_write
from app.database import get_db
from app.models.claims import Claim
from app.models.documents import DocumentSection, ParsedDocument

router = APIRouter(prefix="/claims", tags=["claims"])
_TOR_SCREENSHOT_DIR = Path(__file__).resolve().parents[2] / "data" / "tor_screenshots"
_TOR_ARTIFACT_DIR = Path(__file__).resolve().parents[2] / "data" / "tor_artifacts"
_SCREENSHOT_NAME_RE = re.compile(
    r"^[0-9a-fA-F-]{36}(?:_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{8})?\.png$"
)
_ARTIFACT_NAME_RE = re.compile(
    r"^[0-9a-fA-F-]{36}_[0-9]{8}T[0-9]{6}Z_[0-9a-f]{12}\.[A-Za-z0-9]{1,8}$"
)


class ClaimCreate(BaseModel):
    statement: str
    claim_type: str = "general"
    confidence: float = 0.5
    subject: str | None = None
    predicate: str | None = None
    object: str | None = None


class ClaimOut(BaseModel):
    id: uuid.UUID
    statement: str
    claim_type: str
    confidence: float
    tenant_id: uuid.UUID
    entity_id: uuid.UUID | None = None
    source_url: str | None = None
    model_config = {"from_attributes": True}


def _claim_statement(claim: Claim) -> str:
    value = claim.value if isinstance(claim.value, dict) else {}
    for key in ("assertion", "statement", "title"):
        text = value.get(key)
        if isinstance(text, str) and text.strip():
            return text.strip()
    subject = value.get("subject")
    predicate = value.get("predicate")
    object_ = value.get("object")
    if all(isinstance(x, str) and x.strip() for x in (subject, predicate, object_)):
        return f"{subject.strip()} {predicate.strip()} {object_.strip()}"
    return ""


def _tenant_id(auth: AuthContext | dict) -> str:
    if isinstance(auth, dict):
        return str(auth["tenant_id"])
    return str(auth.tenant_id)


@router.get("/", response_model=list[ClaimOut])
async def list_claims(
    limit: int = Query(20, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_read),
):
    q = (
        select(Claim)
        .where(Claim.tenant_id == _tenant_id(auth))
        .order_by(Claim.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    result = await db.execute(q)
    claims = result.scalars().all()
    return [
        {
            "id": claim.id,
            "statement": _claim_statement(claim),
            "claim_type": claim.claim_type,
            "confidence": claim.confidence,
            "tenant_id": claim.tenant_id,
            "entity_id": claim.entity_id,
            "source_url": (claim.value or {}).get("source_url") if isinstance(claim.value, dict) else None,
        }
        for claim in claims
    ]


@router.post("/", response_model=ClaimOut, status_code=201)
async def create_claim(
    body: ClaimCreate,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_write),
):
    # Build statement from subject/predicate/object if provided
    statement = body.statement
    if body.subject and body.predicate and body.object:
        statement = f"{body.subject} {body.predicate} {body.object}"
    value: dict[str, Any] = {"assertion": statement}
    if body.subject:
        value["subject"] = body.subject
    if body.predicate:
        value["predicate"] = body.predicate
    if body.object:
        value["object"] = body.object
    claim = Claim(
        tenant_id=_tenant_id(auth),
        claim_type=body.claim_type,
        value=value,
        confidence=body.confidence,
    )
    db.add(claim)
    await db.flush()
    await db.refresh(claim)
    return {
        "id": claim.id,
        "statement": statement,
        "claim_type": claim.claim_type,
        "confidence": claim.confidence,
        "tenant_id": claim.tenant_id,
    }


class ClaimDetailOut(BaseModel):
    id: uuid.UUID
    entity_id: uuid.UUID | None = None
    claim_type: str
    value: dict = {}
    confidence: float
    status: str
    created_at: datetime | None = None
    model_config = {"from_attributes": True}


class TorContextOut(BaseModel):
    id: uuid.UUID
    source_url: str
    onion_view_url: str | None = None
    scraped_at: Any | None = None
    screenshot_url: str | None = None
    deterministic: dict = {}
    ai_enrichment: dict = {}
    artifact_files: list[dict] = []
    created_at: datetime | None = None


def _source_url_from_value(value: Any) -> str | None:
    if not isinstance(value, dict):
        return None
    source_url = value.get("source_url")
    if not isinstance(source_url, str):
        return None
    source_url = source_url.strip()
    return source_url or None


def _tor_screenshot_url(path_value: Any) -> str | None:
    if not isinstance(path_value, str) or not path_value.strip():
        return None
    filename = Path(path_value).name
    if not _SCREENSHOT_NAME_RE.match(filename):
        return None
    return f"/api/v1/claims/tor-screenshot/{filename}"


def _tor_artifact_urls(artifact: Any) -> dict[str, Any]:
    if not isinstance(artifact, dict):
        return {}
    filename = str(artifact.get("filename", "")).strip()
    if not _ARTIFACT_NAME_RE.match(filename):
        return dict(artifact)
    out = dict(artifact)
    out["view_url"] = f"/api/v1/claims/tor-artifact/{filename}"
    out["download_url"] = f"/api/v1/claims/tor-artifact/{filename}?download=1"
    return out


def _is_onion_url(value: str | None) -> bool:
    if not value:
        return False
    host = urlparse(value).netloc or value
    return ".onion" in host.lower()


def _onion_view_url(source_url: str | None) -> str | None:
    if not _is_onion_url(source_url):
        return None
    return f"/onion/view?url={quote(source_url or '')}"


class OnionContextOut(BaseModel):
    claim_id: uuid.UUID
    source_url: str
    onion_view_url: str
    scraped_at: Any | None = None
    screenshot_url: str | None = None
    deterministic: dict = {}
    ai_enrichment: dict = {}
    artifact_files: list[dict] = []
    raw_text: str | None = None
    created_at: datetime | None = None


@router.get("/tor-screenshot/{filename}")
async def get_tor_screenshot(filename: str):
    if not _SCREENSHOT_NAME_RE.match(filename):
        raise HTTPException(status_code=404, detail="Screenshot not found")
    path = _TOR_SCREENSHOT_DIR / filename
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Screenshot not found")
    return FileResponse(path, media_type="image/png")


@router.get("/tor-artifact/{filename}")
async def get_tor_artifact(filename: str, download: bool = Query(False)):
    if not _ARTIFACT_NAME_RE.match(filename):
        raise HTTPException(status_code=404, detail="Artifact not found")
    path = _TOR_ARTIFACT_DIR / filename
    if not path.exists() or not path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    media_type = "application/octet-stream"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'} if download else None
    return FileResponse(path, media_type=media_type, filename=filename if download else None, headers=headers)


@router.get("/onion/context", response_model=OnionContextOut)
async def get_onion_context(
    url: str = Query(..., min_length=8),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_read),
):
    source_url = url.strip()
    if not _is_onion_url(source_url):
        raise HTTPException(status_code=400, detail="Only onion URLs are supported")

    tenant_id = _tenant_id(auth)
    claim = (
        await db.execute(
            select(Claim).where(
                Claim.tenant_id == tenant_id,
                Claim.claim_type == "tor_site_findings",
                Claim.value["source_url"].astext == source_url,
            ).order_by(Claim.created_at.desc()).limit(1)
        )
    ).scalar_one_or_none()
    if claim is None:
        raise HTTPException(status_code=404, detail="No onion context found")

    value = claim.value if isinstance(claim.value, dict) else {}
    artifacts = [_tor_artifact_urls(a) for a in (value.get("artifact_files", []) or [])]
    raw_text = str(value.get("raw_text_excerpt", "")).strip() or None

    if not raw_text:
        doc = (
            await db.execute(
                select(ParsedDocument)
                .where(
                    ParsedDocument.tenant_id == tenant_id,
                    ParsedDocument.url == source_url,
                )
                .order_by(ParsedDocument.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        if doc is not None:
            sections = (
                await db.execute(
                    select(DocumentSection)
                    .where(DocumentSection.document_id == doc.id)
                    .order_by(DocumentSection.section_index.asc())
                    .limit(6)
                )
            ).scalars().all()
            if sections:
                raw_text = "\n\n".join(s.content or "" for s in sections).strip()
                raw_text = raw_text[:12000] if raw_text else None

    onion_view_url = _onion_view_url(source_url)
    if onion_view_url is None:
        raise HTTPException(status_code=400, detail="Only onion URLs are supported")
    return OnionContextOut(
        claim_id=claim.id,
        source_url=source_url,
        onion_view_url=onion_view_url,
        scraped_at=value.get("scraped_at"),
        screenshot_url=_tor_screenshot_url(value.get("screenshot_path")),
        deterministic=value.get("deterministic", {}) or {},
        ai_enrichment=value.get("ai_enrichment", {}) or {},
        artifact_files=artifacts,
        raw_text=raw_text,
        created_at=claim.created_at,
    )


@router.get("/entity/{entity_id}/tor-context", response_model=list[TorContextOut])
async def list_entity_tor_context(
    entity_id: uuid.UUID,
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_read),
):
    tenant_id = _tenant_id(auth)
    source_rows = await db.execute(
        select(Claim.value).where(
            Claim.entity_id == entity_id,
            Claim.tenant_id == tenant_id,
        ).order_by(Claim.created_at.desc()).limit(200)
    )
    source_urls = {
        url for url in (_source_url_from_value(row[0]) for row in source_rows.all()) if url
    }

    filters = [Claim.entity_id == entity_id]
    if source_urls:
        filters.append(Claim.value["source_url"].astext.in_(list(source_urls)))
    q = (
        select(Claim)
        .where(
            Claim.tenant_id == tenant_id,
            Claim.claim_type == "tor_site_findings",
            or_(*filters),
        )
        .order_by(Claim.created_at.desc())
        .limit(limit)
    )
    rows = (await db.execute(q)).scalars().all()
    out: list[dict[str, Any]] = []
    for claim in rows:
        value = claim.value if isinstance(claim.value, dict) else {}
        artifacts = [_tor_artifact_urls(a) for a in (value.get("artifact_files", []) or [])]
        out.append(
            {
                "id": claim.id,
                "source_url": value.get("source_url", ""),
                "scraped_at": value.get("scraped_at"),
                "screenshot_url": _tor_screenshot_url(value.get("screenshot_path")),
                "deterministic": value.get("deterministic", {}) or {},
                "ai_enrichment": value.get("ai_enrichment", {}) or {},
                "artifact_files": artifacts,
                "onion_view_url": _onion_view_url(value.get("source_url")),
                "created_at": claim.created_at,
            }
        )
    return out


@router.get("/entity/{entity_id}", response_model=list[ClaimDetailOut])
async def list_entity_claims(
    entity_id: uuid.UUID,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_read),
):
    tenant_id = _tenant_id(auth)
    q = select(Claim).where(
        Claim.entity_id == entity_id,
        Claim.tenant_id == tenant_id,
    ).order_by(Claim.created_at.desc()).limit(limit)
    direct = (await db.execute(q)).scalars().all()

    source_urls = {
        url for url in (_source_url_from_value(c.value) for c in direct) if url
    }
    if not source_urls:
        return direct

    related_q = (
        select(Claim)
        .where(
            Claim.tenant_id == tenant_id,
            Claim.claim_type == "tor_site_findings",
            Claim.value["source_url"].astext.in_(list(source_urls)),
        )
        .order_by(Claim.created_at.desc())
        .limit(limit)
    )
    related = (await db.execute(related_q)).scalars().all()
    seen: set[uuid.UUID] = set()
    merged: list[Claim] = []
    for claim in [*direct, *related]:
        if claim.id in seen:
            continue
        seen.add(claim.id)
        merged.append(claim)
    return merged[:limit]
