from __future__ import annotations
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_auth, AuthContext, Scope
from app.database import get_db
from app.enrichment.registry import list_providers
from app.enrichment.service import EnrichmentService
from app.lookup.classifier import classify_input
from app.lookup.diffing import diff_payload
from app.models.enrichment import EnrichmentCache, EnrichmentDiff
from app.models.entities import Entity
from app.models.relationships import Relationship
from app.pivot.graph import shortest_path

router = APIRouter(tags=["lookup"])

# Minimum seconds between automatic enrichment dispatches for the same entity+tenant
_DISPATCH_DEBOUNCE_SECONDS = 300


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------

class LookupRequest(BaseModel):
    query: str
    force_repoll: bool = False
    investigation_id: Optional[str] = None


class BulkLookupRequest(BaseModel):
    queries: list[str]
    investigation_id: Optional[str] = None


class TagRequest(BaseModel):
    tags: list[str]


class NoteRequest(BaseModel):
    note: str


class InvestigationCreate(BaseModel):
    name: str
    description: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Map classifier type → EntityKind value
_KIND_MAP: dict[str, str] = {
    "ip": "ip_address",
    "cidr": "ip_address",
    "domain": "domain",
    "url": "url",
    "email": "email",
    "sha256": "hash",
    "sha1": "hash",
    "md5": "hash",
    "asn": "asn",
    "phone": "other",
    "username": "other",
    "unknown": "indicator",
    "empty": "indicator",
}


async def _upsert_entity(db: AsyncSession, tenant_id: str, kind: str, canonical_name: str) -> Entity:
    result = await db.execute(
        select(Entity).where(
            Entity.tenant_id == uuid.UUID(tenant_id),
            Entity.kind == kind,
            Entity.canonical_name == canonical_name,
        )
    )
    entity = result.scalar_one_or_none()
    if entity is None:
        entity = Entity(
            tenant_id=uuid.UUID(tenant_id),
            kind=kind,
            canonical_name=canonical_name,
            external_refs={},
        )
        db.add(entity)
        await db.flush()
    return entity


async def _should_dispatch(db: AsyncSession, entity_id: str, tenant_id: str, force: bool) -> bool:
    if force:
        return True
    row = await db.execute(
        text("SELECT last_dispatch_at FROM entity_lookup_state WHERE entity_id = :eid AND tenant_id = :tid"),
        {"eid": entity_id, "tid": tenant_id},
    )
    rec = row.mappings().one_or_none()
    if rec is None or rec["last_dispatch_at"] is None:
        return True
    elapsed = (datetime.now(timezone.utc) - rec["last_dispatch_at"]).total_seconds()
    return elapsed > _DISPATCH_DEBOUNCE_SECONDS


async def _record_dispatch(db: AsyncSession, entity_id: str, tenant_id: str, force: bool) -> None:
    now = datetime.now(timezone.utc)
    extra = ", last_force_repoll_at = :now" if force else ""
    await db.execute(
        text(f"""
            INSERT INTO entity_lookup_state (entity_id, tenant_id, last_dispatch_at{', last_force_repoll_at' if force else ''})
            VALUES (:eid, :tid, :now{', :now' if force else ''})
            ON CONFLICT (entity_id, tenant_id) DO UPDATE
            SET last_dispatch_at = :now{extra}
        """),
        {"eid": entity_id, "tid": tenant_id, "now": now},
    )


async def _dispatch_enrichment(entity: Entity, tenant_id: str, force: bool, db: AsyncSession, user_id: str | None = None) -> None:
    """Run enrichment for all registered providers (background-safe, opens own session)."""
    from app.database import AsyncSessionLocal  # avoid circular at module level

    async with AsyncSessionLocal() as bg_db:
        svc = EnrichmentService(bg_db, tenant_id, user_id=user_id)
        for provider_name in list_providers():
            try:
                await svc.enrich(provider_name, entity.kind, entity.canonical_name)
            except Exception:
                pass
        await bg_db.commit()


async def _get_enrichment_results(db: AsyncSession, tenant_id: str, entity_kind: str, entity_value: str) -> list[dict]:
    result = await db.execute(
        select(EnrichmentCache).where(
            EnrichmentCache.tenant_id == uuid.UUID(tenant_id),
            EnrichmentCache.entity_kind == entity_kind,
            EnrichmentCache.entity_value == entity_value,
        )
    )
    rows = result.scalars().all()
    now = datetime.now(timezone.utc)
    out = []
    for row in rows:
        expired = row.expires_at is not None and row.expires_at < now
        out.append({
            # JS renderResults() expects these field names:
            "source": row.provider,
            "data": row.normalized,
            "query_duration_ms": None,
            # additional metadata
            "provider": row.provider,
            "success": row.success,
            "cached_at": row.created_at.isoformat() if row.created_at else None,
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "expired": expired,
        })
    return out


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/lookup")
async def lookup(
    body: LookupRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    auth.require_scope(Scope.read)
    classified = classify_input(body.query)
    if classified["type"] in ("empty",):
        raise HTTPException(status_code=400, detail="Empty or unclassifiable query")

    kind = _KIND_MAP.get(classified["type"], "indicator")
    canonical = classified["value"]

    entity = await _upsert_entity(db, auth.tenant_id, kind, canonical)
    await db.commit()

    should_dispatch = await _should_dispatch(db, str(entity.id), auth.tenant_id, body.force_repoll)
    if should_dispatch:
        # Record the dispatch BEFORE queuing the background task so any concurrent
        # request for the same entity sees it and skips the double-dispatch.
        await _record_dispatch(db, str(entity.id), auth.tenant_id, body.force_repoll)
        await db.commit()
        background_tasks.add_task(_dispatch_enrichment, entity, auth.tenant_id, body.force_repoll, db, auth.user_id)

    if body.investigation_id:
        await _add_entity_to_investigation(db, body.investigation_id, str(entity.id), auth.tenant_id, auth.user_id)
        await db.commit()

    enrichments = await _get_enrichment_results(db, auth.tenant_id, kind, canonical)
    dispatch_mode = "in_process" if should_dispatch else ("debounced" if enrichments else "cached")
    return {
        # JS-compatible fields
        "message": f"Lookup accepted for {canonical!r}.",
        "entity_id": str(entity.id),
        "entity_type": kind,
        "entity_value": canonical,
        "cached_results": enrichments,
        "dispatch_mode": dispatch_mode,
        "should_poll": should_dispatch,
        # additional detail
        "kind": kind,
        "canonical_name": canonical,
        "classified_as": classified["type"],
        "enrichment_dispatched": should_dispatch,
    }


@router.post("/bulk-lookup")
async def bulk_lookup(
    body: BulkLookupRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    results = []
    for query in body.queries[:50]:  # cap at 50
        classified = classify_input(query)
        if classified["type"] == "empty":
            results.append({"query": query, "error": "empty"})
            continue
        kind = _KIND_MAP.get(classified["type"], "indicator")
        canonical = classified["value"]
        try:
            entity = await _upsert_entity(db, auth.tenant_id, kind, canonical)
            should_dispatch = await _should_dispatch(db, str(entity.id), auth.tenant_id, False)
            if should_dispatch:
                background_tasks.add_task(_dispatch_enrichment, entity, auth.tenant_id, False, db, auth.user_id)
            if body.investigation_id:
                await _add_entity_to_investigation(db, body.investigation_id, str(entity.id), auth.tenant_id, auth.user_id)
            results.append({
                "query": query,
                "entity_id": str(entity.id),
                "kind": kind,
                "canonical_name": canonical,
                "classified_as": classified["type"],
                "enrichment_dispatched": should_dispatch,
            })
        except Exception as exc:
            results.append({"query": query, "error": str(exc)})
    await db.commit()
    return {"results": results}


@router.get("/lookup/entity/{entity_id}/results")
async def entity_results(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    entity = await _get_entity_for_tenant(db, entity_id, auth.tenant_id)
    enrichments = await _get_enrichment_results(db, auth.tenant_id, entity.kind, entity.canonical_name)

    # Build relationships list for renderResults() — use raw SQL to avoid ORM
    # column mismatch (Relationship model has updated_at but DB table does not)
    rels_raw = await db.execute(
        text("""SELECT id, from_entity_id, to_entity_id, kind, confidence
                FROM relationships
                WHERE tenant_id = :tid
                  AND (from_entity_id = :eid OR to_entity_id = :eid)
                LIMIT 50"""),
        {"tid": auth.tenant_id, "eid": entity_id},
    )
    relationships = []
    for row in rels_raw.mappings().all():
        target = str(row["to_entity_id"]) if str(row["from_entity_id"]) == entity_id else str(row["from_entity_id"])
        relationships.append({
            "relation_type": row["kind"],
            "target_entity": target,
            "discovered_via": "graph",
        })

    return {
        # JS renderResults() expects this shape:
        "entity": {
            "id": str(entity.id),
            "entity_type": entity.kind,
            "entity_value": entity.canonical_name,
            "notes": None,
            "tags": [],
        },
        "enrichments": enrichments,
        "relationships": relationships,
        # keep legacy field for other consumers
        "entity_id": entity_id,
        "results": enrichments,
    }


@router.get("/lookup/entity/{entity_id}/graph")
async def entity_graph(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    entity = await _get_entity_for_tenant(db, entity_id, auth.tenant_id)
    rels = await db.execute(
        text("""SELECT from_entity_id, to_entity_id, kind, confidence
                FROM relationships
                WHERE tenant_id = :tid
                  AND (from_entity_id = :eid OR to_entity_id = :eid)"""),
        {"tid": auth.tenant_id, "eid": entity_id},
    )

    rel_rows = rels.mappings().all()
    edges = []
    related_ids: set[str] = set()
    for row in rel_rows:
        from_id = str(row["from_entity_id"])
        to_id = str(row["to_entity_id"])
        edges.append({
            "from": from_id,
            "to": to_id,
            "label": row["kind"],
            "kind": row["kind"],
            "confidence": row["confidence"],
        })
        related_ids.add(from_id)
        related_ids.add(to_id)

    # Build nodes: the focal entity + all related entities
    node_ids = related_ids | {entity_id}
    entities_q = await db.execute(
        select(Entity).where(
            Entity.id.in_([uuid.UUID(eid) for eid in node_ids]),
            Entity.tenant_id == uuid.UUID(auth.tenant_id),
        )
    )
    nodes = []
    for e in entities_q.scalars().all():
        nodes.append({
            "id": str(e.id),
            "label": e.canonical_name,
            "type": e.kind,
            "color": "#2dd4bf" if str(e.id) == entity_id else "#6366f1",
            "size": 18 if str(e.id) == entity_id else 12,
        })

    return {"entity_id": entity_id, "nodes": nodes, "edges": edges}


@router.get("/lookup/entity/{entity_id}/history")
async def entity_history(
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    entity = await _get_entity_for_tenant(db, entity_id, auth.tenant_id)
    diffs = await db.execute(
        select(EnrichmentDiff)
        .where(
            EnrichmentDiff.entity_kind == entity.kind,
            EnrichmentDiff.entity_value == entity.canonical_name,
        )
        .order_by(EnrichmentDiff.created_at.desc())
        .limit(50)
    )
    history = []
    for d in diffs.scalars().all():
        history.append({
            "id": str(d.id),
            "provider": d.provider,
            "has_changes": d.has_changes,
            "diff_summary": d.diff_summary,
            "created_at": d.created_at.isoformat() if d.created_at else None,
        })
    return {"entity_id": entity_id, "history": history}


@router.get("/lookup/entity/{entity_id}/diff")
async def entity_diff(
    entity_id: str,
    source: str = Query(..., description="Provider name to diff"),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    entity = await _get_entity_for_tenant(db, entity_id, auth.tenant_id)
    diffs = await db.execute(
        select(EnrichmentDiff)
        .where(
            EnrichmentDiff.entity_kind == entity.kind,
            EnrichmentDiff.entity_value == entity.canonical_name,
            EnrichmentDiff.provider == source,
        )
        .order_by(EnrichmentDiff.created_at.desc())
        .limit(2)
    )
    rows = diffs.scalars().all()
    if len(rows) < 2:
        return {"entity_id": entity_id, "provider": source, "diff": None, "message": "Not enough history"}
    payload = diff_payload(rows[1].new_normalized, rows[0].new_normalized)
    return {"entity_id": entity_id, "provider": source, "diff": payload}


@router.post("/lookup/entity/{entity_id}/tag")
async def entity_tag(
    entity_id: str,
    body: TagRequest,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    entity = await _get_entity_for_tenant(db, entity_id, auth.tenant_id)
    existing = entity.external_refs or {}
    tags = list(set(existing.get("tags", []) + body.tags))
    entity.external_refs = {**existing, "tags": tags}
    await db.commit()
    return {"entity_id": entity_id, "tags": tags}


@router.post("/lookup/entity/{entity_id}/note")
async def entity_note(
    entity_id: str,
    body: NoteRequest,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    entity = await _get_entity_for_tenant(db, entity_id, auth.tenant_id)
    existing = entity.external_refs or {}
    notes = existing.get("notes", [])
    notes.append({"note": body.note, "created_at": datetime.now(timezone.utc).isoformat()})
    entity.external_refs = {**existing, "notes": notes}
    await db.commit()
    return {"entity_id": entity_id, "note_count": len(notes)}


# ---------------------------------------------------------------------------
# Investigations
# ---------------------------------------------------------------------------

async def _add_entity_to_investigation(
    db: AsyncSession, investigation_id: str, entity_id: str, tenant_id: str, user_id: str | None
) -> None:
    inv = await db.execute(
        text("SELECT id FROM investigations WHERE id = :iid AND tenant_id = :tid"),
        {"iid": investigation_id, "tid": tenant_id},
    )
    if inv.one_or_none() is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    await db.execute(
        text("""
            INSERT INTO investigation_entities (investigation_id, entity_id, added_by)
            VALUES (:iid, :eid, :uid)
            ON CONFLICT DO NOTHING
        """),
        {"iid": investigation_id, "eid": entity_id, "uid": user_id},
    )


@router.get("/lookup/investigations")
async def list_investigations(
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    result = await db.execute(
        text("SELECT id, name, description, created_by, created_at, updated_at FROM investigations WHERE tenant_id = :tid ORDER BY updated_at DESC"),
        {"tid": auth.tenant_id},
    )
    rows = result.mappings().all()
    return {"investigations": [dict(r) for r in rows]}


@router.post("/lookup/investigations")
async def create_investigation(
    body: InvestigationCreate,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    result = await db.execute(
        text("""
            INSERT INTO investigations (tenant_id, name, description, created_by)
            VALUES (:tid, :name, :desc, :uid)
            RETURNING id, name, description, created_at
        """),
        {"tid": auth.tenant_id, "name": body.name, "desc": body.description, "uid": auth.user_id},
    )
    row = result.mappings().one()
    await db.commit()
    return dict(row)


@router.post("/lookup/investigations/{inv_id}/entities/{entity_id}")
async def add_entity_to_investigation(
    inv_id: str,
    entity_id: str,
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    await _get_entity_for_tenant(db, entity_id, auth.tenant_id)
    await _add_entity_to_investigation(db, inv_id, entity_id, auth.tenant_id, auth.user_id)
    await db.commit()
    return {"investigation_id": inv_id, "entity_id": entity_id, "added": True}


# ---------------------------------------------------------------------------
# Path finding
# ---------------------------------------------------------------------------

@router.get("/lookup/path")
async def find_path(
    source_entity_id: str = Query(...),
    target_entity_id: str = Query(...),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext = Depends(get_auth),
):
    rels = await db.execute(
        select(Relationship).where(
            Relationship.tenant_id == uuid.UUID(auth.tenant_id),
        )
    )
    rel_dicts = [
        {
            "source_entity": str(r.from_entity_id),
            "target_entity": str(r.to_entity_id),
            "relation_type": r.kind,
            "confidence": r.confidence,
        }
        for r in rels.scalars().all()
    ]
    path = shortest_path(rel_dicts, source_entity_id, target_entity_id)
    return {
        "source": source_entity_id,
        "target": target_entity_id,
        "path": path,
        "hops": max(0, len(path) - 1),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _get_entity_for_tenant(db: AsyncSession, entity_id: str, tenant_id: str) -> Entity:
    result = await db.execute(
        select(Entity).where(
            Entity.id == uuid.UUID(entity_id),
            Entity.tenant_id == uuid.UUID(tenant_id),
        )
    )
    entity = result.scalar_one_or_none()
    if entity is None:
        raise HTTPException(status_code=404, detail="Entity not found")
    return entity
