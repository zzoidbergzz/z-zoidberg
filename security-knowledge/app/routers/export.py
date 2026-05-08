"""STIX 2.1 export endpoint.

Exports entities, claims, and relationships from the current tenant as a
valid STIX 2.1 Bundle.  The response can be used directly with tools like
OpenCTI, MISP, or any other platform that consumes STIX over TAXII or HTTP.

Endpoint:  GET /api/v1/export/stix
Content-Type: application/stix+json; version=2.1

Query parameters:
  kind       Filter by entity kind (repeatable: ?kind=malware&kind=actor)
  limit      Max entities per page (default 200, max 1000)
  offset     Pagination offset (default 0)
  include_claims  Include claim notes in bundle (default true)
  include_rels    Include relationship objects (default true)
"""
from __future__ import annotations

import json
from typing import Annotated

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AuthContext, Scope, require_read
from app.database import get_db
from app.models.claims import Claim
from app.models.entities import Entity
from app.models.relationships import Relationship
from app.stix.builder import build_stix_bundle

router = APIRouter(prefix="/export", tags=["export"])


@router.get(
    "/stix",
    summary="Export as STIX 2.1 Bundle",
    response_class=Response,
    responses={
        200: {
            "content": {"application/stix+json": {}},
            "description": "A STIX 2.1 Bundle containing entities, claims, and relationships.",
        }
    },
)
async def export_stix(
    kind: Annotated[list[str], Query(description="Filter by entity kind (repeatable)")] = [],
    limit: int = Query(200, ge=1, le=1000, description="Max number of entities"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    include_claims: bool = Query(True, description="Include claim notes in bundle"),
    include_rels: bool = Query(True, description="Include relationship objects"),
    auth: AuthContext = Depends(require_read),
    db: AsyncSession = Depends(get_db),
) -> Response:
    """Export all entities (with claims and relationships) as a STIX 2.1 Bundle.

    The bundle is returned with ``Content-Type: application/stix+json`` and
    includes a ``Content-Disposition`` header so browsers/tools prompt for a
    sensible filename.

    Use the ``kind`` parameter to filter by entity type, e.g.::

        GET /api/v1/export/stix?kind=malware&kind=actor

    Pagination is supported via ``limit`` + ``offset``.  For large exports,
    iterate with ``offset=0``, ``offset=200``, etc. and merge the ``objects``
    arrays.
    """
    tenant_id = auth.tenant_id

    # ------------------------------------------------------------------
    # 1. Fetch entities
    # ------------------------------------------------------------------
    entity_query = select(Entity).where(Entity.tenant_id == tenant_id)
    if kind:
        entity_query = entity_query.where(Entity.kind.in_(kind))
    entity_query = entity_query.order_by(Entity.created_at.desc()).offset(offset).limit(limit)

    result = await db.execute(entity_query)
    entities = list(result.scalars().all())

    entity_ids = [e.id for e in entities]

    # ------------------------------------------------------------------
    # 2. Fetch claims (if requested)
    # ------------------------------------------------------------------
    claims: list = []
    if include_claims:
        claims_result = await db.execute(
            select(Claim).where(Claim.tenant_id == tenant_id).limit(limit * 5)
        )
        claims = list(claims_result.scalars().all())

    # ------------------------------------------------------------------
    # 3. Fetch relationships (if requested, restricted to returned entities)
    # ------------------------------------------------------------------
    rels: list = []
    if include_rels and entity_ids:
        rels_result = await db.execute(
            select(Relationship).where(
                Relationship.tenant_id == tenant_id,
                Relationship.from_entity_id.in_(entity_ids),
            ).limit(limit * 10)
        )
        rels = list(rels_result.scalars().all())

    # ------------------------------------------------------------------
    # 4. Build bundle
    # ------------------------------------------------------------------
    bundle = build_stix_bundle(entities, claims, rels)

    # Count for informational header
    obj_count = len(bundle["objects"])

    # Serialise to compact JSON
    body = json.dumps(bundle, separators=(",", ":"))

    return Response(
        content=body,
        media_type="application/stix+json; version=2.1",
        headers={
            "Content-Disposition": 'attachment; filename="export.stix2.json"',
            "X-STIX-Object-Count": str(obj_count),
            "X-STIX-Bundle-ID": bundle["id"],
        },
    )
