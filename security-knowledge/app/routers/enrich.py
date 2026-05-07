from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional
import uuid
from app.database import get_db
from app.auth.dependencies import require_write, require_scope, Scope, AuthContext
from app.enrichment.service import EnrichmentService

router = APIRouter(prefix="/enrich", tags=["enrich"])


class EnrichRequest(BaseModel):
    entity_id: uuid.UUID
    providers: Optional[list[str]] = None


@router.post("/{entity_id}")
async def enrich_entity(
    entity_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_write),
):
    service = EnrichmentService(db)
    results = await service.enrich(str(entity_id), str(auth["tenant_id"]))
    return {"entity_id": str(entity_id), "results": results}


@router.post("/{entity_kind}/{entity_value}/refresh")
async def force_refresh(
    entity_kind: str,
    entity_value: str,
    provider: str = Query(..., description="Provider name to refresh"),
    auth: AuthContext = Depends(require_scope(Scope.enrichment)),
    db: AsyncSession = Depends(get_db),
):
    """Force fresh enrichment lookup bypassing cache. Returns result + diff summary."""
    from app.services.enrichment_diff import force_refresh_enrichment

    new_data, diff = await force_refresh_enrichment(
        entity_value=entity_value,
        entity_kind=entity_kind,
        provider=provider,
        user_id=auth.user_id,
        tenant_id=auth.tenant_id,
        db=db,
    )
    return {
        "entity_kind": entity_kind,
        "entity_value": entity_value,
        "provider": provider,
        "data": new_data,
        "diff": diff.diff_summary if diff else None,
        "has_changes": diff.has_changes if diff else False,
    }
