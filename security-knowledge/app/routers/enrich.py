from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional
import uuid
from app.database import get_db
from app.auth.dependencies import require_write
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
