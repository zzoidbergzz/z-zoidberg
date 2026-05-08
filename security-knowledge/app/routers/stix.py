from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.auth.dependencies import require_read
from app.models.entities import Entity
from app.stix.builder import build_stix_bundle

router = APIRouter(prefix="/stix", tags=["STIX"])


@router.get("/bundle")
async def export_stix_bundle(
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(select(Entity).where(Entity.tenant_id == auth.tenant_id).limit(limit))
    entities = list(result.scalars().all())
    return build_stix_bundle(entities, [])
