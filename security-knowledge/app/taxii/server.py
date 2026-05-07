from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database import get_db
from app.auth.dependencies import require_read
from app.models.sync import TaxiiCollection
from app.models.entities import Entity
from app.stix.builder import build_stix_bundle
import structlog

logger = structlog.get_logger(__name__)

taxii_router = APIRouter(prefix="/taxii2", tags=["TAXII"])
TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"


@taxii_router.get("/")
async def taxii_discovery():
    return {
        "title": "Security Knowledge TAXII Server",
        "description": "TAXII 2.1 server providing threat intelligence",
        "contact": "admin@example.com",
        "api_roots": ["/taxii2/"],
    }


@taxii_router.get("/collections/")
async def list_collections(
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(
        select(TaxiiCollection).where(TaxiiCollection.tenant_id == auth["tenant_id"])
    )
    collections = result.scalars().all()
    return {
        "collections": [
            {
                "id": c.collection_id,
                "title": c.title,
                "description": c.description,
                "can_read": c.can_read,
                "can_write": c.can_write,
            }
            for c in collections
        ]
    }


@taxii_router.get("/collections/{collection_id}/objects/")
async def get_objects(
    collection_id: str,
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    result = await db.execute(select(Entity).where(Entity.tenant_id == auth["tenant_id"]).limit(100))
    entities = list(result.scalars().all())
    bundle = build_stix_bundle(entities, [])
    return bundle
