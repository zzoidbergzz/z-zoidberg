from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import uuid
from app.database import get_db
from app.auth.dependencies import require_read
from app.graph.visualisation import build_graph

router = APIRouter(prefix="/graph", tags=["graph"])


@router.get("/")
async def get_graph(
    entity_id: Optional[uuid.UUID] = None,
    depth: int = Query(2, le=5),
    fmt: str = Query("vis", regex="^(vis|cytoscape)$"),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    return await build_graph(db, str(auth["tenant_id"]), entity_id, depth, fmt)
