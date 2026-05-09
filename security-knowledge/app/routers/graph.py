import uuid

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import AuthContext, require_read
from app.database import get_db
from app.graph.visualisation import build_graph

router = APIRouter(prefix="/graph", tags=["graph"])


def _tenant_id(auth: AuthContext | dict) -> str:
    if isinstance(auth, dict):
        return str(auth["tenant_id"])
    return str(auth.tenant_id)


@router.get("/")
async def get_graph(
    entity_id: uuid.UUID | None = None,
    depth: int = Query(2, le=5),
    fmt: str = Query("vis", regex="^(vis|cytoscape)$"),
    db: AsyncSession = Depends(get_db),
    auth: AuthContext | dict = Depends(require_read),
):
    return await build_graph(db, _tenant_id(auth), entity_id, depth, fmt)
