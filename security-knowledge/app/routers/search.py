from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from app.database import get_db
from app.auth.dependencies import require_read
from app.services.search import full_text_search

router = APIRouter(prefix="/search", tags=["search"])


class SearchResult(BaseModel):
    kind: str
    id: str
    name: str
    score: float = 1.0


@router.get("/", response_model=list[SearchResult])
async def search(
    q: str = Query(..., min_length=2),
    limit: int = Query(20, le=100),
    db: AsyncSession = Depends(get_db),
    auth: dict = Depends(require_read),
):
    results = await full_text_search(db, auth["tenant_id"], q, limit)
    return [SearchResult(**r) for r in results]
