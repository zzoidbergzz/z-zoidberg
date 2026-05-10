import asyncio
import uuid
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

import app.mcp  # trigger registration
from app.auth.dependencies import AuthContext, Scope, get_auth
from app.database import get_db
from app.mcp.registry import get_tool

router = APIRouter(prefix="/batch", tags=["enrich"])


class BatchEnrichRequest(BaseModel):
    indicators: list[dict]
    providers: str | None = None
    delay_seconds: float = 1.0


class BatchEnrichResult(BaseModel):
    kind: str
    value: str
    status: str
    entity_id: uuid.UUID | None = None
    providers_completed: int = 0
    error: str | None = None


class BatchEnrichResponse(BaseModel):
    total: int
    results: list[BatchEnrichResult]


@router.post("/enrich", response_model=BatchEnrichResponse)
async def batch_enrich(
    body: BatchEnrichRequest,
    auth: AuthContext = Depends(get_auth),
    db: AsyncSession = Depends(get_db),
):
    """Batch enrich multiple indicators via MCP tools.
    Each: {"kind": "ip_address", "value": "1.2.3.4"}. Max 50. Rate-limited.
    """
    auth.require_scope(Scope.write)
    indicators = body.indicators[:50]
    results = []
    for ioc in indicators:
        kind = ioc.get("kind", "indicator")
        value = ioc.get("value", "")
        if not value:
            results.append(BatchEnrichResult(kind=kind, value="", status="error", error="missing value"))
            continue
        try:
            enrich_args = {"entity_kind": kind, "entity_value": value}
            if body.providers:
                enrich_args["providers"] = body.providers
            tool = get_tool("enrich_entity")
            result = await tool.fn(enrich_args, db, auth)
            results.append(BatchEnrichResult(kind=kind, value=value, status="ok", providers_completed=1))
        except Exception as e:
            results.append(BatchEnrichResult(kind=kind, value=value, status="error", error=str(e)[:200]))
        if body.delay_seconds > 0:
            await asyncio.sleep(body.delay_seconds)
    return BatchEnrichResponse(total=len(indicators), results=results)
