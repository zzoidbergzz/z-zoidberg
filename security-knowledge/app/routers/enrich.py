from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import Optional
import json
import uuid
from app.database import get_db
from app.auth.dependencies import require_write, require_scope, Scope, AuthContext
from app.enrichment.registry import list_providers
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
    service = EnrichmentService(db, str(auth["tenant_id"]))
    providers = list_providers()
    results = {}
    for prov in providers:
        results[prov] = await service.enrich(prov, "unknown", str(entity_id))
    return {"entity_id": str(entity_id), "results": results}


@router.get(
    "/{entity_kind}/{entity_value}/stream",
    summary="Stream enrichment results via Server-Sent Events",
    response_class=StreamingResponse,
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "SSE stream of enrichment results, one event per provider.",
        }
    },
)
async def stream_enrichment(
    entity_kind: str,
    entity_value: str,
    providers: Optional[str] = Query(None, description="Comma-separated provider list; omit for all"),
    auth: AuthContext = Depends(require_scope(Scope.read)),
    db: AsyncSession = Depends(get_db),
):
    """Stream enrichment results as Server-Sent Events.

    Each provider result is pushed as a separate SSE event as soon as it
    completes — no waiting for slow providers before fast ones arrive.

    Event format::

        event: provider_result
        data: {"provider": "virustotal", "status": "ok", "data": {...}}

        event: provider_result
        data: {"provider": "shodan", "status": "error", "error": "..."}

        event: done
        data: {"providers_completed": 3, "entity_kind": "ip_address", "entity_value": "1.2.3.4"}

    Use ``?providers=virustotal,shodan`` to restrict to specific providers.
    """
    tenant_id = str(auth.tenant_id)
    provider_filter = [p.strip() for p in providers.split(",")] if providers else None
    all_providers = list_providers()
    selected = [p for p in all_providers if not provider_filter or p in provider_filter]

    async def event_generator():
        service = EnrichmentService(db, tenant_id)
        completed = 0

        for prov_name in selected:
            try:
                data = await service.enrich(prov_name, entity_kind, entity_value)
                payload = json.dumps({"provider": prov_name, "status": "ok", "data": data})
            except Exception as exc:
                payload = json.dumps({"provider": prov_name, "status": "error", "error": str(exc)})

            yield f"event: provider_result\ndata: {payload}\n\n"
            completed += 1

        # Terminal event
        done_payload = json.dumps({
            "providers_completed": completed,
            "entity_kind": entity_kind,
            "entity_value": entity_value,
        })
        yield f"event: done\ndata: {done_payload}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # Disable nginx buffering for SSE
        },
    )


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
