"""MCP tool: enrich a named entity via registered providers."""

from __future__ import annotations

from typing import Any

import structlog
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.enrichment.registry import list_providers
from app.enrichment.service import EnrichmentService
from app.mcp.registry import register_tool

logger = structlog.get_logger(__name__)


class EnrichEntityInput(BaseModel):
    entity_kind: str
    entity_value: str
    providers: list[str] | None = None
    tenant_id: str


class ProviderResult(BaseModel):
    provider: str
    ok: bool
    data: dict[str, Any] = {}
    error: str | None = None


class EnrichEntityOutput(BaseModel):
    entity_kind: str
    entity_value: str
    results: list[ProviderResult]
    count: int


async def enrich_entity_tool(inp: EnrichEntityInput, db: AsyncSession) -> EnrichEntityOutput:
    """Run each matching enrichment provider and return a normalised result envelope.

    Provider errors are captured per-result (ok=False, error=<msg>) so a single
    broken provider never prevents the others from returning data.
    """
    available = list_providers()
    selected = [p for p in (inp.providers or available) if p in available]

    service = EnrichmentService(db=db, tenant_id=inp.tenant_id)
    results: list[ProviderResult] = []

    for provider_name in selected:
        try:
            data = await service.enrich(provider_name, inp.entity_kind, inp.entity_value)
            results.append(ProviderResult(provider=provider_name, ok=True, data=data or {}))
        except Exception as exc:  # noqa: BLE001
            logger.warning("enrich_entity_provider_error", provider=provider_name, error=str(exc))
            results.append(ProviderResult(provider=provider_name, ok=False, data={}, error=str(exc)))

    return EnrichEntityOutput(
        entity_kind=inp.entity_kind,
        entity_value=inp.entity_value,
        results=results,
        count=len(results),
    )


async def _enrich_entity_mcp(args: dict, db, auth) -> dict:
    inp = EnrichEntityInput(tenant_id=str(auth.tenant_id), **args)
    result = await enrich_entity_tool(inp, db)
    return result.model_dump()


register_tool(
    name="enrich_entity",
    fn=_enrich_entity_mcp,
    schema={
        "type": "object",
        "required": ["entity_kind", "entity_value"],
        "properties": {
            "entity_kind": {
                "type": "string",
                "description": "Kind of entity to enrich (e.g. cve, ip_address, domain, malware)",
            },
            "entity_value": {
                "type": "string",
                "description": "The entity value to look up (e.g. CVE-2024-1234, 1.2.3.4)",
            },
            "providers": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Optional provider names to restrict enrichment to",
            },
        },
    },
    description="Enrich an entity via registered providers",
    scope="read",
)
