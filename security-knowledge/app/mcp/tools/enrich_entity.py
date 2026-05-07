"""MCP tool: enrich a named entity."""
from pydantic import BaseModel
from typing import Any


class EnrichEntityInput(BaseModel):
    entity_name: str
    entity_kind: str
    tenant_id: str


class EnrichEntityOutput(BaseModel):
    entity_name: str
    enrichment_data: dict[str, Any]
    sources: list[str]


async def enrich_entity_tool(inp: EnrichEntityInput) -> EnrichEntityOutput:
    """Look up enrichment data for the given entity."""
    # Stub: in production, calls EnrichmentService
    return EnrichEntityOutput(
        entity_name=inp.entity_name,
        enrichment_data={},
        sources=[],
    )
