"""MCP tool: look up a CVE by ID via NVD."""

from __future__ import annotations

from app.enrichment.service import EnrichmentService
from app.mcp.registry import register_tool


async def _lookup_cve(args: dict, db, auth) -> dict:
    cve_id = args.get("cve_id")
    if not cve_id:
        return {"error": {"code": "missing_arg", "message": "Missing required arg: cve_id"}}
    service = EnrichmentService(db=db, tenant_id=str(auth.tenant_id))
    result = await service.enrich("nvd", "cve", cve_id)
    return {"cve_id": cve_id, "data": result}


register_tool(
    name="lookup_cve",
    fn=_lookup_cve,
    schema={
        "type": "object",
        "required": ["cve_id"],
        "properties": {
            "cve_id": {"type": "string", "description": "CVE identifier, e.g. CVE-2024-1234"},
        },
    },
    description="Look up a CVE by ID via NVD",
    scope="read",
)
