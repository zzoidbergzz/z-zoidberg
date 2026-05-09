"""MCP tool: enqueue a URL/text for ingestion into the knowledge base."""

from __future__ import annotations

import structlog

from app.mcp.registry import register_tool
from app.services.ingestion import create_ingestion_job

logger = structlog.get_logger(__name__)


async def _ingest_url(args: dict, db, auth) -> dict:
    source_url = (args.get("source_url") or "").strip()
    if not source_url:
        return {"error": "source_url is required"}
    source_type = args.get("source_type") or "generic"

    try:
        job = await create_ingestion_job(db, auth.tenant_id, source_url, source_type)
    except ValueError as exc:
        return {"error": str(exc)}
    await db.commit()
    logger.info(
        "mcp_ingest_url",
        job_id=str(job.id),
        source_url=source_url,
        tenant_id=str(auth.tenant_id),
    )
    return {
        "job_id": str(job.id),
        "status": job.status,
        "source_url": source_url,
        "source_type": source_type,
        "note": "Job is queued for the worker. Poll its status separately or wait for entities to appear via search_knowledge.",
    }


register_tool(
    name="ingest_url",
    fn=_ingest_url,
    schema={
        "type": "object",
        "required": ["source_url"],
        "properties": {
            "source_url": {
                "type": "string",
                "description": "URL of an article/PDF/feed item to fetch, parse, extract entities from, and store.",
            },
            "source_type": {
                "type": "string",
                "description": "Hint for the parser: generic | rss | atom | pdf | report (default: generic)",
            },
        },
    },
    description="Enqueue a URL for ingestion. Returns a job_id; the ingest pipeline runs asynchronously and auto-enriches extracted entities.",
    scope="write",
)
