"""MCP package — import all tool modules to trigger registration side-effects."""

from app.mcp.tools import (  # noqa: F401
    create_claim,
    create_entity,
    create_evidence,
    enrich_entity,
    export_stix_bundle,
    get_changes_since,
    get_entity,
    list_entities,
    lookup_cve,
    mitre_tools,
    search_knowledge,
    searxng_search,
)
