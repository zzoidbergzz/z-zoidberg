"""MCP package — import all tool modules to trigger registration side-effects."""

from app.mcp.tools import (  # noqa: F401
    ask_question,
    audit,
    corpus_tools,
    create_claim,
    create_entity,
    create_evidence,
    detections,
    digests,
    enrich_entity,
    export_stix_bundle,
    get_changes_since,
    get_entity,
    graph,
    ingest_url,
    list_entities,
    lookup_cve,
    lookup_ioc,
    mitre_tools,
    search_knowledge,
    searxng_search,
    sources,
    unified_search,
    translate_text,
    necti_collect,
)

# Dark-Moon bridge — registers dm_* tools when DARK_MOON_ENABLED=true.
from app.mcp.dark_moon_bridge import register_dark_moon_tools as _dm_register  # noqa: E402

_dm_register()
