"""MCP tools for searching historical security corpora (CVE, GCVE, Exploit-DB)."""

from __future__ import annotations

from sqlalchemy import text

from app.mcp.registry import register_tool


async def _cve_lookup(args: dict, db, auth) -> dict:
    """Look up a CVE from the local corpus_documents table."""
    cve_id = (args.get("cve_id") or "").strip().upper()
    if not cve_id:
        return {"error": "cve_id is required"}

    row = await db.execute(
        text(
            """
            SELECT
                cd.id::text, cd.corpus, cd.external_id, cd.title, cd.summary,
                cd.body_text, cd.raw_json, cd.published_at, cd.modified_at,
                cd.source_path
            FROM corpus_documents cd
            WHERE cd.corpus IN ('cve', 'gcve')
              AND cd.external_id = :eid
              AND cd.tenant_id = :tid
            LIMIT 1
            """
        ),
        {"eid": cve_id, "tid": str(auth.tenant_id)},
    )
    rec = row.mappings().first()
    if rec is None:
        return {"found": False, "cve_id": cve_id, "message": "Not found in local corpus"}

    doc = dict(rec)
    # Enrich with any related exploits via FTS on the CVE ID in body_text
    exploit_rows = await db.execute(
        text(
            """
            SELECT external_id, title, published_at
            FROM corpus_documents
            WHERE corpus = 'exploitdb'
              AND tenant_id = :tid
              AND body_text ILIKE :pat
            ORDER BY published_at DESC NULLS LAST
            LIMIT 10
            """
        ),
        {"tid": str(auth.tenant_id), "pat": f"%{cve_id}%"},
    )
    exploits = [
        {"edb_id": r["external_id"], "title": r["title"], "date": str(r["published_at"] or "")}
        for r in exploit_rows.mappings().all()
    ]

    return {
        "found": True,
        "cve_id": cve_id,
        "corpus": doc.get("corpus"),
        "title": doc.get("title"),
        "summary": doc.get("summary"),
        "published_at": str(doc.get("published_at") or ""),
        "modified_at": str(doc.get("modified_at") or ""),
        "related_exploits": exploits,
        "detail_url": f"/cve/{cve_id}",
    }


async def _exploit_search(args: dict, db, auth) -> dict:
    """Full-text search over Exploit-DB corpus."""
    query = (args.get("query") or "").strip()
    if not query:
        return {"error": "query is required"}
    limit = min(int(args.get("limit", 20)), 100)

    rows = await db.execute(
        text(
            """
            SELECT
                external_id, title, summary, published_at,
                ts_rank_cd(search_vector, plainto_tsquery('english', :q)) AS score
            FROM corpus_documents
            WHERE corpus = 'exploitdb'
              AND tenant_id = :tid
              AND search_vector @@ plainto_tsquery('english', :q)
            ORDER BY score DESC, published_at DESC NULLS LAST
            LIMIT :lim
            """
        ),
        {"q": query, "tid": str(auth.tenant_id), "lim": limit},
    )
    results = [
        {
            "edb_id": r["external_id"],
            "title": r["title"],
            "summary": r["summary"] or "",
            "date": str(r["published_at"] or ""),
            "score": float(r["score"]),
            "detail_url": f"/search?q={r['external_id']}&corpus=exploitdb",
        }
        for r in rows.mappings().all()
    ]
    return {"query": query, "count": len(results), "results": results}


async def _corpus_search(args: dict, db, auth) -> dict:
    """Full-text search across all corpora (or a specific one)."""
    query = (args.get("query") or "").strip()
    if not query:
        return {"error": "query is required"}
    corpus = args.get("corpus")  # None = all, or 'cve'/'gcve'/'exploitdb'
    limit = min(int(args.get("limit", 20)), 100)

    params: dict = {"q": query, "tid": str(auth.tenant_id), "lim": limit}
    corpus_filter = ""
    if corpus:
        corpus_filter = "AND corpus = :corpus"
        params["corpus"] = corpus

    rows = await db.execute(
        text(
            f"""
            SELECT
                corpus, external_id, title, summary, published_at,
                ts_rank_cd(search_vector, plainto_tsquery('english', :q)) AS score
            FROM corpus_documents
            WHERE tenant_id = :tid
              AND search_vector @@ plainto_tsquery('english', :q)
              {corpus_filter}
            ORDER BY score DESC, published_at DESC NULLS LAST
            LIMIT :lim
            """
        ),
        params,
    )
    results = [
        {
            "corpus": r["corpus"],
            "id": r["external_id"],
            "title": r["title"],
            "summary": (r["summary"] or "")[:300],
            "date": str(r["published_at"] or ""),
            "score": float(r["score"]),
        }
        for r in rows.mappings().all()
    ]
    return {"query": query, "corpus": corpus or "all", "count": len(results), "results": results}


register_tool(
    name="cve_lookup",
    fn=_cve_lookup,
    schema={
        "type": "object",
        "required": ["cve_id"],
        "properties": {
            "cve_id": {
                "type": "string",
                "description": "CVE or GCVE identifier, e.g. CVE-2024-3094 or GCVE-1-2025-0001",
            }
        },
    },
    description="Look up a CVE or GCVE record from the local corpus. Returns record + related exploits.",
    scope="read",
)

register_tool(
    name="exploit_search",
    fn=_exploit_search,
    schema={
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string", "description": "Search query for exploit records"},
            "limit": {"type": "integer", "description": "Max results (default 20, max 100)"},
        },
    },
    description="Full-text search across Exploit-DB corpus records.",
    scope="read",
)

register_tool(
    name="corpus_search",
    fn=_corpus_search,
    schema={
        "type": "object",
        "required": ["query"],
        "properties": {
            "query": {"type": "string", "description": "Search query"},
            "corpus": {
                "type": "string",
                "enum": ["cve", "gcve", "exploitdb"],
                "description": "Limit to a specific corpus (omit for all)",
            },
            "limit": {"type": "integer", "description": "Max results (default 20, max 100)"},
        },
    },
    description="Full-text search across all historical security corpora (CVE, GCVE, Exploit-DB).",
    scope="read",
)
