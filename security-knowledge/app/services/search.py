"""Full-text + trigram hybrid search across entities, claims, and corpus_documents.

Migration 0005 adds a ``search_vector`` tsvector column (GIN-indexed) and a
``canonical_name gin_trgm_ops`` index to ``entities``, and a
``search_vector`` column (GIN-indexed) to ``claims``.

Migration 0023 adds ``corpus_documents`` (CVE, GCVE, Exploit-DB) with its own
``search_vector`` GIN index.

Results are enriched with claim descriptions (assertion text), tags,
CVSS scores and external reference links so the search UI can render
rich cards without needing a separate detail-page round-trip.
"""
from __future__ import annotations

import re
from typing import Any

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = structlog.get_logger(__name__)

# Entity search: LEFT JOIN the most-relevant claim for a description snippet.
_ENTITY_SQL = text(
    """
    SELECT
        e.id::text                                                                AS id,
        e.canonical_name                                                          AS name,
        e.kind,
        e.external_refs,
        e.mitre_attack_id,
        COALESCE(ts_rank_cd(e.search_vector, websearch_to_tsquery('english', :q)), 0)
            + 0.4 * COALESCE(similarity(e.canonical_name, :q), 0)               AS score,
        (
            SELECT c.value->>'assertion'
            FROM claims c
            WHERE c.entity_id = e.id
              AND c.claim_type IN (
                  'vulnerability_detail', 'technique_detail', 'actor_profile', 'report_detail', 'organization_profile',
                  'product_detail', 'framework_detail', 'tool_capability',
                  'detection_detail'
              )
            ORDER BY c.created_at DESC
            LIMIT 1
        ) AS claim_desc,
        COALESCE(
            (SELECT c.value->>'assertion'
             FROM claims c
             WHERE c.entity_id = e.id
               AND c.claim_type IN (
                   'vulnerability_detail', 'technique_detail', 'actor_profile', 'report_detail', 'organization_profile',
                   'product_detail', 'framework_detail', 'tool_capability', 'detection_detail'
               )
             ORDER BY c.created_at DESC LIMIT 1),
            e.external_refs->>'description'
        ) AS description,
        (
            SELECT c.value->'tags'
            FROM claims c
            WHERE c.entity_id = e.id
            ORDER BY c.created_at DESC
            LIMIT 1
        ) AS tags,
        (
            SELECT c.value->>'confidence'
            FROM claims c
            WHERE c.entity_id = e.id
            ORDER BY c.created_at DESC
            LIMIT 1
        ) AS confidence
    FROM entities e
    WHERE e.tenant_id = :tenant_id
      AND (
          e.search_vector @@ websearch_to_tsquery('english', :q)
          OR e.canonical_name % :q
      )
    ORDER BY score DESC, e.updated_at DESC
    LIMIT :lim
    """
)

# Claim search: JOIN the parent entity to get its external_refs + kind so we
# can still surface CVSS / MITRE links even when the entity is reached via
# a claim rather than its canonical_name.
_CLAIM_SQL = text(
    """
    SELECT
        COALESCE(e.id::text, c.id::text)                                          AS id,
        c.id::text                                                                 AS claim_id,
        c.entity_id::text                                                         AS entity_id,
        COALESCE(e.kind, c.claim_type)                                            AS kind,
        COALESCE(e.canonical_name, c.value->>'title', c.claim_type)              AS name,
        e.external_refs,
        e.mitre_attack_id,
        c.value->>'assertion'                                                     AS description,
        c.value->'tags'                                                           AS tags,
        c.value->>'confidence'                                                    AS confidence,
        COALESCE(ts_rank_cd(c.search_vector, websearch_to_tsquery('english', :q)), 0)
            + 0.4 * COALESCE(similarity(c.claim_type, :q), 0)                   AS score
    FROM claims c
    LEFT JOIN entities e ON e.id = c.entity_id
    WHERE c.tenant_id = :tenant_id
      AND (
          c.search_vector @@ websearch_to_tsquery('english', :q)
          OR c.claim_type % :q
      )
    ORDER BY score DESC, c.updated_at DESC
    LIMIT :lim
    """
)

_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)
_GCVE_RE = re.compile(r"^GCVE-\d+-\d{4}-\d+$", re.IGNORECASE)
_MITRE_RE = re.compile(r"^[TGSC]\d{4}(\.\d{3})?$")


def _nvd_link(cve_id: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve_id.upper()}"


def _mitre_link(attack_id: str) -> str:
    base = "https://attack.mitre.org"
    aid = attack_id.upper()
    if "." in aid:
        parent, sub = aid.split(".", 1)
        return f"{base}/techniques/{parent}/{sub}/"
    if aid.startswith("T"):
        return f"{base}/techniques/{aid}/"
    if aid.startswith("G"):
        return f"{base}/groups/{aid}/"
    if aid.startswith("S"):
        return f"{base}/software/{aid}/"
    return f"{base}/"


def _severity_from_cvss(cvss_str: str | None) -> str:
    """Map CVSS numeric score string to severity label."""
    if not cvss_str:
        return ""
    try:
        score = float(cvss_str)
    except ValueError:
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _build_entity_result(row: Any) -> dict[str, Any]:
    ext = row["external_refs"] or {}
    kind: str = row["kind"] or "entity"
    name: str = row["name"]
    mitre_id: str | None = row["mitre_attack_id"] or ext.get("attack_id") or ext.get("mitre_id")

    result: dict[str, Any] = {
        "kind": kind,
        "id": row["id"],
        "name": name,
        "score": float(row["score"]),
        "description": row["description"] or "",
        "tags": list(row["tags"]) if row["tags"] else [],
        "confidence": row["confidence"] or "",
        "cvss": None,
        "severity": "",
        "detail_url": None,
        "nvd_link": None,
        "mitre_link": None,
    }

    # Hash/malware enrichment
    if kind == hash and ext.get(source, ).startswith(malware-repo):
        result[detail_url] = f/entities/{row["id"]}
        result[tags] = list(set(result[tags] + [malware, ext.get(family, unknown)]))

    # Hash / malware enrichment
    if kind == "hash":
        fn = ext.get("filename", "")
        fam = ext.get("family", "")
        if fn:
            result["name"] = fn
            result["description"] = f"SHA256: {name[:16]}..." + (f" | Family: {fam}" if fam else "")
        if ext.get("source", "").startswith("malware-repo"):
            result["detail_url"] = f"/entities/{row["id"]}"
            result["tags"] = list(set(result["tags"] + ["malware"] + ([fam] if fam else [])))

    # CVE-specific enrichment
    cve_id: str | None = ext.get("cve") or (name if _CVE_RE.match(name) else None)
    if cve_id:
        cvss_str = ext.get("cvss") or ext.get("cvss_score")
        result["cvss"] = cvss_str
        result["severity"] = _severity_from_cvss(cvss_str)
        result["nvd_link"] = _nvd_link(cve_id)

    # MITRE technique/group/software enrichment
    if mitre_id and _MITRE_RE.match(mitre_id):
        result["mitre_link"] = _mitre_link(mitre_id)
    elif _MITRE_RE.match(name):
        result["mitre_link"] = _mitre_link(name)

    return result


# Substring fallback for free-form / SearXNG-style queries that don't tokenize well
# (CVE-IDs, IPs, hostnames, EDB-IDs, hashes, etc.). Triggered when tsquery returns
# nothing or for very short tokens.
_CORPUS_ILIKE_SQL = text(
    """
    SELECT
        cd.id::text AS id, cd.corpus, cd.external_id AS name,
        cd.title, cd.summary, cd.published_at,
        0.05::float AS score
    FROM corpus_documents cd
    WHERE cd.tenant_id = :tenant_id
      AND (
          cd.external_id ILIKE :pat
          OR cd.title ILIKE :pat
          OR cd.summary ILIKE :pat
      )
    ORDER BY cd.published_at DESC NULLS LAST
    LIMIT :lim
    """
)

_ENTITY_ILIKE_SQL = text(
    """
    SELECT
        e.id::text AS id, e.canonical_name AS name, e.kind, e.external_refs,
        e.mitre_attack_id,
        0.05::float AS score,
        NULL::text AS description, NULL::jsonb AS tags, NULL::text AS confidence
    FROM entities e
    WHERE e.tenant_id = :tenant_id
      AND (
          e.canonical_name ILIKE :pat
          OR e.external_refs->>'filename' ILIKE :pat
          OR e.external_refs->>'family' ILIKE :pat
      )
    ORDER BY e.updated_at DESC
    LIMIT :lim
    """
)


async def full_text_search(
    db: AsyncSession, tenant_id: str, query: str, limit: int = 20
) -> list[dict[str, Any]]:
    """Return enriched search results across entities, claims, and corpus_documents.

    Each result includes description (from claim assertion), CVSS/severity
    for CVEs, NVD/MITRE links, and tag lists so the UI can render rich cards.
    Entity-linked claims are deduplicated — if an entity matches via both the
    entity row and an associated claim, only the entity result is kept.
    Corpus documents are merged in and re-ranked by score.
    """
    params = {"q": query, "tenant_id": tenant_id, "lim": limit}

    entity_rows = await db.execute(_ENTITY_SQL, params)
    claim_rows = await db.execute(_CLAIM_SQL, params)

    # Also search corpus_documents
    corpus_params = {"q": query, "tenant_id": tenant_id, "lim": limit}
    try:
        corpus_rows = await db.execute(_CORPUS_SQL, corpus_params)
        corpus_records = corpus_rows.mappings().all()
    except Exception:
        corpus_records = []

    results: list[dict[str, Any]] = []
    seen_entity_ids: set[str] = set()

    for row in entity_rows.mappings().all():
        r = _build_entity_result(row)
        results.append(r)
        seen_entity_ids.add(row["id"])

    for row in claim_rows.mappings().all():
        eid = row["entity_id"]
        # Skip orphan claims — without a parent entity their "id" is a claim UUID
        # and any /entities/<id> link will 404. Surface them only via parent.
        if not eid:
            continue
        if eid in seen_entity_ids:
            continue
        seen_entity_ids.add(eid)

        ext = row["external_refs"] or {}
        kind: str = row["kind"] or "claim"
        name: str = row["name"] or kind
        mitre_id: str | None = row["mitre_attack_id"] or ext.get("attack_id") or ext.get("mitre_id")

        r: dict[str, Any] = {
            "kind": kind,
            "id": eid,
            "name": name,
            "score": float(row["score"]),
            "description": row["description"] or "",
            "tags": list(row["tags"]) if row["tags"] else [],
            "confidence": row["confidence"] or "",
            "cvss": None,
            "severity": "",
            "detail_url": f"/entities/{eid}",
            "nvd_link": None,
            "mitre_link": None,
        }

        # Enrich with entity data if we have it
        cve_id: str | None = ext.get("cve") or (name if _CVE_RE.match(name) else None)
        if cve_id:
            cvss_str = ext.get("cvss") or ext.get("cvss_score")
            r["cvss"] = cvss_str
            r["severity"] = _severity_from_cvss(cvss_str)
            r["nvd_link"] = _nvd_link(cve_id)

        if mitre_id and _MITRE_RE.match(mitre_id):
            r["mitre_link"] = _mitre_link(mitre_id)
        elif _MITRE_RE.match(name):
            r["mitre_link"] = _mitre_link(name)

        results.append(r)

    for row in corpus_records:
        results.append(_build_corpus_result(row))

    # Free-form / SearXNG-style fallback: if tsquery yielded nothing useful,
    # do a substring search across entities + corpus_documents so that
    # arbitrary strings (CVE-IDs, IPs, hashes, EDB-IDs, partial hostnames,
    # apostrophe'd words, etc.) still surface results.
    if len(results) < max(3, limit // 4):
        ilike_params = {
            "tenant_id": tenant_id,
            "pat": f"%{query.strip()}%",
            "lim": limit,
        }
        try:
            ent_fallback = await db.execute(_ENTITY_ILIKE_SQL, ilike_params)
            for row in ent_fallback.mappings().all():
                if row["id"] in seen_entity_ids:
                    continue
                seen_entity_ids.add(row["id"])
                results.append(_build_entity_result(row))
        except Exception:
            pass
        try:
            corpus_fallback = await db.execute(_CORPUS_ILIKE_SQL, ilike_params)
            seen_corpus_ids = {r["id"] for r in results if r.get("kind") in ("cve", "exploit", "exploitdb", "gcve")}
            for row in corpus_fallback.mappings().all():
                if row["id"] in seen_corpus_ids:
                    continue
                results.append(_build_corpus_result(row))
        except Exception:
            pass

    results.sort(key=lambda r: r["score"], reverse=True)
    return results[:limit]


# Corpus document search: CVE, GCVE, and Exploit-DB records.
_CORPUS_SQL = text(
    """
    SELECT
        cd.id::text                                                               AS id,
        cd.corpus,
        cd.external_id                                                            AS name,
        cd.title,
        cd.summary,
        cd.published_at,
        ts_rank_cd(cd.search_vector, websearch_to_tsquery('english', :q))              AS score
    FROM corpus_documents cd
    WHERE cd.tenant_id = :tenant_id
      AND cd.search_vector @@ websearch_to_tsquery('english', :q)
    ORDER BY score DESC, cd.published_at DESC NULLS LAST
    LIMIT :lim
    """
)


def _build_corpus_result(row: Any) -> dict[str, Any]:
    corpus = row["corpus"]
    ext_id: str = row["name"]
    title: str = row["title"] or ext_id
    summary: str = row["summary"] or ""

    kind_map = {"cve": "cve", "gcve": "cve", "exploitdb": "exploit"}
    kind = kind_map.get(corpus, corpus)

    result: dict[str, Any] = {
        "kind": kind,
        "id": row["id"],
        "name": ext_id,
        "score": float(row["score"]),
        "description": (summary[:300] + "…" if len(summary) > 300 else summary),
        "tags": [corpus],
        "confidence": "",
        "cvss": None,
        "severity": "",
        "nvd_link": None,
        "mitre_link": None,
        "detail_url": (
            f"/cve/{ext_id}" if corpus in ("cve", "gcve")
            else (f"/exploit/{ext_id.replace('EDB-', '')}" if corpus == "exploitdb" else None)
        ),
    }

    if corpus in ("cve", "gcve") and _CVE_RE.match(ext_id):
        result["nvd_link"] = _nvd_link(ext_id)

    return result


async def corpus_search(
    db: AsyncSession, tenant_id: str, query: str, corpus: str | None = None, limit: int = 20
) -> list[dict[str, Any]]:
    """Search corpus_documents only. Used by the corpus-filtered search endpoint."""
    params: dict[str, Any] = {"q": query, "tenant_id": tenant_id, "lim": limit}
    corpus_filter = ""
    if corpus:
        corpus_filter = "AND cd.corpus = :corpus"
        params["corpus"] = corpus

    rows = await db.execute(
        text(
            f"""
            SELECT
                cd.id::text AS id, cd.corpus, cd.external_id AS name,
                cd.title, cd.summary, cd.published_at,
                ts_rank_cd(cd.search_vector, websearch_to_tsquery('english', :q)) AS score
            FROM corpus_documents cd
            WHERE cd.tenant_id = :tenant_id
              AND cd.search_vector @@ websearch_to_tsquery('english', :q)
              {corpus_filter}
            ORDER BY score DESC, cd.published_at DESC NULLS LAST
            LIMIT :lim
            """
        ),
        params,
    )
    out = [_build_corpus_result(r) for r in rows.mappings().all()]
    if len(out) < max(3, limit // 4):
        ilike_params = dict(params)
        ilike_params["pat"] = f"%{query.strip()}%"
        rows2 = await db.execute(
            text(
                f"""
                SELECT
                    cd.id::text AS id, cd.corpus, cd.external_id AS name,
                    cd.title, cd.summary, cd.published_at,
                    0.05::float AS score
                FROM corpus_documents cd
                WHERE cd.tenant_id = :tenant_id
                  AND (cd.external_id ILIKE :pat OR cd.title ILIKE :pat OR cd.summary ILIKE :pat)
                  {corpus_filter}
                ORDER BY cd.published_at DESC NULLS LAST
                LIMIT :lim
                """
            ),
            ilike_params,
        )
        seen = {r["id"] for r in out}
        for row in rows2.mappings().all():
            if row["id"] in seen:
                continue
            out.append(_build_corpus_result(row))
    return out
