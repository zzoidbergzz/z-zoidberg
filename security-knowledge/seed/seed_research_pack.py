"""Seed research pack knowledge into the Security Knowledge database.

Loads from seed/knowledge/research_pack/:
  - relationships.jsonl   — entity relationships with string entity IDs
  - learning_units.jsonl  — structured learning units
  - context_packs.md      — context packs as ParsedDocuments
  - sysinternals_pack.md  — Sysinternals tools as ParsedDocuments

Usage:
  python -m seed.seed_research_pack

The script is fully idempotent — safe to run repeatedly.
Requires: seed_data.py to have been run first (tenant must exist).
Requires: Alembic migration 0014 to have been applied (learning_units table).
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import uuid
from pathlib import Path

import asyncpg
import structlog

from app.config import settings

logger = structlog.get_logger(__name__)

PACK_DIR = Path(__file__).parent / "knowledge" / "research_pack"
CATALOG_PATH = Path(__file__).parent / "knowledge" / "entity_catalog.yml"


def _load_catalog() -> dict[str, dict]:
    """Load curated entity catalog (knowledge_id → metadata).
    Used to seed friendly canonical_name + description on stub creation
    instead of bare slugs. Safe if PyYAML or file missing.
    """
    try:
        import yaml  # type: ignore
    except Exception:
        return {}
    if not CATALOG_PATH.exists():
        return {}
    try:
        with CATALOG_PATH.open() as f:
            data = yaml.safe_load(f) or {}
            return data if isinstance(data, dict) else {}
    except Exception:
        return {}


_CATALOG = _load_catalog()


def _asyncpg_dsn(url: str) -> str:
    """Convert SQLAlchemy asyncpg URL to plain asyncpg DSN."""
    return re.sub(r"^postgresql\+asyncpg://", "postgresql://", url)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _get_tenant(conn: asyncpg.Connection):
    row = await conn.fetchrow("SELECT id, slug FROM tenants WHERE slug = 'default'")
    if row is None:
        print("ERROR: default tenant not found. Run `python -m seed.seed_data` first.", file=sys.stderr)
        sys.exit(1)
    return row["id"]


async def _get_or_create_entity_stub(conn: asyncpg.Connection, tenant_id, knowledge_id: str) -> uuid.UUID:
    """Return entity UUID for knowledge_id, creating a stub if needed."""
    # Try by knowledge_id in external_refs JSONB
    row = await conn.fetchrow(
        "SELECT id FROM entities WHERE tenant_id = $1 AND external_refs->>'knowledge_id' = $2 LIMIT 1",
        tenant_id, knowledge_id,
    )
    if row:
        return row["id"]

    # Try canonical_name match (for role nodes like "blue_team", "dfir")
    row = await conn.fetchrow(
        "SELECT id FROM entities WHERE tenant_id = $1 AND canonical_name = $2 LIMIT 1",
        tenant_id, knowledge_id,
    )
    if row:
        entity_id = row["id"]
        await conn.execute(
            "UPDATE entities SET external_refs = external_refs || jsonb_build_object('knowledge_id', $1) WHERE id = $2",
            knowledge_id, entity_id,
        )
        return entity_id

    # Create stub with JSONB external_refs — pass dict, asyncpg serialises to jsonb
    entry = _CATALOG.get(knowledge_id) or {}
    refs: dict = {"knowledge_id": knowledge_id}
    if not entry:
        refs["stub"] = True
    else:
        for k in ("description", "aka", "url"):
            if entry.get(k) is not None:
                v = entry[k]
                if isinstance(v, str):
                    v = " ".join(v.split())
                refs[k] = v
    new_kind = entry.get("kind") or "other"
    new_name = entry.get("name") or knowledge_id
    row = await conn.fetchrow(
        "INSERT INTO entities (tenant_id, kind, canonical_name, external_refs)"
        " VALUES ($1, $2, $3, $4) RETURNING id",
        tenant_id, new_kind, new_name, json.dumps(refs),
    )
    entity_id = row["id"]
    logger.info("created_entity_stub", knowledge_id=knowledge_id, entity_id=str(entity_id))
    return entity_id


async def _upsert_relationship(conn: asyncpg.Connection, tenant_id, rel: dict) -> tuple[object | None, bool]:
    """Upsert a relationship record."""
    from_id = await _get_or_create_entity_stub(conn, tenant_id, rel["source_entity_id"])
    to_id = await _get_or_create_entity_stub(conn, tenant_id, rel["target_entity_id"])

    row = await conn.fetchrow(
        "SELECT id FROM relationships WHERE tenant_id = $1 AND from_entity_id = $2"
        " AND to_entity_id = $3 AND kind = $4 LIMIT 1",
        tenant_id, from_id, to_id, rel["kind"],
    )
    if row:
        return row["id"], False

    row = await conn.fetchrow(
        "INSERT INTO relationships (tenant_id, from_entity_id, to_entity_id, kind, confidence)"
        " VALUES ($1, $2, $3, $4, $5) RETURNING id",
        tenant_id, from_id, to_id, rel["kind"], rel.get("confidence", 1.0),
    )
    return row["id"], True


async def _upsert_learning_unit(conn: asyncpg.Connection, tenant_id, lu: dict) -> tuple[str, bool]:
    """Upsert a learning unit."""
    lu_id = lu["learning_unit_id"]

    row = await conn.fetchrow(
        "SELECT id FROM learning_units WHERE tenant_id = $1 AND learning_unit_id = $2 LIMIT 1",
        tenant_id, lu_id,
    )
    if row:
        await conn.execute(
            "UPDATE learning_units SET title=$1, level=$2, roles=$3, domains=$4, objectives=$5,"
            " prerequisites=$6, source_refs=$7, entity_refs=$8, fact_refs=$9, lab=$10,"
            " assessment=$11, retrieval_tags=$12, updated_at=now() WHERE id=$13",
            lu["title"],
            lu.get("level", "foundation"),
            json.dumps(lu.get("roles", [])),
            json.dumps(lu.get("domains", [])),
            json.dumps(lu.get("objectives", [])),
            json.dumps(lu.get("prerequisites", [])),
            json.dumps(lu.get("source_refs", [])),
            json.dumps(lu.get("entity_refs", [])),
            json.dumps(lu.get("fact_refs", [])),
            json.dumps(lu.get("lab", {})),
            json.dumps(lu.get("assessment", [])),
            json.dumps(lu.get("retrieval_tags", [])),
            row["id"],
        )
        return str(row["id"]), False

    row = await conn.fetchrow(
        "INSERT INTO learning_units"
        " (tenant_id, learning_unit_id, title, level, roles, domains,"
        "  objectives, prerequisites, source_refs, entity_refs, fact_refs,"
        "  lab, assessment, retrieval_tags)"
        " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING id",
        tenant_id,
        lu_id,
        lu["title"],
        lu.get("level", "foundation"),
        json.dumps(lu.get("roles", [])),
        json.dumps(lu.get("domains", [])),
        json.dumps(lu.get("objectives", [])),
        json.dumps(lu.get("prerequisites", [])),
        json.dumps(lu.get("source_refs", [])),
        json.dumps(lu.get("entity_refs", [])),
        json.dumps(lu.get("fact_refs", [])),
        json.dumps(lu.get("lab", {})),
        json.dumps(lu.get("assessment", [])),
        json.dumps(lu.get("retrieval_tags", [])),
    )
    return str(row["id"]), True


async def _upsert_pack_claim(
    conn: asyncpg.Connection, tenant_id, pack_slug: str, title: str, content: str, entity_id
) -> tuple[str, bool]:
    """Store a context pack as a Claim on the context_packs entity."""
    row = await conn.fetchrow(
        "SELECT id FROM claims WHERE tenant_id = $1 AND external_refs->>'pack_slug' = $2 LIMIT 1",
        tenant_id, pack_slug,
    )
    if row:
        return str(row["id"]), False

    row = await conn.fetchrow(
        "INSERT INTO claims (tenant_id, entity_id, claim_type, value, confidence, status, external_refs)"
        " VALUES ($1, $2, 'context_pack', $3, 1.0, 'approved', $4) RETURNING id",
        tenant_id,
        entity_id,
        json.dumps({"title": title, "content": content, "pack_slug": pack_slug}),
        json.dumps({"pack_slug": pack_slug}),
    )
    return str(row["id"]), True


# ---------------------------------------------------------------------------
# Main seeding functions
# ---------------------------------------------------------------------------


async def seed_relationships(conn: asyncpg.Connection) -> tuple[int, int]:
    tenant_id = await _get_tenant(conn)

    path = PACK_DIR / "relationships.jsonl"
    created = 0
    skipped = 0

    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rel = json.loads(line)
            _, was_created = await _upsert_relationship(conn, tenant_id, rel)
            if was_created:
                created += 1
            else:
                skipped += 1

    return created, skipped


async def seed_learning_units(conn: asyncpg.Connection) -> tuple[int, int]:
    tenant_id = await _get_tenant(conn)

    path = PACK_DIR / "learning_units.jsonl"
    created = 0
    skipped = 0

    with path.open() as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            lu = json.loads(line)
            _, was_created = await _upsert_learning_unit(conn, tenant_id, lu)
            if was_created:
                created += 1
            else:
                skipped += 1

    return created, skipped


async def seed_context_packs(conn: asyncpg.Connection) -> tuple[int, int]:
    tenant_id = await _get_tenant(conn)
    created = 0
    skipped = 0

    pack_entity_id = await _get_or_create_entity_stub(conn, tenant_id, "ent_corpus_context_packs")

    for fname, title, slug in [
        ("context_packs.md", "Security Knowledge Context Packs", "context_packs"),
        ("sysinternals_pack.md", "Microsoft Sysinternals Security Tools Pack", "sysinternals_pack"),
    ]:
        content = (PACK_DIR / fname).read_text()
        _, was_created = await _upsert_pack_claim(conn, tenant_id, slug, title, content, pack_entity_id)
        if was_created:
            created += 1
        else:
            skipped += 1

    return created, skipped


async def main() -> None:
    dsn = _asyncpg_dsn(settings.DATABASE_URL)
    conn = await asyncpg.connect(dsn)

    try:
        async with conn.transaction():
            print("\n── Research Pack: Relationships ──────────────────────")
            rel_created, rel_skipped = await seed_relationships(conn)
            print(f"   {rel_created} new relationships, {rel_skipped} already existed")

            print("\n── Research Pack: Learning Units ─────────────────────")
            lu_created, lu_skipped = await seed_learning_units(conn)
            print(f"   {lu_created} new learning units, {lu_skipped} already existed")

            print("\n── Research Pack: Context/Sysinternals Packs ─────────")
            doc_created, doc_skipped = await seed_context_packs(conn)
            print(f"   {doc_created} new documents, {doc_skipped} already existed")

    finally:
        await conn.close()

    print("\n✅ Research pack seed complete.")


if __name__ == "__main__":
    asyncio.run(main())
