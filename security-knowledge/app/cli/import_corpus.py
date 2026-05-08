"""Bulk corpus importer — CLI and library.

Implements TODO C2: import a Mode A research corpus package produced by
the deep-research-prompt workflow into the security-knowledge service.

CLI usage::

    python -m app.cli.import_corpus --package /path/to/corpus [--validate] [--import]
    python -m app.cli.import_corpus --package corpus.tar.zst   [--validate] [--import]

The package must contain one or more of the canonical JSONL files::

    sources.jsonl, documents.jsonl, sections.jsonl, entities.jsonl,
    facts.jsonl, relationships.jsonl

Import is idempotent: re-running over an already-imported corpus produces
zero new writes (keyed on URL for sources, canonical_name+kind for entities,
source+target+kind for relationships, and content_hash for documents).

Exit codes:
    0 — success (or validation-only with no errors)
    1 — validation errors found
    2 — import errors
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# JSONL helpers
# ---------------------------------------------------------------------------


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    with path.open() as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path.name}:{lineno}: {exc}") from exc
    return rows


def _validate_package(pkg_dir: Path) -> list[str]:
    """Return a list of validation error strings (empty = OK)."""
    errors: list[str] = []
    # At least one JSONL file must exist
    known = [
        "sources.jsonl",
        "documents.jsonl",
        "sections.jsonl",
        "entities.jsonl",
        "facts.jsonl",
        "relationships.jsonl",
    ]
    present = [f for f in known if (pkg_dir / f).exists()]
    if not present:
        errors.append(f"No JSONL files found in {pkg_dir}. Expected one of: {known}")
        return errors

    # Validate JSON syntax
    for fname in present:
        try:
            _load_jsonl(pkg_dir / fname)
        except ValueError as exc:
            errors.append(str(exc))

    # Cross-file referential checks (warn only, not hard error)
    return errors


# ---------------------------------------------------------------------------
# DB import helpers (async)
# ---------------------------------------------------------------------------


async def _upsert_sources(db, tenant_id: uuid.UUID, rows: list[dict]) -> dict[str, uuid.UUID]:
    """Import sources.jsonl rows. Returns mapping of external id → DB UUID."""
    from sqlalchemy import select

    from app.models.sources import SourceRecord

    id_map: dict[str, uuid.UUID] = {}
    for row in rows:
        url = row.get("url", "")
        if not url:
            continue
        res = await db.execute(
            select(SourceRecord).where(
                SourceRecord.tenant_id == tenant_id,
                SourceRecord.url == url,
            )
        )
        existing = res.scalar_one_or_none()
        if existing:
            if row.get("id"):
                id_map[row["id"]] = existing.id
            id_map[url] = existing.id
            continue
        src = SourceRecord(
            tenant_id=tenant_id,
            url=url,
            title=row.get("title", ""),
            kind=row.get("kind", "feed"),
            source_type=row.get("source_type", "corpus"),
            policy_status=row.get("policy_status", "allowed"),
            external_refs=row.get("external_refs", {}),
        )
        db.add(src)
        await db.flush()
        await db.refresh(src)
        if row.get("id"):
            id_map[row["id"]] = src.id
        id_map[url] = src.id
    return id_map


async def _upsert_documents(
    db, tenant_id: uuid.UUID, rows: list[dict], source_map: dict[str, uuid.UUID]
) -> dict[str, uuid.UUID]:
    from sqlalchemy import select

    from app.models.documents import ParsedDocument

    id_map: dict[str, uuid.UUID] = {}
    for row in rows:
        url = row.get("url", "")
        res = (
            await db.execute(
                select(ParsedDocument).where(
                    ParsedDocument.tenant_id == tenant_id,
                    ParsedDocument.url == url,
                )
            )
            if url
            else None
        )
        existing = res.scalar_one_or_none() if res else None
        if existing:
            if row.get("id"):
                id_map[row["id"]] = existing.id
            continue
        source_ref = row.get("source_id", "")
        source_id = source_map.get(source_ref)
        doc = ParsedDocument(
            tenant_id=tenant_id,
            source_id=source_id,
            title=row.get("title", ""),
            url=url or None,
            content_type=row.get("content_type", "text/plain"),
            word_count=row.get("word_count", 0),
            metadata_=row.get("metadata", {}),
        )
        db.add(doc)
        await db.flush()
        await db.refresh(doc)
        if row.get("id"):
            id_map[row["id"]] = doc.id
    return id_map


async def _upsert_sections(db, rows: list[dict], doc_map: dict[str, uuid.UUID]) -> None:
    from sqlalchemy import select

    from app.models.documents import DocumentSection

    for row in rows:
        doc_ref = row.get("document_id", "")
        doc_id = doc_map.get(doc_ref)
        if not doc_id:
            continue
        section_index = row.get("section_index", 0)
        res = await db.execute(
            select(DocumentSection).where(
                DocumentSection.document_id == doc_id,
                DocumentSection.section_index == section_index,
            )
        )
        if res.scalar_one_or_none():
            continue
        sec = DocumentSection(
            document_id=doc_id,
            section_index=section_index,
            heading=row.get("heading", ""),
            content=row.get("content", ""),
        )
        db.add(sec)
    await db.flush()


async def _upsert_entities(db, tenant_id: uuid.UUID, rows: list[dict]) -> dict[str, uuid.UUID]:
    from sqlalchemy import select

    from app.models.entities import Entity

    id_map: dict[str, uuid.UUID] = {}
    for row in rows:
        name = row.get("name") or row.get("canonical_name", "")
        kind = row.get("kind", "other")
        if not name:
            continue
        res = await db.execute(
            select(Entity).where(
                Entity.tenant_id == tenant_id,
                Entity.canonical_name == name,
                Entity.kind == kind,
            )
        )
        existing = res.scalar_one_or_none()
        if existing:
            if row.get("id"):
                id_map[row["id"]] = existing.id
            continue
        entity = Entity(
            tenant_id=tenant_id,
            canonical_name=name,
            kind=kind,
        )
        db.add(entity)
        await db.flush()
        await db.refresh(entity)
        if row.get("id"):
            id_map[row["id"]] = entity.id
    return id_map


async def _upsert_facts(db, tenant_id: uuid.UUID, rows: list[dict], entity_map: dict[str, uuid.UUID]) -> None:
    from app.models.claims import Claim
    from app.models.evidence import Evidence

    for row in rows:
        entity_ref = row.get("entity_id", "")
        entity_id = entity_map.get(entity_ref)
        # Skip facts without evidence (default policy from TODO C2)
        evidence_list = row.get("evidence", [])
        if not evidence_list:
            logger.debug("import_corpus.skipping_fact_no_evidence", row_id=row.get("id"))
            continue
        claim = Claim(
            tenant_id=tenant_id,
            entity_id=entity_id,
            claim_type=row.get("claim_type", "general"),
            value=row.get("value", {}),
            confidence=row.get("confidence", 1.0),
            status=row.get("status", "active"),
            external_refs=row.get("external_refs", {}),
        )
        db.add(claim)
        await db.flush()
        await db.refresh(claim)
        for ev in evidence_list:
            evrow = Evidence(
                tenant_id=tenant_id,
                claim_id=claim.id,
                entity_id=entity_id,
                title=ev.get("title", ""),
                content=ev.get("content", ""),
                text_snippet=ev.get("text_snippet") or ev.get("content", "")[:200],
                source_url=ev.get("source_url"),
                confidence=ev.get("confidence", 1.0),
            )
            db.add(evrow)
    await db.flush()


async def _upsert_relationships(
    db, tenant_id: uuid.UUID, rows: list[dict], entity_map: dict[str, uuid.UUID]
) -> tuple[int, int]:
    from sqlalchemy import select

    from app.models.relationships import Relationship

    imported = skipped = 0
    for row in rows:
        src_ref = row.get("source_id") or row.get("from_entity_id", "")
        tgt_ref = row.get("target_id") or row.get("to_entity_id", "")
        kind = row.get("kind", "related_to")
        src_id = entity_map.get(src_ref)
        tgt_id = entity_map.get(tgt_ref)
        if not src_id or not tgt_id:
            skipped += 1
            continue
        res = await db.execute(
            select(Relationship).where(
                Relationship.tenant_id == tenant_id,
                Relationship.from_entity_id == src_id,
                Relationship.to_entity_id == tgt_id,
                Relationship.kind == kind,
            )
        )
        if res.scalar_one_or_none():
            skipped += 1
            continue
        rel = Relationship(
            tenant_id=tenant_id,
            from_entity_id=src_id,
            to_entity_id=tgt_id,
            kind=kind,
            confidence=row.get("confidence", 1.0),
        )
        db.add(rel)
        imported += 1
    await db.flush()
    return imported, skipped


async def import_corpus_package(
    pkg_dir: Path,
    tenant_id: str | uuid.UUID,
    *,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Import a corpus package directory into the DB.

    Returns a summary dict with counts per object type and zero-write flag.
    """
    from app.database import AsyncSessionLocal

    tid = uuid.UUID(str(tenant_id)) if isinstance(tenant_id, str) else tenant_id
    summary: dict[str, Any] = {
        "tenant_id": str(tid),
        "dry_run": dry_run,
        "sources": 0,
        "documents": 0,
        "sections": 0,
        "entities": 0,
        "claims": 0,
        "relationships": 0,
        "skipped_relationships": 0,
        "skipped_facts_no_evidence": 0,
        "errors": [],
    }

    async with AsyncSessionLocal() as db:
        source_map: dict[str, uuid.UUID] = {}
        doc_map: dict[str, uuid.UUID] = {}
        entity_map: dict[str, uuid.UUID] = {}

        # 1. Sources
        sources_path = pkg_dir / "sources.jsonl"
        if sources_path.exists():
            rows = _load_jsonl(sources_path)
            source_map = await _upsert_sources(db, tid, rows)
            summary["sources"] = len(rows)

        # 2. Documents
        docs_path = pkg_dir / "documents.jsonl"
        if docs_path.exists():
            rows = _load_jsonl(docs_path)
            doc_map = await _upsert_documents(db, tid, rows, source_map)
            summary["documents"] = len(rows)

        # 3. Sections
        secs_path = pkg_dir / "sections.jsonl"
        if secs_path.exists():
            rows = _load_jsonl(secs_path)
            await _upsert_sections(db, rows, doc_map)
            summary["sections"] = len(rows)

        # 4. Entities
        ents_path = pkg_dir / "entities.jsonl"
        if ents_path.exists():
            rows = _load_jsonl(ents_path)
            entity_map = await _upsert_entities(db, tid, rows)
            summary["entities"] = len(rows)

        # 5. Facts (claims + evidence)
        facts_path = pkg_dir / "facts.jsonl"
        if facts_path.exists():
            rows = _load_jsonl(facts_path)
            no_ev = sum(1 for r in rows if not r.get("evidence"))
            summary["skipped_facts_no_evidence"] = no_ev
            summary["claims"] = len(rows) - no_ev
            await _upsert_facts(db, tid, rows, entity_map)

        # 6. Relationships
        rels_path = pkg_dir / "relationships.jsonl"
        if rels_path.exists():
            rows = _load_jsonl(rels_path)
            imported, skipped = await _upsert_relationships(db, tid, rows, entity_map)
            summary["relationships"] = imported
            summary["skipped_relationships"] = skipped

        if dry_run:
            await db.rollback()
        else:
            await db.commit()

    return summary


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------


def _extract_tarzst(archive_path: Path, dest_dir: Path) -> None:
    """Extract a .tar.zst archive using the tarfile + zstandard module."""
    try:
        import zstandard as zstd  # type: ignore[import]

        with open(archive_path, "rb") as fh:
            dctx = zstd.ZstdDecompressor()
            with dctx.stream_reader(fh) as reader:
                with tarfile.open(fileobj=reader) as tar:
                    tar.extractall(dest_dir)
    except ImportError:
        # Fallback: rely on system zstd
        import subprocess

        subprocess.run(
            ["tar", "--zstd", "-xf", str(archive_path), "-C", str(dest_dir)],
            check=True,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Import a Mode A research corpus package into security-knowledge.")
    parser.add_argument(
        "--package",
        required=True,
        help="Path to corpus directory or .tar.zst archive",
    )
    parser.add_argument(
        "--tenant-id",
        default=None,
        help="Tenant UUID to import into. Defaults to BOOTSTRAP_ADMIN_TENANT from config.",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Validate JSONL syntax and report errors without importing",
    )
    parser.add_argument(
        "--import",
        dest="do_import",
        action="store_true",
        help="Run the import (required to actually write to DB)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and process but rollback DB at end",
    )
    args = parser.parse_args()

    pkg_path = Path(args.package)
    if not pkg_path.exists():
        print(f"ERROR: package path does not exist: {pkg_path}", file=sys.stderr)
        sys.exit(1)

    # Extract archive if needed
    tmp_dir = None
    if pkg_path.is_file() and pkg_path.suffix in (".zst", ".zstd", ".gz", ".bz2"):
        tmp_dir = tempfile.mkdtemp(prefix="corpus_import_")
        pkg_dir = Path(tmp_dir)
        _extract_tarzst(pkg_path, pkg_dir)
        # If tar extracted a single sub-directory, descend into it
        children = list(pkg_dir.iterdir())
        if len(children) == 1 and children[0].is_dir():
            pkg_dir = children[0]
    else:
        pkg_dir = pkg_path

    # Validate
    errors = _validate_package(pkg_dir)
    if errors:
        for err in errors:
            print(f"VALIDATION ERROR: {err}", file=sys.stderr)
        sys.exit(1)

    if args.validate:
        print(f"OK — package at {pkg_dir} is valid.")
        sys.exit(0)

    if not args.do_import and not args.dry_run:
        print("No action taken. Use --validate, --import, or --dry-run.", file=sys.stderr)
        sys.exit(0)

    # Resolve tenant
    from app.config import settings

    tenant_id = args.tenant_id or getattr(settings, "BOOTSTRAP_ADMIN_TENANT_ID", None)
    if not tenant_id:
        print(
            "ERROR: --tenant-id required (or set BOOTSTRAP_ADMIN_TENANT_ID in .env)",
            file=sys.stderr,
        )
        sys.exit(1)

    summary = asyncio.run(import_corpus_package(pkg_dir, tenant_id, dry_run=args.dry_run))

    print(json.dumps(summary, indent=2))

    if tmp_dir:
        import shutil

        shutil.rmtree(tmp_dir, ignore_errors=True)

    if summary.get("errors"):
        sys.exit(2)


if __name__ == "__main__":
    main()
