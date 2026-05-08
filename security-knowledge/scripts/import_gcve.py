#!/usr/bin/env python3
"""Import GCVE (Global CVE Allocation System) records into corpus_documents.

GCVE is a decentralised vulnerability numbering system. Records are allocated
by GNAs (GCVE Numbering Authorities). We pull from CIRCL's vulnerability-lookup
dump endpoint which hosts NDJSON files per GNA.

Usage:
    python scripts/import_gcve.py [--limit N]

Data source:
    https://vulnerability.circl.lu/dumps/gna-*.ndjson  (downloaded to data/corpora/gcve/)

Record format: CVE 5.x JSON with vulnId = GCVE-<gna_id>-<year>-<seq>
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncpg

CORPUS_DIR = Path(__file__).parent.parent / "data" / "corpora" / "gcve"
DEFAULT_TENANT_ID = "bcc8ab78-0982-4ea3-81d3-7e4bd166881a"
DATABASE_URL = (
    os.environ.get("DATABASE_URL", "postgresql://sk:sk@localhost/sk")
    .replace("postgresql+asyncpg://", "postgresql://")
    .replace("postgresql+psycopg://", "postgresql://")
)


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s[: len(fmt)], fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def parse_gcve_record(data: dict, source_path: str) -> dict | None:
    """Parse a GCVE record (CVE-5-like JSON with vulnId) into a corpus_documents row."""
    meta = data.get("cveMetadata", {})

    # GCVE records use vulnId instead of cveId
    gcve_id = meta.get("vulnId") or meta.get("cveId", "")
    if not gcve_id:
        return None

    state = meta.get("state", "UNKNOWN")

    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    # Title
    title_raw = cna.get("title", "")
    if isinstance(title_raw, list):
        title = " ".join(
            (t.get("value", "") if isinstance(t, dict) else str(t)) for t in title_raw
        )
    else:
        title = str(title_raw)

    # Description / summary
    descs = cna.get("descriptions", [])
    summary = ""
    for d in descs:
        if isinstance(d, dict) and d.get("lang", "").startswith("en"):
            summary = d.get("value", "")
            break
    if not summary and descs:
        first = descs[0]
        summary = first.get("value", "") if isinstance(first, dict) else str(first)

    # Affected
    affected = cna.get("affected", [])
    affected_strs = []
    for a in affected[:10]:
        if isinstance(a, dict):
            vendor = a.get("vendor", "")
            product = a.get("product", "")
            if vendor or product:
                affected_strs.append(f"{vendor} {product}".strip())

    body_parts = [gcve_id, title, summary, f"state:{state}"]
    body_parts.extend(affected_strs)
    body_text = "\n".join(p for p in body_parts if p)

    date_published = meta.get("datePublished") or meta.get("dateReserved")
    date_updated = meta.get("dateUpdated")

    return {
        "corpus": "gcve",
        "external_id": gcve_id.upper(),
        "title": (title[:512] if title else None) or f"GCVE Record {gcve_id}",
        "summary": summary[:4096] if summary else None,
        "body_text": body_text[:200000] if body_text else None,
        "raw_json": json.dumps(data),
        "source_path": source_path,
        "published_at": _parse_dt(date_published),
        "modified_at": _parse_dt(date_updated),
    }


async def import_batch(conn: asyncpg.Connection, batch: list[dict], tenant_id: str) -> int:
    rows = [
        (
            tenant_id,
            rec["corpus"],
            rec["external_id"],
            rec.get("title"),
            rec.get("summary"),
            rec.get("body_text"),
            rec.get("raw_json"),
            rec.get("source_path"),
            rec.get("published_at"),
            rec.get("modified_at"),
        )
        for rec in batch
    ]
    await conn.executemany(
        """
        INSERT INTO corpus_documents
            (id, tenant_id, corpus, external_id, title, summary, body_text,
             raw_json, source_path, published_at, modified_at)
        VALUES
            (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7::jsonb, $8, $9, $10)
        ON CONFLICT (corpus, external_id) DO UPDATE SET
            title = EXCLUDED.title,
            summary = EXCLUDED.summary,
            body_text = EXCLUDED.body_text,
            raw_json = EXCLUDED.raw_json,
            source_path = EXCLUDED.source_path,
            published_at = EXCLUDED.published_at,
            modified_at = EXCLUDED.modified_at,
            updated_at = now()
        """,
        rows,
    )
    return len(rows)


async def main(args: argparse.Namespace) -> None:
    if not CORPUS_DIR.exists():
        print(f"ERROR: {CORPUS_DIR} not found. Run: mkdir -p {CORPUS_DIR} and download GNA dumps.")
        sys.exit(1)

    ndjson_files = sorted(CORPUS_DIR.glob("gna-*.ndjson"))
    if not ndjson_files:
        print(f"No gna-*.ndjson files found in {CORPUS_DIR}")
        sys.exit(1)

    print(f"Found {len(ndjson_files)} GNA dump file(s): {[f.name for f in ndjson_files]}")

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        batch: list[dict] = []
        processed = 0
        upserted = 0
        errors = 0
        t0 = time.monotonic()

        for ndjson_path in ndjson_files:
            print(f"  Processing {ndjson_path.name} ...", flush=True)
            with open(ndjson_path, encoding="utf-8") as fh:
                for line_no, line in enumerate(fh, 1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError as e:
                        print(f"    JSON parse error line {line_no}: {e}")
                        errors += 1
                        continue

                    rec = parse_gcve_record(data, f"{ndjson_path.name}:{line_no}")
                    if rec is None:
                        errors += 1
                        continue

                    batch.append(rec)
                    if args.limit and len(batch) + processed >= args.limit:
                        break

                    if len(batch) >= 100:
                        count = await import_batch(conn, batch, DEFAULT_TENANT_ID)
                        upserted += count
                        processed += len(batch)
                        batch = []

            if args.limit and processed >= args.limit:
                break

        if batch:
            count = await import_batch(conn, batch, DEFAULT_TENANT_ID)
            upserted += count
            processed += len(batch)

        elapsed = time.monotonic() - t0
        print(
            f"\nDone! {processed} processed, {upserted} upserted, "
            f"{errors} errors in {elapsed:.1f}s",
            flush=True,
        )
    finally:
        await conn.close()


if __name__ == "__main__":
    import asyncio

    parser = argparse.ArgumentParser(description="Import GCVE records into corpus_documents")
    parser.add_argument("--limit", type=int, default=None, help="Max records (for testing)")
    args = parser.parse_args()
    asyncio.run(main(args))
