#!/usr/bin/env python3
"""Import CVE List V5 into corpus_documents.

Usage:
    python scripts/import_cvelist.py [--limit N] [--year YYYY] [--batch-size N]

Idempotent: uses ON CONFLICT DO UPDATE on (corpus, external_id).
Resume-safe: failed batches are retried on next run via the unique key.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Allow running from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

import asyncpg

CORPUS_DIR = Path(__file__).parent.parent / "data" / "corpora" / "cvelistv5"
DEFAULT_TENANT_ID = "bcc8ab78-0982-4ea3-81d3-7e4bd166881a"
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://sk:sk@localhost/sk"
).replace("postgresql+asyncpg://", "postgresql://").replace("postgresql+psycopg://", "postgresql://")


def parse_cve5(path: Path, rel_path: str) -> dict | None:
    """Parse a CVE 5.x JSON file into a corpus_documents row dict."""
    try:
        with open(path, "rb") as f:
            data = json.load(f)
    except Exception:
        return None

    meta = data.get("cveMetadata", {})
    cve_id = meta.get("cveId", "")
    if not cve_id:
        return None

    state = meta.get("state", "")
    if state == "REJECTED":
        # Still import rejected CVEs but mark them
        pass

    containers = data.get("containers", {})
    cna = containers.get("cna", {})

    # Title
    title_list = cna.get("title") or ""
    if isinstance(title_list, list):
        title = " ".join(t.get("value", "") if isinstance(t, dict) else str(t) for t in title_list)
    else:
        title = str(title_list)

    # Summary / description
    descs = cna.get("descriptions", [])
    summary = ""
    for d in descs:
        if isinstance(d, dict) and d.get("lang", "").startswith("en"):
            summary = d.get("value", "")
            break
    if not summary and descs:
        first = descs[0]
        summary = first.get("value", "") if isinstance(first, dict) else str(first)

    # CVSS scores
    metrics = cna.get("metrics", [])
    cvss_score = None
    cvss_vector = None
    for m in metrics:
        if not isinstance(m, dict):
            continue
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            if key in m:
                cvss_data = m[key]
                if isinstance(cvss_data, dict):
                    cvss_score = cvss_data.get("baseScore")
                    cvss_vector = cvss_data.get("vectorString")
                    break
        if cvss_score is not None:
            break

    # Affected products
    affected = cna.get("affected", [])
    affected_strs = []
    for a in affected[:10]:
        if isinstance(a, dict):
            vendor = a.get("vendor", "")
            product = a.get("product", "")
            if vendor or product:
                affected_strs.append(f"{vendor} {product}".strip())

    # References
    refs = cna.get("references", [])
    ref_urls = [r.get("url", "") for r in refs[:5] if isinstance(r, dict)]

    # Build body_text for FTS
    body_parts = [cve_id, title, summary]
    body_parts.extend(affected_strs)
    body_parts.extend(ref_urls)
    # Include CWE IDs
    problem_types = cna.get("problemTypes", [])
    for pt in problem_types:
        if isinstance(pt, dict):
            for desc in pt.get("descriptions", []):
                if isinstance(desc, dict):
                    cwe = desc.get("cweId", "")
                    if cwe:
                        body_parts.append(cwe)
    body_text = "\n".join(p for p in body_parts if p)

    # Dates
    date_published = meta.get("datePublished") or meta.get("dateReserved")
    date_updated = meta.get("dateUpdated")
    published_at = _parse_dt(date_published)
    modified_at = _parse_dt(date_updated)

    return {
        "corpus": "cve",
        "external_id": cve_id.upper(),
        "title": title[:512] if title else None,
        "summary": summary[:4096] if summary else None,
        "body_text": body_text[:200000] if body_text else None,
        "raw_json": json.dumps(data),
        "source_path": rel_path,
        "published_at": published_at,
        "modified_at": modified_at,
    }


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(s[:26], fmt[:len(s[:26])])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def collect_files(corpus_dir: Path, year: str | None, limit: int | None) -> list[Path]:
    cves_dir = corpus_dir / "cves"
    if not cves_dir.exists():
        print(f"ERROR: {cves_dir} does not exist. Clone cvelistV5 first.")
        sys.exit(1)

    files = []
    if year:
        year_dir = cves_dir / year
        if not year_dir.exists():
            print(f"ERROR: Year directory {year_dir} not found")
            sys.exit(1)
        for f in sorted(year_dir.rglob("CVE-*.json")):
            files.append(f)
            if limit and len(files) >= limit:
                break
    else:
        for f in sorted(cves_dir.rglob("CVE-*.json")):
            files.append(f)
            if limit and len(files) >= limit:
                break
    return files


async def import_batch(conn: asyncpg.Connection, batch: list[dict], tenant_id: str) -> int:
    """Upsert a batch of records. Returns count of rows upserted."""
    rows = []
    for rec in batch:
        rows.append((
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
        ))

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
    import asyncio  # noqa: PLC0415

    files = collect_files(CORPUS_DIR, args.year, args.limit)
    total = len(files)
    print(f"Found {total:,} CVE JSON files to process", flush=True)

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        batch_size = args.batch_size
        batch: list[dict] = []
        processed = 0
        upserted = 0
        errors = 0
        t0 = time.monotonic()
        last_report = t0

        for i, fpath in enumerate(files):
            rel = str(fpath.relative_to(CORPUS_DIR))
            rec = parse_cve5(fpath, rel)
            if rec is None:
                errors += 1
                continue
            batch.append(rec)

            if len(batch) >= batch_size:
                count = await import_batch(conn, batch, DEFAULT_TENANT_ID)
                upserted += count
                processed += len(batch)
                batch = []

                now = time.monotonic()
                if now - last_report >= 10:
                    elapsed = now - t0
                    rate = processed / elapsed if elapsed > 0 else 0
                    pct = 100.0 * (i + 1) / total if total > 0 else 0
                    eta = (total - i - 1) / rate if rate > 0 else 0
                    print(
                        f"  [{pct:5.1f}%] {processed:>7,}/{total:,} processed, "
                        f"{upserted:>7,} upserted, {errors} errors, "
                        f"{rate:.0f} rec/s, ETA {eta/60:.1f}m",
                        flush=True,
                    )
                    last_report = now

        # Flush remaining
        if batch:
            count = await import_batch(conn, batch, DEFAULT_TENANT_ID)
            upserted += count
            processed += len(batch)

        elapsed = time.monotonic() - t0
        print(
            f"\nDone! {processed:,} processed, {upserted:,} upserted, "
            f"{errors} parse errors in {elapsed:.1f}s ({processed/elapsed:.0f} rec/s)",
            flush=True,
        )
    finally:
        await conn.close()


if __name__ == "__main__":
    import asyncio

    parser = argparse.ArgumentParser(description="Import CVE List V5 into corpus_documents")
    parser.add_argument("--limit", type=int, default=None, help="Max records to import (for testing)")
    parser.add_argument("--year", type=str, default=None, help="Import only a specific year, e.g. 2024")
    parser.add_argument("--batch-size", type=int, default=1000, help="Rows per DB transaction")
    args = parser.parse_args()
    asyncio.run(main(args))
