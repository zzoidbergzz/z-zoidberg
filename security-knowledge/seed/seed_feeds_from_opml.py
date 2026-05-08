"""Seed feed SourceRecords from an OPML subscription export.

Usage:
  python -m seed.seed_feeds_from_opml [path/to/opml.xml]

Defaults to the bundled feedly export.  Idempotent: each (tenant_id, url)
pair is upserted, so the script is safe to re-run after edits to the OPML
file.  The "Data Science & Engineering" top-level category is skipped
(case-insensitive) per the project ingestion policy.
"""
from __future__ import annotations

import asyncio
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

DEFAULT_OPML = (
    "/home/z/.copilot/session-state/4770bf2b-fc23-4b2c-97d1-a4e8aba3964b/"
    "files/paste-1778241252318.txt"
)

SKIP_CATEGORIES = {"data science & engineering"}


def _iter_feeds(opml_path: Path):
    """Yield (category, title, xml_url, html_url) tuples for each feed.

    Walks the OPML tree once, tracking the nearest ancestor outline that
    has no xmlUrl (i.e. a category container) so we can attach the right
    label to each feed entry.  Skips entire subtrees whose category title
    is in SKIP_CATEGORIES (case-insensitive).
    """
    tree = ET.parse(opml_path)
    body = tree.getroot().find("body")
    if body is None:
        return

    def _walk(node, category: str | None):
        for child in node.findall("outline"):
            xml_url = child.attrib.get("xmlUrl")
            if xml_url:
                title = (
                    child.attrib.get("title")
                    or child.attrib.get("text")
                    or xml_url
                )
                yield (
                    category or "",
                    title.strip(),
                    xml_url.strip(),
                    (child.attrib.get("htmlUrl") or "").strip(),
                )
            else:
                # Container outline → category label is its text/title
                label = (child.attrib.get("text") or child.attrib.get("title") or "").strip()
                if label.lower() in SKIP_CATEGORIES:
                    continue
                yield from _walk(child, label or category)

    yield from _walk(body, None)


async def _upsert_feed(
    db: AsyncSession,
    tenant_id,
    *,
    url: str,
    title: str,
    category: str,
    html_url: str,
) -> str:
    """Upsert a single feed SourceRecord.  Returns 'inserted' / 'updated'."""
    from app.models.sources import SourceRecord

    result = await db.execute(
        select(SourceRecord).where(
            SourceRecord.tenant_id == tenant_id,
            SourceRecord.url == url,
        )
    )
    existing = result.scalar_one_or_none()
    refs = {"opml_category": category, "html_url": html_url}

    if existing is not None:
        existing.title = title[:1024]
        merged = dict(existing.external_refs or {})
        merged.update(refs)
        existing.external_refs = merged
        existing.active = True
        return "updated"

    record = SourceRecord(
        tenant_id=tenant_id,
        url=url,
        title=title[:1024],
        kind="feed",
        source_type="rss",
        policy_status="allowed",
        active=True,
        fetch_interval_seconds=3600,
        external_refs=refs,
    )
    db.add(record)
    await db.flush()
    return "inserted"


async def _resolve_default_tenant(db: AsyncSession):
    from app.models.auth import Tenant

    result = await db.execute(select(Tenant).where(Tenant.slug == "default"))
    tenant = result.scalar_one_or_none()
    if tenant is None:
        print(
            "ERROR: default tenant not found. Run `python -m seed.seed_data` first.",
            file=sys.stderr,
        )
        sys.exit(1)
    return tenant


async def main(opml_path: Path) -> None:
    from app.database import AsyncSessionLocal

    inserted = updated = skipped = 0
    seen_urls: set[str] = set()

    async with AsyncSessionLocal() as db:
        tenant = await _resolve_default_tenant(db)

        for category, title, xml_url, html_url in _iter_feeds(opml_path):
            if not xml_url:
                skipped += 1
                continue
            if xml_url in seen_urls:
                # Duplicate inside the OPML — count as skipped, don't double-upsert
                skipped += 1
                continue
            seen_urls.add(xml_url)

            outcome = await _upsert_feed(
                db,
                tenant.id,
                url=xml_url,
                title=title,
                category=category,
                html_url=html_url,
            )
            if outcome == "inserted":
                inserted += 1
            else:
                updated += 1

        await db.commit()

    print(f"inserted={inserted} updated={updated} skipped={skipped}")


if __name__ == "__main__":
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(DEFAULT_OPML)
    if not path.exists():
        print(f"OPML file not found: {path}", file=sys.stderr)
        sys.exit(1)
    asyncio.run(main(path))
