"""Seed non-English CTI sources into the z.je SK platform's source_records table."""

import asyncio
import sys
import yaml
from pathlib import Path

sys.path.insert(0, str(Path.home() / "z-zoidberg" / "security-knowledge"))

from app.database import AsyncSessionLocal
from app.models.sources import SourceRecord
from sqlalchemy import select


async def seed():
    catalogue_path = Path.home() / "non-english-cti" / "catalogue" / "sources.yaml"
    with open(catalogue_path) as f:
        sources = yaml.safe_load(f)

    async with AsyncSessionLocal() as db:
        # Check existing to avoid duplicates
        existing = await db.execute(select(SourceRecord.url))
        existing_urls = {row[0] for row in existing.all()}

        added = 0
        skipped = 0

        for src in sources:
            name = src.get("source_name", "")
            url = src.get("url", "")
            feed_url = ""
            for ep in src.get("feeds_endpoints", []):
                if ep.get("type") in ("rss", "atom", "feed"):
                    feed_url = ep.get("url", "")
                    break

            source_url = feed_url or url
            if source_url in existing_urls:
                skipped += 1
                continue

            source_type = "rss" if src.get("collection_method") == "rss" else "html"
            if src.get("source_type") == "api":
                source_type = "api"

            priority = src.get("collection_priority", 3)
            interval_map = {1: 3600, 2: 7200, 3: 21600, 4: 86400}
            fetch_interval = interval_map.get(priority, 21600)

            record = SourceRecord(
                tenant_id="bcc8ab78-0982-4ea3-81d3-7e4bd166881a",
                title=name,
                url=source_url,
                kind=src.get("source_type", "cert"),
                source_type=source_type,
                active=True,
                fetch_interval_seconds=fetch_interval,
                external_refs={
                    "necti_language": src.get("language", ""),
                    "necti_country": src.get("country", ""),
                    "necti_region": src.get("region", ""),
                    "necti_priority": priority,
                    "necti_original_url": url,
                    "necti_reliability": src.get("reliability", 3),
                },
            )
            db.add(record)
            added += 1

        await db.commit()
        print(f"Seeded {added} non-English CTI sources ({skipped} already existed)")


if __name__ == "__main__":
    asyncio.run(seed())
