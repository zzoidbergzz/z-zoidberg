#!/usr/bin/env python3
"""Feed cycle script for non-English CTI sources.

Run via cron:
  */60 * * * * cd ~/non-english-cti && .venv/bin/python scripts/feed_cycle.py --priority 1 >> ~/necti-data/feed_cycle.log 2>&1
  */120 * * * * cd ~/non-english-cti && .venv/bin/python scripts/feed_cycle.py --priority 2 >> ~/necti-data/feed_cycle.log 2>&1
  0 */6 * * * cd ~/non-english-cti && .venv/bin/python scripts/feed_cycle.py --priority 3 >> ~/necti-data/feed_cycle.log 2>&1
  0 0 * * * cd ~/non-english-cti && .venv/bin/python scripts/feed_cycle.py --priority 4 >> ~/necti-data/feed_cycle.log 2>&1
"""

import argparse
import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.registry import SourceRegistry
from src.fetchers.rss import RSSFetcher
from src.fetchers.api import APIFetcher
from src.fetchers.html import HTMLFetcher
from src.translation.detector import LanguageDetector
from src.translation.translator import TranslationPipeline
from src.extraction.ioc import extract_iocs
from src.extraction.cve import extract_cves
from src.extraction.ttp import extract_ttps, extract_actors, extract_malware
from src.extraction.dedup import compute_content_hash
from src.export.stix import create_stix_bundle
from src.storage.raw_store import RawEvidenceStore

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("feed_cycle")

CATALOGUE_PATH = Path(__file__).parent.parent / "catalogue" / "sources.yaml"
OUTPUT_DIR = Path.home() / "necti-data" / "output"
RAW_STORE = Path.home() / "necti-data" / "raw_store"


async def run_cycle(priority: int, max_sources: int = 0, ingest_to_sk: bool = True):
    """Run collection cycle for sources of given priority."""
    registry = SourceRegistry()
    registry.load(str(CATALOGUE_PATH))
    sources = registry.get_by_priority(priority)

    if max_sources:
        sources = sources[:max_sources]

    logger.info("Starting cycle: priority=%d, sources=%d", priority, len(sources))

    fetcher = RSSFetcher(rate_limit=2.0, timeout=15.0)
    api_fetcher = APIFetcher(rate_limit=2.0)
    html_fetcher = HTMLFetcher(rate_limit=2.0)
    detector = LanguageDetector()
    translator = TranslationPipeline(libretranslate_url="http://localhost:5000")
    raw_store = RawEvidenceStore(base_path=str(RAW_STORE))

    total_items = 0
    translated_items = 0
    iocs_found = 0
    cves_found = 0
    errors = 0
    records = []

    seen_hashes: set[str] = set()
    # Load existing hashes from a simple file
    hash_file = OUTPUT_DIR / "seen_hashes.txt"
    if hash_file.exists():
        seen_hashes.update(hash_file.read_text().strip().splitlines())

    for source in sources:
        try:
            if source.collection_method == "rss":
                items = await fetcher.fetch(source)
            elif source.collection_method == "api":
                items = await api_fetcher.fetch(source)
            elif source.collection_method == "html":
                items = await html_fetcher.fetch(source)
            else:
                continue

            for item in items:
                title = item.get("title", "")
                body = item.get("body", "")
                url = item.get("url", "")

                if not title and not body:
                    continue

                # Dedup
                content_hash = compute_content_hash(title, body)
                if content_hash in seen_hashes:
                    continue
                seen_hashes.add(content_hash)

                # Detect language
                lang, lang_conf = detector.detect(f"{title} {body}")
                if not lang:
                    lang = source.language

                # Translate
                title_en = title
                body_en = body
                translation_method = "identity"

                if lang != "en" and body:
                    result = await translator.translate(body, lang, "en")
                    body_en = result.get("translated_text", body)
                    translation_method = result.get("method", "unknown")
                    translated_items += 1

                    if title:
                        title_result = await translator.translate(title, lang, "en")
                        title_en = title_result.get("translated_text", title)

                # Extract
                iocs = extract_iocs(f"{title} {body}") if body else None
                cves = extract_cves(f"{title} {body}")
                ttps = extract_ttps(f"{title} {body}")
                actors = extract_actors(f"{title} {body}")
                malware = extract_malware(f"{title} {body}")

                if iocs and (iocs.ipv4 or iocs.domains or iocs.sha256_hashes):
                    iocs_found += 1
                if cves:
                    cves_found += 1

                record = {
                    "source": source.source_name,
                    "language": lang,
                    "country": source.country,
                    "region": source.region,
                    "source_type": source.source_type,
                    "title_original": title,
                    "title_en": title_en,
                    "url": url,
                    "published_at": str(item.get("published_at", "")),
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "translation_method": translation_method,
                    "iocs": {
                        "ipv4": iocs.ipv4 if iocs else [],
                        "domains": iocs.domains if iocs else [],
                        "sha256": iocs.sha256_hashes if iocs else [],
                        "urls": iocs.urls if iocs else [],
                        "emails": iocs.email_addresses if iocs else [],
                    } if iocs else {},
                    "cves": cves,
                    "ttps": [t["id"] for t in ttps] if ttps else [],
                    "actors": actors,
                    "malware": malware,
                    "content_hash": content_hash,
                }
                records.append(record)
                total_items += 1

                # Store raw HTML
                if body:
                    raw_store.store_html(source.source_id, url, body)

            # Ingest into z.je SK platform
            if ingest_to_sk and records:
                await _ingest_to_sk(records)

        except Exception as exc:
            logger.error("Source error: %s: %s", source.source_name, exc)
            errors += 1

    # Save outputs
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # Save seen hashes
    hash_file.write_text("\n".join(seen_hashes))

    # Save STIX bundle if we have records
    if records:
        stix_path = OUTPUT_DIR / f"stix_p{priority}_{datetime.now().strftime('%Y%m%d_%H%M')}.json"
        # Simplified: just dump records as JSON for now
        stix_path.write_text(json.dumps(records, ensure_ascii=False, indent=2), encoding="utf-8")
        logger.info("Saved %d records to %s", len(records), stix_path)

    # Close
    await fetcher.close()
    await api_fetcher.close()
    await html_fetcher.close()

    logger.info(
        "Cycle complete: priority=%d, items=%d, translated=%d, iocs=%d, cves=%d, errors=%d",
        priority, total_items, translated_items, iocs_found, cves_found, errors,
    )
    return {
        "priority": priority,
        "total_items": total_items,
        "translated": translated_items,
        "iocs_found": iocs_found,
        "cves_found": cves_found,
        "errors": errors,
    }


async def _ingest_to_sk(records: list[dict]) -> int:
    """Push collected records to the z.je SK platform via its ingest API."""
    import httpx

    ingested = 0
    api_url = "http://localhost:8000/ingest/"

    async with httpx.AsyncClient(timeout=15.0) as client:
        for record in records:
            try:
                resp = await client.post(api_url, json={
                    "source_url": record.get("url", ""),
                    "source_type": f"necti_{record.get('source_type', 'unknown')}",
                    "priority": 3,
                })
                if resp.is_success:
                    ingested += 1
            except Exception:
                pass  # Non-fatal

    if ingested:
        logger.info("Ingested %d items to SK platform", ingested)
    return ingested


def main():
    parser = argparse.ArgumentParser(description="Non-English CTI feed cycle")
    parser.add_argument("--priority", type=int, default=1, choices=[1, 2, 3, 4])
    parser.add_argument("--max-sources", type=int, default=0, help="Limit number of sources")
    parser.add_argument("--no-ingest", action="store_true", help="Skip SK platform ingestion")
    args = parser.parse_args()

    result = asyncio.run(run_cycle(
        priority=args.priority,
        max_sources=args.max_sources,
        ingest_to_sk=not args.no_ingest,
    ))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
